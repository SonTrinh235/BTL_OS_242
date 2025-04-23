/*
 * Copyright (C) 2025 pdnguyen of HCMC University of Technology VNU-HCM
 */

/* Sierra release
 * Source Code License Grant: The authors hereby grant to Licensee
 * personal permission to use and modify the Licensed Source Code
 * for the sole purpose of studying while attending the course CO2018.
 */

// #ifdef MM_PAGING
/*
 * System Library
 * Memory Module Library libmem.c
 */

 #include "string.h"
 #include "mm.h"
 #include "syscall.h"
 #include "libmem.h"
 #include <stdlib.h>
 #include <stdio.h>
 #include <pthread.h>
 
 static pthread_mutex_t mmvm_lock = PTHREAD_MUTEX_INITIALIZER;
 
 /*enlist_vm_freerg_list - add new rg to freerg_list
  *@mm: memory region
  *@rg_elmt: new region
  *
  */
 int enlist_vm_freerg_list(struct mm_struct *mm, struct vm_rg_struct *rg_elmt)
 {
   struct vm_rg_struct *rg_node = mm->mmap->vm_freerg_list;
 
   if (rg_elmt->rg_start >= rg_elmt->rg_end)
     return -1;
 
   if (rg_node != NULL)
     rg_elmt->rg_next = rg_node;
 
   /* Enlist the new region */
   mm->mmap->vm_freerg_list = rg_elmt;
 
   return 0;
 }
 
 /*get_symrg_byid - get mem region by region ID
  *@mm: memory region
  *@rgid: region ID act as symbol index of variable
  *
  */
 struct vm_rg_struct *get_symrg_byid(struct mm_struct *mm, int rgid)
 {
   if (rgid < 0 || rgid > PAGING_MAX_SYMTBL_SZ)
     return NULL;
 
   return &mm->symrgtbl[rgid];
 }
 
 /*__alloc - allocate a region memory
  *@caller: caller
  *@vmaid: ID vm area to alloc memory region
  *@rgid: memory region ID (used to identify variable in symbole table)
  *@size: allocated size
  *@alloc_addr: address of allocated memory region
  *
  */
 int __alloc(struct pcb_t *caller, int vmaid, int rgid, int size, int *alloc_addr)
 {
     if (!caller || !caller->mm || !alloc_addr || size <= 0 ||
         rgid < 0 || rgid >= PAGING_MAX_SYMTBL_SZ)
     {
         *alloc_addr = 0;
         return -1; // Invalid parameters
     }
 
     pthread_mutex_lock(&mmvm_lock);
 
     struct vm_rg_struct rgnode; // Use this to store the found free region info
     struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
 
     if (!cur_vma)
     {
         *alloc_addr = 0;
         pthread_mutex_unlock(&mmvm_lock);
         return -2; // VMA not found
     }
 
     /* Try to find free space in existing regions */
     if (get_free_vmrg_area(caller, vmaid, size, &rgnode) == 0)
     {
         /* Found a suitable free region. Use its start address */
         caller->mm->symrgtbl[rgid].rg_start = rgnode.rg_start; // Use the start of the found region
         caller->mm->symrgtbl[rgid].rg_end = rgnode.rg_start + size;
         *alloc_addr = rgnode.rg_start; // Set the output address
 
         #ifdef IODUMP
          // printf("===== PHYSICAL MEMORY AFTER ALLOCATION (found free region) =====\n");
          // printf("PID=%d - Region=%d - Address=%08lx - Size=%d byte\n", caller->pid, rgid, rgnode.rg_start, size);
             #ifdef PAGETBL_DUMP
               print_pgtbl(caller, 0, -1); // print max TBL
             #endif
         MEMPHY_dump(caller->mram);
         #endif
 
         pthread_mutex_unlock(&mmvm_lock);
         return 0; // Successful allocation in existing space
     }
 
     /* No suitable free region found, need to increase VMA limit */
     int inc_sz = PAGING_PAGE_ALIGNSZ(size); // Calculate aligned size increase needed
     int old_sbrk = cur_vma->sbrk;          // Store the current break point
 
     /* Try to increase VMA limit */
     if (inc_vma_limit(caller, vmaid, inc_sz) != 0)
     {
         *alloc_addr = 0;
         pthread_mutex_unlock(&mmvm_lock);
         return -3; // Failed to increase VMA limit
     }
 
     /* VMA limit successfully increased. The new space starts at old_sbrk */
     cur_vma->sbrk += inc_sz; // Update the break pointer
 
     /* Update free region list if we allocated more page-aligned space than needed */
     if (inc_sz > size)
     {
         struct vm_rg_struct *new_rgnode = malloc(sizeof(struct vm_rg_struct));
         if (!new_rgnode)
         {
             // Ideally, should try to roll back the sbrk increase, but that's complex.
             *alloc_addr = 0;
             pthread_mutex_unlock(&mmvm_lock);
             return -4; // Malloc failed for tracking free space
         }
         new_rgnode->rg_start = old_sbrk + size; // The unused part starts after the allocated size
         new_rgnode->rg_end = old_sbrk + inc_sz; // Ends at the new break point
         new_rgnode->rg_next = NULL; // Initialize next pointer
         if (enlist_vm_freerg_list(caller->mm, new_rgnode) != 0)
         {
             free(new_rgnode);
             // Rollback attempt might be needed here too.
             *alloc_addr = 0;
             pthread_mutex_unlock(&mmvm_lock);
             return -5; // Failed to add new free region to list
         }
     }
 
     /* Allocate the requested region starting at the old break point */
     caller->mm->symrgtbl[rgid].rg_start = old_sbrk; // Start at the old break point
     caller->mm->symrgtbl[rgid].rg_end = old_sbrk + size;
     *alloc_addr = old_sbrk; // Set the output address
 
     #ifdef IODUMP
     printf("===== PHYSICAL MEMORY AFTER ALLOCATION =====\n");
     printf("PID=%d - Region=%d - Address=%08x - Size=%d byte\n", caller->pid, rgid, old_sbrk, size); // Use old_sbrk
         #ifdef PAGETBL_DUMP
           print_pgtbl(caller, 0, -1); // print max TBL
         #endif
     MEMPHY_dump(caller->mram);
     #endif
     pthread_mutex_unlock(&mmvm_lock);
     return 0; // Successful allocation by expanding VMA
 }

 
 /*__free - remove a region memory
  *@caller: caller
  *@vmaid: ID vm area to alloc memory region
  *@rgid: memory region ID (used to identify variable in symbole table)
  *@size: allocated size
  *
  */
 int __free(struct pcb_t *caller, int vmaid, int rgid)
 {
   // struct vm_rg_struct rgnode;
   struct vm_rg_struct rgnode;
   if (rgid < 0 || rgid > PAGING_MAX_SYMTBL_SZ)
     return -1;
   rgnode.rg_start = caller->mm->symrgtbl[rgid].rg_start;
   rgnode.rg_end = caller->mm->symrgtbl[rgid].rg_end;
   caller->mm->symrgtbl[rgid].rg_start = caller->mm->symrgtbl[rgid].rg_end;
   /*enlist the obsoleted memory region */
   // enlist_vm_freerg_list();
   enlist_vm_freerg_list(caller->mm, &rgnode);
 
   printf("===== PHYSICAL MEMORY AFTER DEALLOCATION =====\n");
   printf("PID=%d - Region=%d\n",
          caller->pid,
          rgid);
   print_pgtbl(caller, 0, -1);
   return 0;
 }
 
 
 /*liballoc - PAGING-based allocate a region memory
  *@proc:  Process executing the instruction
  *@size: allocated size
  *@reg_index: memory region ID (used to identify variable in symbole table)
  */  
 int liballoc(struct pcb_t *proc, uint32_t size, uint32_t reg_index)
 {
   /* Initialize addr to store allocation address */
   int addr = 0;
 
   /* Perform allocation using vmaid 0 */
   int result = __alloc(proc, 0, reg_index, size, &addr);

   /* If allocation successful, return 0, otherwise return error code */
   return result;
 }
 
 /*libfree - PAGING-based free a region memory
  *@proc: Process executing the instruction
  *@size: allocated size
  *@reg_index: memory region ID (used to identify variable in symbole table)
  */
 
 int libfree(struct pcb_t *proc, uint32_t reg_index)
 {
   /* Validate input parameters */
   if (!proc || reg_index >= PAGING_MAX_SYMTBL_SZ)
   {
     return -1;
   }
 
   /* Try to free the memory region */
   return __free(proc, 0, reg_index);
 }
 
 /*pg_getpage - get the page in ram
  *@mm: memory region
  *@pagenum: PGN
  *@framenum: return FPN
  *@caller: caller
  *
  */
int pg_getpage(struct mm_struct *mm, int pgn, int *fpn, struct pcb_t *caller)
{
    if (!mm || !fpn || !caller || pgn < 0 || pgn >= PAGING_MAX_PGN)
        return -1;

    static pthread_mutex_t mem_lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&mem_lock);

    uint32_t pte = mm->pgd[pgn];
    int ret = 0;

    if (!PAGING_PAGE_PRESENT(pte)) {
        int newfpn;

        if (MEMPHY_get_freefp(caller->mram, &newfpn) == 0) {
            pte_set_fpn(&mm->pgd[pgn], newfpn);
            *fpn = newfpn;

            struct pgn_t *new_node = malloc(sizeof(struct pgn_t));
            if (!new_node) {
                ret = -6;
                goto out;
            }
            new_node->pgn = pgn;
            new_node->pg_next = NULL;

            if (caller->mm->fifo_pgn == NULL)
                caller->mm->fifo_pgn = new_node;
            else {
                struct pgn_t *curr = caller->mm->fifo_pgn;
                while (curr->pg_next != NULL)
                    curr = curr->pg_next;
                curr->pg_next = new_node;
            }
            goto out;
        }
        int vicpgn, swpfpn, vicfpn;
        if (find_victim_page(caller->mm, &vicpgn) != 0) {
            ret = -2;
            goto out;
        }

        if (vicpgn < 0 || vicpgn >= PAGING_MAX_PGN) {
            ret = -9;
            goto out;
        }

        uint32_t vicpte = mm->pgd[vicpgn];
        vicfpn = GETVAL(vicpte, PAGING_PTE_FPN_MASK, PAGING_PTE_FPN_LOBIT);

        if (MEMPHY_get_freefp(caller->active_mswp, &swpfpn) != 0) {
            ret = -3;
            goto out;
        }

        if (__swap_cp_page(caller->mram, vicfpn, caller->active_mswp, swpfpn) != 0) {
            MEMPHY_put_freefp(caller->active_mswp, swpfpn);
            ret = -4;
            goto out;
        }

        int tgtfpn = GETVAL(pte, PAGING_PTE_SWPOFF_MASK, PAGING_PTE_SWPOFF_LOBIT);
        if (__swap_cp_page(caller->active_mswp, tgtfpn, caller->mram, vicfpn) != 0) {
            __swap_cp_page(caller->active_mswp, swpfpn, caller->mram, vicfpn);
            MEMPHY_put_freefp(caller->active_mswp, swpfpn);
            ret = -5;
            goto out;
        }

        MEMPHY_put_freefp(caller->active_mswp, tgtfpn);
        pte_set_swap(&mm->pgd[vicpgn], 0, swpfpn);
        pte_set_fpn(&mm->pgd[pgn], vicfpn);
        *fpn = vicfpn;

        struct pgn_t *new_node = malloc(sizeof(struct pgn_t));
        if (!new_node) {
            ret = -6;
            goto out;
        }
        new_node->pgn = pgn;
        new_node->pg_next = NULL;

        struct pgn_t *curr = caller->mm->fifo_pgn;
        if (curr == NULL)
            caller->mm->fifo_pgn = new_node;
        else {
            while (curr->pg_next != NULL)
                curr = curr->pg_next;
            curr->pg_next = new_node;
        }

    } else {
        *fpn = GETVAL(pte, PAGING_PTE_FPN_MASK, PAGING_PTE_FPN_LOBIT);
        if (*fpn < 0) {
            ret = -10;
            goto out;
        }
    }

out:
    pthread_mutex_unlock(&mem_lock);
    return ret;
}

 
 /*pg_getval - read value at given offset
  *@mm: memory region
  *@addr: virtual address to acess
  *@value: value
  *
  */
 int pg_getval(struct mm_struct *mm, int addr, BYTE *data, struct pcb_t *caller)
 {
   int pgn = PAGING_PGN(addr);
   int off = PAGING_OFFST(addr);
   int fpn;
 
   /* Get the page to MEMRAM, swap from MEMSWAP if needed */
   if (pg_getpage(mm, pgn, &fpn, caller) != 0)
     return -1; /* invalid page access */
 
   int phyaddr = (fpn << PAGING_ADDR_FPN_LOBIT) + off;
 
   MEMPHY_read(caller->mram, phyaddr, data);
 
   return 0;
 }
 
 /*pg_setval - write value to given offset
  *@mm: memory region
  *@addr: virtual address to acess
  *@value: value
  *
  */
 int pg_setval(struct mm_struct *mm, int addr, BYTE value, struct pcb_t *caller)
 {
   int pgn = PAGING_PGN(addr);
   int off = PAGING_OFFST(addr);
   int fpn;
 
   /* Get the page to MEMRAM, swap from MEMSWAP if needed */
   if (pg_getpage(mm, pgn, &fpn, caller) != 0)
     return -1; /* invalid page access */
 
   /* Calculate physical address */
   int phyaddr = fpn * PAGING_PAGESZ + off;
 
   /* Write data to physical memory */
   if (MEMPHY_write(caller->mram, phyaddr, value) != 0)
     return -1; /* failed to write memory */
 
   /* Use SYSCALL 17 sys_memmap with SYSMEM_IO_WRITE */
 
   return 0;
 }
 
 /*__read - read value in region memory
  *@caller: caller
  *@vmaid: ID vm area to alloc memory region
  *@offset: offset to acess in memory region
  *@rgid: memory region ID (used to identify variable in symbole table)
  *@size: allocated size
  *
  */
 int __read(struct pcb_t *caller, int vmaid, int rgid, int offset, BYTE *data)
 {
   struct vm_rg_struct *currg = get_symrg_byid(caller->mm, rgid);
   struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
 
   if (currg == NULL || cur_vma == NULL) /* Invalid memory identify */
     return -1;
 
   pg_getval(caller->mm, currg->rg_start + offset, data, caller);
 
   return 0;
 }
 
 /*libread - PAGING-based read a region memory */
 int libread(
     struct pcb_t *proc, // Process executing the instruction
     uint32_t source,    // Index of source register
     uint32_t offset,    // Source address = [source] + [offset]
     uint32_t *destination)
 {
   BYTE data;
   int ret = __read(proc, 0, source, offset, &data);
 
   *destination = data;
 
   #ifdef IODUMP
    printf("===== PHYSICAL MEMORY AFTER READING ===== \n");
    printf("read region=%d offset=%d value=%d\n", source, offset, data);
   #ifdef PAGETBL_DUMP
     print_pgtbl(proc, 0, -1); // print max TBL
   #endif
     MEMPHY_dump(proc->mram);
   #endif
   return ret;
 }
 
 /*__write - write a region memory
  *@caller: caller
  *@vmaid: ID vm area to alloc memory region
  *@offset: offset to acess in memory region
  *@rgid: memory region ID (used to identify variable in symbole table)
  *@size: allocated size
  *
  */
 int __write(struct pcb_t *caller, int vmaid, int rgid, int offset, BYTE value)
 {

   struct vm_rg_struct *currg = get_symrg_byid(caller->mm, rgid);
   struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
 
   if (currg == NULL || cur_vma == NULL) /* Invalid memory identify */
     return -1;
 
   pg_setval(caller->mm, currg->rg_start + offset, value, caller);
 
   return 0;
 }
 
 /*libwrite - PAGING-based write a region memory */
 int libwrite(
     struct pcb_t *proc,   // Process executing the instruction
     BYTE data,            // Data to be wrttien into memory
     uint32_t destination, // Index of destination register
     uint32_t offset)
 {
    #ifdef IODUMP
    printf("===== PHYSICAL MEMORY AFTER WRITING ===== \n");
     printf("write region=%d offset=%d value=%d\n", destination, offset, data);
   #ifdef PAGETBL_DUMP
     print_pgtbl(proc, 0, -1); // print max TBL
   #endif
     MEMPHY_dump(proc->mram);
   #endif
 
   return __write(proc, 0, destination, offset, data);
 }
 
 /*free_pcb_memphy - collect all memphy of pcb
  *@caller: caller
  *@vmaid: ID vm area to alloc memory region
  *@incpgnum: number of page
  */
 int free_pcb_memph(struct pcb_t *caller)
 {
   int pagenum, fpn;
   uint32_t pte;
 
   for (pagenum = 0; pagenum < PAGING_MAX_PGN; pagenum++)
   {
     pte = caller->mm->pgd[pagenum];
 
     if (!PAGING_PAGE_PRESENT(pte))
     {
       fpn = PAGING_PTE_FPN(pte);
       MEMPHY_put_freefp(caller->mram, fpn);
     }
     else
     {
       fpn = PAGING_PTE_SWP(pte);
       MEMPHY_put_freefp(caller->active_mswp, fpn);
     }
   }
 
   return 0;
 }
 
 
 /*find_victim_page - find victim page using FIFO policy
  *@mm: memory management struct
  *@retpgn: return victim page number
  *
  * Returns 0 on success, negative value on failure
  */
 int find_victim_page(struct mm_struct *mm, int *retpgn)
 {
   static pthread_mutex_t fifo_lock = PTHREAD_MUTEX_INITIALIZER;
 
   /* Validate parameters */
   if (!mm || !retpgn)
   {
     return -1;
   }
 
   pthread_mutex_lock(&fifo_lock);
 
   /* Check if queue is empty */
   struct pgn_t *victim = mm->fifo_pgn;
   if (!victim)
   {
     pthread_mutex_unlock(&fifo_lock);
     return -2; /* Empty queue */
   }
 
   /* Get victim page number from head of queue */
   *retpgn = victim->pgn;
   if (*retpgn < 0 || *retpgn >= PAGING_MAX_PGN)
   {
     /* Invalid page number - remove corrupted entry */
     mm->fifo_pgn = victim->pg_next;
     free(victim);
     pthread_mutex_unlock(&fifo_lock);
     return -3; /* Invalid page number */
   }
 
   /* Remove victim from head of queue */
   mm->fifo_pgn = victim->pg_next;
   victim->pg_next = NULL; /* Safety: clear pointer before free */
   free(victim);
 
   pthread_mutex_unlock(&fifo_lock);
   return 0;
 }
 
 /*get_free_vmrg_area - get a free vm region
  *@caller: caller
  *@vmaid: ID vm area to alloc memory region
  *@size: allocated size
  *
  */
 int get_free_vmrg_area(struct pcb_t *caller, int vmaid, int size, struct vm_rg_struct *newrg)
 {
   struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
 
   struct vm_rg_struct *rgit = cur_vma->vm_freerg_list;
 
   if (rgit == NULL)
     return -1;
 
   /* Probe uninitialized newrg */
   newrg->rg_start = newrg->rg_end = -1;
 
   /* Traverse the list of free vm regions to find a fit space */
   while (rgit != NULL)
   {
     if ((rgit->rg_end - rgit->rg_start) >= size)
     {
       /* Found a suitable region */
       newrg->rg_start = rgit->rg_start;
       newrg->rg_end = rgit->rg_start + size;
 
       /* Update the free region list */
       rgit->rg_start += size;
       if (rgit->rg_start == rgit->rg_end)
       {
         /* Remove the region if fully used */
         cur_vma->vm_freerg_list = rgit->rg_next;
         free(rgit);
       }
       return 0;
     }
     rgit = rgit->rg_next;
   }
 
   return -1; /* No suitable region found */
 }
 
 // #endif
 