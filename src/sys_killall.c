#include "common.h"
#include "syscall.h"
#include "stdio.h"
#include "libmem.h"
#include "string.h"
#include "queue.h"
#include "pthread.h"
#include <stdlib.h>

pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;

int __sys_killall(struct pcb_t *caller, struct sc_regs* regs)
{
    char proc_name[100];
    uint32_t data;
    uint32_t memrg = regs->a1;
    int i = 0;
    data = 0;
    while (data != -1) {
        libread(caller, memrg, i, &data);
        proc_name[i] = data;
        if (data == -1) proc_name[i] = '\0';
        i++;
    }
    printf("The procname retrieved from memregionid %d is \"%s\"\n", memrg, proc_name);
    extern pthread_mutex_t queue_lock;
    pthread_mutex_lock(&queue_lock);

    struct pcb_t *proc;
    int count = 0;

    struct queue_t *running_list = caller->running_list;
    int running_size = running_list ? running_list->size : 0;
    for (int j = 0; j < running_size; j++) {
        proc = dequeue(running_list);
        if (proc && strcmp(proc->path, proc_name) == 0) {
            free(proc);
            count++;
        } else if (proc) {
            enqueue(running_list, proc);
        }
    }

    struct queue_t *ready_queue = caller->ready_queue;
    int ready_size = ready_queue ? ready_queue->size : 0;
    for (int j = 0; j < ready_size; j++) {
        proc = dequeue(ready_queue);
        if (proc && strcmp(proc->path, proc_name) == 0) {
            free(proc);
            count++;
        } else if (proc) {
            enqueue(ready_queue, proc);
        }
    }

#ifdef MLQ_SCHED
    for (int prio = 0; prio < MAX_PRIO; prio++) {
        struct queue_t *mlq_queue = &caller->mlq_ready_queue[prio];
        int mlq_size = mlq_queue ? mlq_queue->size : 0;
        for (int j = 0; j < mlq_size; j++) {
            proc = dequeue(mlq_queue);
            if (proc && strcmp(proc->path, proc_name) == 0) {
                free(proc);
                count++;
            } else if (proc) {
                enqueue(mlq_queue, proc);
            }
        }
    }
#endif

    pthread_mutex_unlock(&queue_lock);
    return count;
}
