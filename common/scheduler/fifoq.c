/*
 * Copyright (c) 2011-2018 NLNet Labs.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include <ldns/ldns.h>
#include "scheduler/fifoq.h"
#include "log.h"

#define FIFOQ_MAX_COUNT 1000

struct fifoq_struct {
    struct fifoq_item queue[FIFOQ_MAX_COUNT];
    int head;       // index to the first to be popped item in the queue
    int tail;       // index to the first open item in the queue
    int capacity;   // size/capacity of queue left open and filled
    int size;       // number of items left open in queue
    int terminate;
    pthread_mutex_t lock;
    pthread_cond_t headwait;
    pthread_cond_t tailwait;
};

fifoq_type
fifoq_create(void)
{
    fifoq_type fifoq;
    CHECKALLOC(fifoq = (fifoq_type) malloc(sizeof(struct fifoq_struct)));
    fifoq->capacity = FIFOQ_MAX_COUNT;
    fifoq->head = 0;
    fifoq->tail = 0;
    fifoq->size = 0;
    fifoq->terminate = 0;
    pthread_mutex_init(&fifoq->lock, NULL);
    pthread_cond_init(&fifoq->headwait, NULL);
    pthread_cond_init(&fifoq->tailwait, NULL);
    return fifoq;
}

void
fifoq_cleanup(fifoq_type fifoq)
{
    pthread_cond_destroy(&fifoq->headwait);
    pthread_cond_destroy(&fifoq->tailwait);
    pthread_mutex_destroy(&fifoq->lock);
    free(fifoq);
}

void
fifoq_pop(fifoq_type fifoq, struct fifoq_item* items, int* count)
{
    int current;
    assert(*count > 0);
    pthread_mutex_lock(&fifoq->lock);
    while(fifoq->size <= 0) {
        int r = pthread_cond_wait(&fifoq->headwait, &fifoq->lock);
        assert(r==0);
        if(fifoq->terminate) {
            pthread_mutex_unlock(&fifoq->lock);
            *count = 0;
            return;
        }
    }
    current = fifoq->head;
    assert(*count > 0);
    if(fifoq->head >= fifoq->tail) {
        if(fifoq->capacity - fifoq->head < *count) {
            *count = fifoq->capacity - fifoq->head;
        }
    } else if(fifoq->head < fifoq->tail) {
        if(fifoq->tail - fifoq->head < *count) {
            *count = fifoq->tail - fifoq->head;
        }
    }
    assert(*count > 0);
    fifoq->head = (fifoq->head + *count) % fifoq->capacity;
    fifoq->size -= *count;
    memcpy(items, &fifoq->queue[current], sizeof(struct fifoq_item) * *count);
    pthread_cond_signal(&fifoq->tailwait);
    pthread_mutex_unlock(&fifoq->lock);
}


int
fifoq_push(fifoq_type fifoq, struct fifoq_item qs)
{
    int current;
    pthread_mutex_lock(&fifoq->lock);
    while(fifoq->size == fifoq->capacity) {
        pthread_cond_wait(&fifoq->tailwait, &fifoq->lock);
        if(fifoq->terminate) {
            pthread_mutex_unlock(&fifoq->lock);
            return 1;
        }
    }
    current = fifoq->tail;
    fifoq->tail = (fifoq->tail + 1) % fifoq->capacity;
    fifoq->size += 1;
    fifoq->queue[current] = qs;
    pthread_cond_signal(&fifoq->headwait);
    pthread_mutex_unlock(&fifoq->lock);
    return 0;
}

void
fifoq_waitfor(fifoq_type fifoq, worker_type* worker, long nsubtasks, long* nsubtasksfailed)
{
    pthread_mutex_lock(&fifoq->lock);
    worker->tasksOutstanding += nsubtasks;
    while (worker->tasksOutstanding > 0 && !worker->need_to_exit) {
        pthread_cond_wait(&worker->tasksBlocker, &fifoq->lock);
    }
    *nsubtasksfailed = worker->tasksFailed;
    worker->tasksFailed = 0;
    pthread_mutex_unlock(&fifoq->lock);
}

void
fifoq_report(fifoq_type fifoq, worker_type* superior, ods_status subtaskstatus)
{
    pthread_mutex_lock(&fifoq->lock);
    if (subtaskstatus != ODS_STATUS_OK) {
        superior->tasksFailed += 1;
    }
    superior->tasksOutstanding -= 1;
    if (superior->tasksOutstanding == 0) {
        pthread_cond_signal(&superior->tasksBlocker);
    }
    pthread_mutex_unlock(&fifoq->lock);
}

void
fifoq_notifyall(fifoq_type fifoq)
{
    pthread_mutex_lock(&fifoq->lock);
    pthread_cond_broadcast(&fifoq->headwait);
    pthread_cond_broadcast(&fifoq->tailwait);
    pthread_mutex_unlock(&fifoq->lock);
}

void
fifoq_terminate(fifoq_type fifoq)
{
    pthread_mutex_lock(&fifoq->lock);
    fifoq->terminate = 1;
    pthread_cond_broadcast(&fifoq->headwait);
    pthread_cond_broadcast(&fifoq->tailwait);
    pthread_mutex_unlock(&fifoq->lock);
}
