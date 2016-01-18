/*
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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
 *
 */

/**
 * Tasks.
 *
 */

#ifndef SCHEDULER_TASK_H
#define SCHEDULER_TASK_H

#include "config.h"
#include <ldns/ldns.h>

enum task_id_enum {
    TASK_NONE = 0,
    TASK_SIGNCONF, /* ods-signer update */
    TASK_READ, /* ods-signer sign */
    TASK_NSECIFY,
    TASK_SIGN, /* ods-signer flush */
    TASK_WRITE
};
typedef enum task_id_enum task_id;

typedef struct task_struct task_type;

#include "status.h"
#include "signer/zone.h"

/**
 * Task.
 */
struct task_struct {
    task_id what;
    task_id interrupt;
    task_id halted;
    time_t when;
    time_t halted_when;
    time_t backoff;
    int flush;
    zone_type* zone;
};

/**
 * Create a new task.
 * \param[in] what task identifier
 * \param[in] when scheduled time
 * \param[in] zone zone reference
 * \return task_type* created task
 *
 */
task_type* task_create(task_id what, time_t when, void* zone);

/**
 * Compare tasks.
 * \param[in] a one task
 * \param[in] b another task
 * \return int -1, 0 or 1
 *
 */
int task_compare(const void* a, const void* b);

/**
 * Convert task to string.
 * \param[in] task task
 * \param[out] buffer to store string-based task in
 * \return string-format task
 *
 */
char* task2str(task_type* task, char* buftask);

/**
 * String-format of who.
 * \param[in] what task identifier
 * \return const char* string-format of what
 *
 */
const char* task_what2str(task_id what);

/**
 * String-format of who.
 * \param[in] task task
 * \return const char* string-format of who
 */
const char* task_who2str(task_type* task);

/**
 * Log task.
 * \param[in] task task
 *
 */
void task_log(task_type* task);

/**
 * Clean up task.
 * \param[in] task task
 *
 */
void task_cleanup(task_type* task);

#endif /* SCHEDULER_TASK_H */
