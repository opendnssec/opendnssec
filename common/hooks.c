/*
 * Copyright (c) 2023 NLNet Labs.
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
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h> /* sigfillset(), sigprocmask() */
#include <string.h> /* strerror() */
#include <time.h> /* gettimeofday() */
#include "locks.h"
#include "log.h"
#include "utilities.h"
#include "err.h"
#include "hooks.h"

// typedef struct hook_struct* hook_t;

struct hook_struct {
    pthread_mutex_t lock;
    int latch;
    long value;
    long minimum;
    long maximum;
};

void
hook_trigger(hook_t hook, const char* arg)
{
    char* cmd;
    int rcode;
    asprintf(&cmd, "%s %s", SIGNER_CLI_UPDATE, arg);
    rcode = system(cmd);
    if (rcode) {
        ods_log_error("unable to notify signer of signconf changes for zone %s!", arg);
    }
    free(cmd);
}

int
hook_ablock(hook_t hook)
{
    return 0;
}

#ifdef NOTDEFINED

int
hook_ablock(hook_t)
{
}

int
hook_ablockrange(hook_t, long minimum, long maximum)
{
}

int
hook_ablockvalue(hook_t, long value)
{
}

void
hook_satisfy(hook_t)
{
}

void
hook_satisfyvalue(hook_t long value)
{
}

void
hook_satisfyrange(hook_t long minimum, long maximum)
{
}

typedef int satifyfn_type(hook_t, void*, va_list);
// yes no
// eat keep

hook_define(satifyfn_type);

#endif
