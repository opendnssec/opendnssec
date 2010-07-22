/*
 * $Id$
 *
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
 * Signal handling.
 *
 */

#include "config.h"
#include "daemon/engine.h"
#include "daemon/signal.h"
#include "scheduler/locks.h"

#include <signal.h>

static int signal_hup_recvd = 0;
static int signal_term_recvd = 0;
static engine_type* signal_engine = NULL;


/**
 * Set corresponding engine.
 *
 */
void
signal_set_engine(struct engine_struct* engine)
{
    signal_engine = (engine_type*) engine;
}


/**
 * Handle signals.
 *
 */
void
signal_handler(sig_atomic_t sig)
{
    switch (sig) {
        case SIGHUP:
            se_log_debug("reload signal received");
            signal_hup_recvd++;
            if (signal_engine) {
                lock_basic_lock(&signal_engine->signal_lock);
                lock_basic_alarm(&signal_engine->signal_cond);
                lock_basic_unlock(&signal_engine->signal_lock);
            }
            break;
        case SIGTERM:
            se_log_debug("shutdown signal received");
            signal_term_recvd++;
            if (signal_engine) {
                lock_basic_lock(&signal_engine->signal_lock);
                lock_basic_alarm(&signal_engine->signal_cond);
                lock_basic_unlock(&signal_engine->signal_lock);
            }
            break;
        default:
            break;
    }
    return;
}


/**
 * Capture signal.
 *
 */
sig_atomic_t
signal_capture(sig_atomic_t dflsig)
{
    if (signal_term_recvd) {
        signal_term_recvd = 0;
        return SIGNAL_SHUTDOWN;
    } else if (signal_hup_recvd) {
        signal_hup_recvd = 0;
        return SIGNAL_RELOAD;
    }
    return dflsig;
}
