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
 * Signal handling.
 *
 */

#include "config.h"

#include <pthread.h>
#include <signal.h>

#include "daemon/engine.h"
#include "daemon/signal.h"
#include "log.h"

#include "signal.h"

static engine_type* signal_engine = NULL;
static const char* signal_str = "signal";


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
void *
signal_handler(sig_atomic_t sig)
{
    switch (sig) {
        case SIGHUP:
            ods_log_debug("[%s] SIGHUP received", signal_str);
            if (signal_engine) {
                signal_engine->need_to_reload = 1;
                pthread_mutex_lock(&signal_engine->signal_lock);
                    pthread_cond_signal(&signal_engine->signal_cond);
                pthread_mutex_unlock(&signal_engine->signal_lock);
            }
            break;
        case SIGINT:
        case SIGTERM:
            ods_log_debug("[%s] SIGTERM received", signal_str);
            if (signal_engine) {
                signal_engine->need_to_exit = 1;
                pthread_mutex_lock(&signal_engine->signal_lock);
                    pthread_cond_signal(&signal_engine->signal_cond);
                pthread_mutex_unlock(&signal_engine->signal_lock);
            }
            break;
        default:
            ods_log_debug("[%s] Spurious signal %d received", 
                signal_str, (int)sig);
            break;
    }
    return NULL;
}
