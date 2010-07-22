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

#ifndef DAEMON_SIGNAL_H
#define DAEMON_SIGNAL_H

#include "config.h"

#include <signal.h>

#define SIGNAL_RUN 0
#define SIGNAL_INIT 1
#define SIGNAL_RELOAD 2
#define SIGNAL_SHUTDOWN 3

struct engine_struct;

/**
 * Set corresponding engine.
 * \param[in] engine corresponding engine
 *
 */
void
signal_set_engine(struct engine_struct* engine);

/**
 * Handle signals.
 * \param[in] sig signal to handle
 *
 */
void signal_handler(sig_atomic_t sig);

/**
 * Capture signal.
 * \param[in] dflsig default signal
 * \return sig_atomic_t captured signal
 *
 */
sig_atomic_t signal_capture(sig_atomic_t dflsig);

#endif /* DAEMON_SIGNAL_H */
