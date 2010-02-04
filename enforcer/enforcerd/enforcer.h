/*
 * $Id: communicator.h 1663 2009-08-19 09:04:23Z sion $
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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

#ifndef ENFORCER_H
#define ENFORCER_H

/* 
 * communicator.h code implements the server_main
 * function needed by daemon.c
 *
 * The bit that makes the daemon do something useful
 */

#include "ksm/ksm.h"
#include "libhsm.h"

int server_init(DAEMONCONFIG *config);
void server_main(DAEMONCONFIG *config);

int do_keygen(DAEMONCONFIG *config, KSM_POLICY* policy, hsm_ctx_t *ctx);
int do_communication(DAEMONCONFIG *config, KSM_POLICY* policy);

int commGenSignConf(char* zone_name, int zone_id, char* current_filename, KSM_POLICY *policy, int* signer_flag, int run_interval, int man_key_gen);
int commKeyConfig(void* context, KSM_KEYDATA* key_data);
int allocateKeysToZone(KSM_POLICY *policy, int key_type, int zone_id, uint16_t interval, const char* zone_name, int man_key_gen);
int read_zonelist_filename(const char* filename, char** zone_list_filename);
int do_purge(int interval, int policy_id);

#endif /* ENFORCER_H */
