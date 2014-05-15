/*
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
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
 *
 */

#ifndef _HSM_KEY_FACTORY_H_
#define _HSM_KEY_FACTORY_H_

#ifdef __cplusplus
extern "C" {
#endif

struct hsm_key_factory;
struct hsm_key_factory_key;
typedef struct hsm_key_factory hsm_key_factory_t;
typedef struct hsm_key_factory_key hsm_key_factory_key_t;

#ifdef __cplusplus
}
#endif

#include "db/hsm_key.h"
#include "db/db_configuration.h"
#include "db/db_connection.h"

#ifdef __cplusplus
extern "C" {
#endif

struct hsm_key_factory {
    db_connection_t* connection;
    hsm_key_factory_key_t* hsm_keys;
};

struct hsm_key_factory_key {
    hsm_key_factory_key_t* next;
    hsm_key_t* hsm_key;
};

hsm_key_factory_t* hsm_key_factory_new(const db_configuration_list_t* configuration_list);
void hsm_key_factory_free(hsm_key_factory_t* hsm_key_factory);

hsm_key_factory_key_t* hsm_key_factory_key_new();
void hsm_key_factory_key_free(hsm_key_factory_key_t* hsm_key_factory_key);

#ifdef __cplusplus
}
#endif

#endif /* _HSM_KEY_FACTORY_H_ */
