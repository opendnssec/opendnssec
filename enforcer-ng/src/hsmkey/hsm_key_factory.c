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

#include "hsmkey/hsm_key_factory.h"

#include "mm.h"
#include "db/hsm_key.h"

#include <stdlib.h>

/* HSM KEY FACTORY */

hsm_key_factory_t* hsm_key_factory_new(const db_configuration_list_t* configuration_list) {
    hsm_key_factory_t* hsm_key_factory =
        (hsm_key_factory_t*)calloc(1, sizeof(hsm_key_factory_t));
    hsm_key_list_t* hsm_key_list;
    hsm_key_t* hsm_key;
    db_clause_list_t* clause_list;
    hsm_key_factory_key_t* hsm_key_factory_key;

    if (hsm_key_factory) {
        /*
         * Create a database connection
         */
        if (!(hsm_key_factory->connection = db_connection_new())
            || db_connection_set_configuration_list(hsm_key_factory->connection, configuration_list)
            || db_connection_setup(hsm_key_factory->connection))
        {
            hsm_key_factory_free(hsm_key_factory);
            return NULL;
        }

        /*
         * Get all hsm keys that are in UNUSED state and store them in hsm_keys
         */
        if (!(clause_list = db_clause_list_new())
            || !hsm_key_state_clause(clause_list, HSM_KEY_STATE_UNUSED)
            || !(hsm_key_list = hsm_key_list_new_get_by_clauses(hsm_key_factory->connection, clause_list)))
        {
            db_clause_list_free(clause_list);
            hsm_key_factory_free(hsm_key_factory);
            return NULL;
        }
        db_clause_list_free(clause_list);

        while ((hsm_key = hsm_key_list_get_next(hsm_key_list))) {
            if (!(hsm_key_factory_key = hsm_key_factory_key_new())) {
                hsm_key_free(hsm_key);
                hsm_key_list_free(hsm_key_list);
                hsm_key_factory_free(hsm_key_factory);
                return NULL;
            }

            hsm_key_factory_key->hsm_key = hsm_key;
            hsm_key_factory_key->next = hsm_key_factory->hsm_keys;
            hsm_key_factory->hsm_keys = hsm_key_factory_key;
        }
        hsm_key_list_free(hsm_key_list);
    }

    return hsm_key_factory;
}

void hsm_key_factory_free(hsm_key_factory_t* hsm_key_factory) {
    hsm_key_factory_key_t* hsm_key_factory_key;

    if (hsm_key_factory) {
        if (hsm_key_factory->connection) {
            db_connection_free(hsm_key_factory->connection);
        }
        if (hsm_key_factory->hsm_keys) {
            while ((hsm_key_factory_key = hsm_key_factory->hsm_keys)) {
                hsm_key_factory->hsm_keys = hsm_key_factory_key->next;
                hsm_key_factory_key_free(hsm_key_factory_key);
            }
        }
        free(hsm_key_factory);
    }
}

/* HSM KEY FACTORY KEY */

static mm_alloc_t __hsm_key_factory_key_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(hsm_key_factory_key_t));

hsm_key_factory_key_t* hsm_key_factory_key_new() {
    hsm_key_factory_key_t* hsm_key_factory_key =
        (hsm_key_factory_key_t*)mm_alloc_new0(&__hsm_key_factory_key_alloc);

    return hsm_key_factory_key;
}

void hsm_key_factory_key_free(hsm_key_factory_key_t* hsm_key_factory_key) {
    if (hsm_key_factory_key) {
        if (hsm_key_factory_key->hsm_key) {
            hsm_key_free(hsm_key_factory_key->hsm_key);
        }
        mm_alloc_delete(&__hsm_key_factory_key_alloc, hsm_key_factory_key);
    }
}
