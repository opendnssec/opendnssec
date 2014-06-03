/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
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

#include "key_data.h"
#include "db_error.h"

int key_data_cache_key_states(key_data_t* key_data) {
    key_state_list_t* key_state_list;
    const key_state_t* key_state;
    key_state_t* key_state_ds = NULL;
    key_state_t* key_state_rrsig = NULL;
    key_state_t* key_state_dnskey = NULL;
    key_state_t* key_state_rrsigdnskey = NULL;

    if (!key_data) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_data->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_value_not_empty(&(key_data->id))) {
        return DB_ERROR_UNKNOWN;
    }

    key_state_list = key_state_list_new(db_object_connection(key_data->dbo));
    if (!key_state_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (key_state_list_get_by_key_data_id(key_state_list, &(key_data->id))) {
        key_state_list_free(key_state_list);
        return DB_ERROR_UNKNOWN;
    }

    key_state = key_state_list_next(key_state_list);
    while (key_state) {
        if (key_state_type(key_state) == KEY_STATE_TYPE_DS) {
            if (!(key_state_ds = key_state_new(db_object_connection(key_data->dbo)))
                || key_state_copy(key_state_ds, key_state))
            {
                key_state_free(key_state_ds);
                key_state_free(key_state_rrsig);
                key_state_free(key_state_dnskey);
                key_state_free(key_state_rrsigdnskey);
                key_state_list_free(key_state_list);
                return DB_ERROR_UNKNOWN;
            }
            continue;
        }

        if (key_state_type(key_state) == KEY_STATE_TYPE_RRSIG) {
            if (!(key_state_rrsig = key_state_new(db_object_connection(key_data->dbo)))
                || key_state_copy(key_state_rrsig, key_state))
            {
                key_state_free(key_state_ds);
                key_state_free(key_state_rrsig);
                key_state_free(key_state_dnskey);
                key_state_free(key_state_rrsigdnskey);
                key_state_list_free(key_state_list);
                return DB_ERROR_UNKNOWN;
            }
        }

        if (key_state_type(key_state) == KEY_STATE_TYPE_DNSKEY) {
            if (!(key_state_dnskey = key_state_new(db_object_connection(key_data->dbo)))
                || key_state_copy(key_state_dnskey, key_state))
            {
                key_state_free(key_state_ds);
                key_state_free(key_state_rrsig);
                key_state_free(key_state_dnskey);
                key_state_free(key_state_rrsigdnskey);
                key_state_list_free(key_state_list);
                return DB_ERROR_UNKNOWN;
            }
        }

        if (key_state_type(key_state) == KEY_STATE_TYPE_RRSIGDNSKEY) {
            if (!(key_state_rrsigdnskey = key_state_new(db_object_connection(key_data->dbo)))
                || key_state_copy(key_state_rrsigdnskey, key_state))
            {
                key_state_free(key_state_ds);
                key_state_free(key_state_rrsig);
                key_state_free(key_state_dnskey);
                key_state_free(key_state_rrsigdnskey);
                key_state_list_free(key_state_list);
                return DB_ERROR_UNKNOWN;
            }
        }
        key_state = key_state_list_next(key_state_list);
    }
    key_state_list_free(key_state_list);

    if (key_data->key_state_ds) {
        key_state_free(key_data->key_state_ds);
    }
    key_data->key_state_ds = key_state_ds;
    if (key_data->key_state_rrsig) {
        key_state_free(key_data->key_state_rrsig);
    }
    key_data->key_state_rrsig = key_state_rrsig;
    if (key_data->key_state_dnskey) {
        key_state_free(key_data->key_state_dnskey);
    }
    key_data->key_state_dnskey = key_state_dnskey;
    if (key_data->key_state_rrsigdnskey) {
        key_state_free(key_data->key_state_rrsigdnskey);
    }
    key_data->key_state_rrsigdnskey = key_state_rrsigdnskey;

    return DB_OK;
}

const key_state_t* key_data_cached_ds(key_data_t* key_data) {
    if (!key_data) {
        return NULL;
    }

    return key_data->key_state_ds;
}

const key_state_t* key_data_cached_rrsig(key_data_t* key_data) {
    if (!key_data) {
        return NULL;
    }

    return key_data->key_state_rrsig;
}

const key_state_t* key_data_cached_dnskey(key_data_t* key_data) {
    if (!key_data) {
        return NULL;
    }

    return key_data->key_state_dnskey;
}

const key_state_t* key_data_cached_rrsigdnskey(key_data_t* key_data) {
    if (!key_data) {
        return NULL;
    }

    return key_data->key_state_rrsigdnskey;
}

int key_data_is_ksk(const key_data_t* key_data) {
    if (!key_data) {
        return 0;
    }

    return key_data_role(key_data) == KEY_DATA_ROLE_KSK ||
        key_data_role(key_data) == KEY_DATA_ROLE_CSK;
}

int key_data_is_zsk(const key_data_t* key_data) {
    if (!key_data) {
        return 0;
    }

    return key_data_role(key_data) == KEY_DATA_ROLE_ZSK ||
        key_data_role(key_data) == KEY_DATA_ROLE_CSK;
}
