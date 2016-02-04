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
    return key_data_retrieve_key_state_list(key_data);
}

static const key_state_t* get_key_state(key_data_t* key_data, key_state_type_t type) {
    key_state_list_t* state_list;
    const key_state_t* state;

    if (!key_data) {
        return NULL;
    }

    if (!(state_list = key_data_key_state_list(key_data))) {
        return NULL;
    }

    state = key_state_list_begin(state_list);
    while (state) {
        if (key_state_type(state) == type) {
            break;
        }
        state = key_state_list_next(state_list);
    }

    return state;
}

const key_state_t* key_data_cached_ds(key_data_t* key_data) {
    return get_key_state(key_data, KEY_STATE_TYPE_DS);
}

const key_state_t* key_data_cached_rrsig(key_data_t* key_data) {
    return get_key_state(key_data, KEY_STATE_TYPE_RRSIG);
}

const key_state_t* key_data_cached_dnskey(key_data_t* key_data) {
    return get_key_state(key_data, KEY_STATE_TYPE_DNSKEY);
}

const key_state_t* key_data_cached_rrsigdnskey(key_data_t* key_data) {
    return get_key_state(key_data, KEY_STATE_TYPE_RRSIGDNSKEY);
}

key_state_t* key_data_get_cached_ds(key_data_t* key_data) {
    if (!key_data) {
        return NULL;
    }

    return key_state_new_copy(get_key_state(key_data, KEY_STATE_TYPE_DS));
}

key_state_t* key_data_get_cached_rrsig(key_data_t* key_data) {
    if (!key_data) {
        return NULL;
    }

    return key_state_new_copy(get_key_state(key_data, KEY_STATE_TYPE_RRSIG));
}

key_state_t* key_data_get_cached_dnskey(key_data_t* key_data) {
    if (!key_data) {
        return NULL;
    }

    return key_state_new_copy(get_key_state(key_data, KEY_STATE_TYPE_DNSKEY));
}

key_state_t* key_data_get_cached_rrsigdnskey(key_data_t* key_data) {
    if (!key_data) {
        return NULL;
    }

    return key_state_new_copy(get_key_state(key_data, KEY_STATE_TYPE_RRSIGDNSKEY));
}

const hsm_key_t* key_data_cached_hsm_key(const key_data_t* key_data) {
    return key_data_hsm_key(key_data);
}
