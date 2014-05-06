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

#ifndef __key_data_ext_h
#define __key_data_ext_h

#include "key_state.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get the key states objects for a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_get_key_states(key_data_t* key_data);

/**
 * Get the DS key state object of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
const key_state_t* key_data_get_ds2(key_data_t* key_data);

/**
 * Get the RRSIG key state object of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
const key_state_t* key_data_get_rrsig2(key_data_t* key_data);

/**
 * Get the DNSKEY key state object of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
const key_state_t* key_data_get_dnskey2(key_data_t* key_data);

/**
 * Get the RRSIG DNSKEY key state object of a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
const key_state_t* key_data_get_rrsigdnskey2(key_data_t* key_data);

/**
 * Tests if key has KSK role (includes CSK)
 * \param[in] key_data a key_data_t pointer.
 * \return 1 if ksk, 0 otherwise or error
 */
int key_data_is_ksk(const key_data_t* key_data);

/**
 * Tests if key has ZSK role (includes CSK)
 * \param[in] key_data a key_data_t pointer.
 * \return 1 if zsk, 0 otherwise or error
 */
int key_data_is_zsk(const key_data_t* key_data);

/**
 * Get key data objects from the database for the ds commands. Theses are
 * filtered by `zone_id`, `role`, `ds_at_parent` and either `locator` or
 * `keytag`.
 * \param[in] key_data_list a key_data_list_t pointer.
 * \param[in] zone_id a db_value_t pointer.
 * \param[in] ds_at_parent a key_data_ds_at_parent_t.
 * \param[in] locator a character pointer.
 * \param[in] keytag an unsigned integer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
int key_data_list_get_for_ds(key_data_list_t* key_data_list,
    const db_value_t* zone_id, key_data_ds_at_parent_t ds_at_parent,
    const char* locator, unsigned int keytag);

#ifdef __cplusplus
}
#endif

#endif
