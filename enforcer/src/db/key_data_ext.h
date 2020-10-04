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
#include "hsm_key.h"

/**
 * Cache all key states objects for a key data object.
 * \param[in] key_data a key_data_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int key_data_cache_key_states(key_data_t* key_data);

/**
 * Get the cached DS key state object of a key data object.
 * key_data_cache_key_states() must have been called before this.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
extern const key_state_t* key_data_cached_ds(key_data_t* key_data);

/**
 * Get the cached RRSIG key state object of a key data object.
 * key_data_cache_key_states() must have been called before this.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
extern const key_state_t* key_data_cached_rrsig(key_data_t* key_data);

/**
 * Get the cached DNSKEY key state object of a key data object.
 * key_data_cache_key_states() must have been called before this.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
extern const key_state_t* key_data_cached_dnskey(key_data_t* key_data);

/**
 * Get the cached RRSIG DNSKEY key state object of a key data object.
 * key_data_cache_key_states() must have been called before this.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
extern const key_state_t* key_data_cached_rrsigdnskey(key_data_t* key_data);

/**
 * Get the cached DS key state object of a key data object.
 * key_data_cache_key_states() must have been called before this.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
extern key_state_t* key_data_get_cached_ds(key_data_t* key_data);

/**
 * Get the cached RRSIG key state object of a key data object.
 * key_data_cache_key_states() must have been called before this.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
extern key_state_t* key_data_get_cached_rrsig(key_data_t* key_data);

/**
 * Get the cached DNSKEY key state object of a key data object.
 * key_data_cache_key_states() must have been called before this.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
extern key_state_t* key_data_get_cached_dnskey(key_data_t* key_data);

/**
 * Get the cached RRSIG DNSKEY key state object of a key data object.
 * key_data_cache_key_states() must have been called before this.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
extern key_state_t* key_data_get_cached_rrsigdnskey(key_data_t* key_data);

/**
 * Get the cached hsm key object of a key data object.
 * key_data_cache_hsm_key() must have been called before this.
 * \param[in] key_data a key_data_t pointer.
 * \return a key_state_t pointer.
 */
extern const hsm_key_t* key_data_cached_hsm_key(const key_data_t* key_data);

#endif
