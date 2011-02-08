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
 * Signing keys.
 *
 */

#ifndef SIGNER_KEYS_H
#define SIGNER_KEYS_H

#include "shared/allocator.h"
#include "shared/status.h"

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <ldns/ldns.h>
#include <libhsm.h>
#include <libhsmdns.h>


/**
 * Key.
 *
 */
typedef struct key_struct key_type;
struct key_struct {
    const char* locator;
    ldns_rr* dnskey;
    hsm_key_t* hsmkey;
    hsm_sign_params_t* params;
    uint8_t algorithm;
    uint32_t flags;
    int publish;
    int ksk;
    int zsk;
    key_type* next;
};

/**
 * Key list.
 *
 */
typedef struct keylist_struct keylist_type;
struct keylist_struct {
    size_t count;
    key_type* first_key;
};

/**
 * Create a new key.
 * \param[in] allocator memory allocator
 * \param[in] locator string that identifies location of key
 * \param[in] algorithm DNSKEY algorithm field value
 * \param[in] flags DNSKEY flags field value
 * \param[in] publish if true, publish key as a DNSKEY
 * \param[in] ksk if true, sign DNSKEY RRset with this key
 * \param[in] zsk if true, sign all but DNSKEY RRset with this key
 * \return key_type* key
 *
 */
key_type* key_create(allocator_type* allocator, const char* locator,
    uint8_t algorithm, uint32_t flags, int publish, int ksk, int zsk);

/**
 * Recover a key from backup.
 * \param[in] fd file descriptor of key backup file
 * \return key_type* key
 *
 */
key_type* key_recover_from_backup(FILE* fd);

/**
 * Create a new key list.
 * \param[in] allocator memory allocator
 * \return keylist_type* key list
 *
 */
keylist_type* keylist_create(allocator_type* allocator);

/**
 * Push a key to the keylist.
 * \param[in] kl key list
 * \param[in] key key
 * \return ods_status status
 *
 */
ods_status keylist_push(keylist_type* kl, key_type* key);

/**
 * Lookup a key in the key list by locator.
 * \param[in] kl key list
 * \param[in] locator  key locator
 * \return key_type* key if it exists, NULL otherwise
 *
 */
key_type* keylist_lookup(keylist_type* kl, const char* locator);

/**
 * Lookup a key in the key list by dnskey.
 * \param[in] kl key list
 * \param[in] dnskey dnskey
 * \return key_type* key if it exists, NULL otherwise
 *
 */
key_type* keylist_lookup_by_dnskey(keylist_type* kl, ldns_rr* dnskey);

/**
 * Clean up key list.
 * \param[in] kl key list to clean up
 *
 */
void keylist_cleanup(keylist_type* kl);

/**
 * Print key list.
 * \param[in] out file descriptor
 * \param[in] kl key list to print
 *
 */
void keylist_print(FILE* out, keylist_type* kl);

/**
 * Log key list.
 * \param[in] kl key list to print
 * \param[in] name zone name
 *
 */
void keylist_log(keylist_type* kl, const char* name);

#endif /* SIGNER_KEYS_H */
