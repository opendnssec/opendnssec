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

#ifndef SIGNER_SE_KEY_H
#define SIGNER_SE_KEY_H

#include <ldns/ldns.h>

/**
 * Key.
 *
 */
typedef struct key_struct key_type;
struct key_struct {
    char* locator;
    ldns_rr* dnskey;
    uint32_t algorithm;
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
 * \param[in] locator string that identifies location of key
 * \param[in] algorithm DNSKEY algorithm field value
 * \param[in] flags DNSKEY flags field value
 * \param[in] publish if true, publish key as a DNSKEY
 * \param[in] ksk if true, sign DNSKEY RRset with this key
 * \param[in] zsk if true, sign all but DNSKEY RRset with this key
 * \return key_type* key
 *
 */
key_type* key_create(const char* locator, uint32_t algorithm, uint32_t flags,
    int publish, int ksk, int zsk);

/**
 * Clean up key.
 * \param[in] key cleaun up this key
 *
 */
void key_cleanup(key_type* key);

/**
 * Print key.
 * \param[in] out file descriptor
 * \param[in] key print this key
 *
 */
void key_print(FILE* out, key_type* key);

/**
 * Create a new key list.
 * \return keylist_type* key list
 *
 */
keylist_type* keylist_create(void);

/**
 * Add a key to the keylist.
 * \param[in] kl key list
 * \param[in] key key
 * \return int 0 on success, 1 on error
 *
 */
int keylist_add(keylist_type* kl, key_type* key);

/**
 * Compare two key references.
 * \param[in] a one key
 * \param[in] b another key
 * \return 0 on equal, -1 if a a < b, 1 if a > b.
 *
 */
int key_compare(key_type* a, key_type* b);

/**
 * Delete a key from the keylist.
 * \param[in] kl key list
 * \param[in] key key
 * \return int 0 on success, 1 on error
 *
 */
int keylist_delete(keylist_type* kl, key_type* key);

/**
 * Compare two key lists.
 * \param[in] a one key list
 * \param[in] b another key list
 * \return 0 on equal, -1 if a a < b, 1 if a > b.
 *
 */
int keylist_compare(keylist_type* a, keylist_type* b);

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

#endif /* SIGNER_SE_KEY_H */
