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

#ifndef SIGNER_SE_KEYS_H
#define SIGNER_SE_KEYS_H

#include "config.h"

#include <ctype.h>
#include <ldns/ldns.h>
#include <stdint.h>
#include <stdio.h>


/**
 * Key.
 *
 */
typedef struct key_struct key_type;
struct key_struct {
    const char* locator;
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
    int count;
    key_type* first_key;
};

/**
 * Create a new key.
 * \param[in] locator locator in the hsm
 * \param[in] algorithm dnskey algorithm
 * \param[in] flags dnskey flags
 * \param[in] publish publish key
 * \param[in] ksk sign dnskey set
 * \param[in] zsk sign other rrsets
 * \return key_type* created key
 *
 */
key_type* key_create(const char* locator, uint32_t algorithm, uint32_t flags,
    int publish, int ksk, int zsk);

/**
 * Compare two keys.
 * \param[in] a one key
 * \param[in] b another key
 * \return -1, 0 or 1
 *
 */
int key_compare(key_type* a, key_type* b);

/**
 * Clean up key.
 * \param[in] key key to cleanup
 *
 */
void key_cleanup(key_type* key);

/**
 * Print key.
 * \param[in] out file descriptor
 * \param[in] key key to print
 *
 */
void key_print(FILE* out, key_type* key);

/**
 * Create a new key list.
 * \return keylist_type* empty key list
 *
 */
keylist_type* keylist_create(void);

/**
 * Add a key to the keylist.
 * \param[in] kl key list
 * \param[in] key key to add
 * \return int 0 on success, 1 on fail
 *
 */
int keylist_add(keylist_type* kl, key_type* key);

/**
 * Delete a key from the keylist.
 * \param[in] kl key list
 * \param[in] key key to delete
 * \return int 0 on success, 1 on fail
 *
 */
int keylist_delete(keylist_type* kl, key_type* key);

/**
 * Compare two key lists.
 * \param[in] a one key list
 * \param[in] b another key
 * \return -1, 0 or 1
 *
 */
int keylist_compare(keylist_type* a, keylist_type* b);

/**
 * Clean up key list.
 * \param[in] kl key list to cleanup
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

#endif /* SIGNER_SE_KEYS_H */
