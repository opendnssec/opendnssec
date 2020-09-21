/*
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

#ifndef SIGNER_KEYS_H
#define SIGNER_KEYS_H

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <ldns/ldns.h>

typedef struct key_struct key_type;
typedef struct keylist_struct keylist_type;

#include "status.h"
#include "libhsm.h"
#include "libhsmdns.h"
#include "signconf.h"

/**
 * Key.
 *
 */
struct key_struct {
    ldns_rr* dnskey;
    hsm_sign_params_t* params;
    const char* locator;
    const char* resourcerecord;
    uint8_t algorithm;
    uint32_t flags;
    int publish;
    int ksk;
    int zsk;
};

/**
 * Key list.
 *
 */
struct keylist_struct {
    signconf_type* sc;
    key_type* keys;
    size_t count;
};

/**
 * Create a new key list.
 * \param[in] sc signer configuration reference
 * \return keylist_type* key list
 *
 */
extern keylist_type* keylist_create(signconf_type* sc);

/**
 * Lookup a key in the key list by locator.
 * \param[in] kl key list
 * \param[in] locator  key locator
 * \return key_type* key if it exists, NULL otherwise
 *
 */
extern key_type* keylist_lookup_by_locator(keylist_type* kl, const char* locator);

/**
 * Push a key to the keylist.
 * \param[in] kl key list
 * \param[in] locator string that identifies location of key
 * \param[in] algorithm DNSKEY algorithm field value
 * \param[in] flags DNSKEY flags field value
 * \param[in] publish if true, publish key as a DNSKEY
 * \param[in] ksk if true, sign DNSKEY RRset with this key
 * \param[in] zsk if true, sign all but DNSKEY RRset with this key
 * \return key_type* key
 *
 */
extern key_type* keylist_push(keylist_type* kl, const char* locator, const char* resourcerecord,
    uint8_t algorithm, uint32_t flags, int publish, int ksk, int zsk);

/**
 * Log key list.
 * \param[in] kl key list to print
 * \param[in] name zone name
 *
 */
extern void keylist_log(keylist_type* kl, const char* name);

/**
 * Clean up key list.
 * \param[in] kl key list to clean up
 *
 */
extern void keylist_cleanup(keylist_type* kl);

/**
 * Recover key from backup.
 * \param[in] fd file descriptor of key backup file
 * \param[in] kl key list to print
 * \return key_type* key
 *
 */
key_type* key_recover2(FILE* fd, keylist_type* kl);

/**
 * Backup key list.
 * \param[in] fd file descriptor
 * \param[in] kl key list to print
 * \param[in] version version string
 *
 */
void keylist_backup(FILE* fd, keylist_type* kl, const char* version);

#endif /* SIGNER_KEYS_H */
