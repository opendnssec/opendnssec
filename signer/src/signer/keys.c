/*
 * Copyright (c) 2009-2018 NLNet Labs.
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
 */

/**
 * Signing keys.
 *
 */

#include "file.h"
#include "log.h"
#include "util.h"
#include "signer/keys.h"
#include "signer/signconf.h"
#include "status.h"

static const char* key_str = "keys";


/**
 * Create a new key list.
 *
 */
keylist_type*
keylist_create(signconf_type* signconf)
{
    keylist_type* kl = NULL;

    if (!signconf) {
        return NULL;
    }
    CHECKALLOC(kl = (keylist_type*) malloc((sizeof(keylist_type))));
    kl->sc = signconf;
    kl->count = 0;
    kl->keys = NULL;
    return kl;
}


/**
 * Lookup a key in the key list by locator.
 *
 */
key_type*
keylist_lookup_by_locator(keylist_type* kl, const char* locator)
{
    uint16_t i = 0;
    if (!kl || !locator || kl->count <= 0) {
        return NULL;
    }
    for (i=0; i < kl->count; i++) {
        if (&kl->keys[i] && kl->keys[i].locator) {
            if (ods_strcmp(kl->keys[i].locator, locator) == 0) {
                return &kl->keys[i];
            }
        }
    }
    return NULL;
}


/**
 * Push a key to the key list.
 *
 */
key_type*
keylist_push(keylist_type* kl, const char* locator, const char* resourcerecord,
    uint8_t algorithm, uint32_t flags, int publish, int ksk, int zsk)
{
    key_type* keys_old = NULL;

    ods_log_assert(kl);

    keys_old = kl->keys;
    CHECKALLOC(kl->keys = (key_type*) malloc((kl->count + 1) * sizeof(key_type)));
    if (keys_old) {
        memcpy(kl->keys, keys_old, (kl->count) * sizeof(key_type));
    }
    free(keys_old);
    kl->count++;
    kl->keys[kl->count -1].locator = locator;
    kl->keys[kl->count -1].resourcerecord = resourcerecord;
    kl->keys[kl->count -1].algorithm = algorithm;
    kl->keys[kl->count -1].flags = flags;
    kl->keys[kl->count -1].publish = publish;
    kl->keys[kl->count -1].ksk = ksk;
    kl->keys[kl->count -1].zsk = zsk;
    kl->keys[kl->count -1].dnskey = NULL;
    kl->keys[kl->count -1].params = NULL;
    return &kl->keys[kl->count -1];
}


/**
 * Log key.
 *
 */
static void
key_log(key_type* key, const char* name)
{
    if (!key) {
        return;
    }
    ods_log_debug("[%s] zone %s key: LOCATOR[%s] FLAGS[%u] ALGORITHM[%u] "
        "KSK[%i] ZSK[%i] PUBLISH[%i]", key_str, name?name:"(null)", key->locator,
        key->flags, key->algorithm, key->ksk, key->zsk, key->publish);
}


/**
 * Log key list.
 *
 */
void
keylist_log(keylist_type* kl, const char* name)
{
    uint16_t i = 0;
    if (!kl || kl->count <= 0) {
        return;
    }
    for (i=0; i < kl->count; i++) {
        key_log(&kl->keys[i], name);
    }
}


/**
 * Clean up key.
 *
 */
static void
key_delfunc(key_type* key)
{
    if (!key) {
        return;
    }
    /*We leak this every time the signconf is reloaded. Although the IXFR structure*/
    /*copies this RR there is a race condition between this func and the ixfr_del*/
    /*function to copy / delete it. */
    /*ldns_rr_free(key->dnskey);*/
    hsm_sign_params_free(key->params);
    free((void*) key->locator);
}


/**
 * Clean up key list.
 *
 */
void
keylist_cleanup(keylist_type* kl)
{
    uint16_t i = 0;
    if (!kl) {
        return;
    }
    for (i=0; i < kl->count; i++) {
        key_delfunc(&kl->keys[i]);
    }
    free(kl->keys);
    free(kl);
}
