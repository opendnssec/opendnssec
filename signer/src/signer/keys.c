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

/**
 * Signing keys.
 *
 */

#include "file.h"
#include "log.h"
#include "util.h"
#include "signer/backup.h"
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


/**
 * Backup key.
 *
 */
static void
key_backup(FILE* fd, key_type* key, const char* version)
{
    if (!fd || !key) {
        return;
    }
    fprintf(fd, ";;Key: locator %s algorithm %u flags %u publish %i ksk %i zsk %i keytag %d\n", key->locator, (unsigned) key->algorithm,
        (unsigned) key->flags, key->publish, key->ksk, key->zsk, ldns_calc_keytag(key->dnskey));
    if (strcmp(version, ODS_SE_FILE_MAGIC_V2) == 0) {
        if (key->dnskey) {
            (void)util_rr_print(fd, key->dnskey);
        }
        fprintf(fd, ";;Keydone\n");
    }
}


/**
 * Recover key from backup.
 *
 */
key_type*
key_recover2(FILE* fd, keylist_type* kl)
{
    const char* locator = NULL;
    const char* resourcerecord = NULL;
    uint8_t algorithm = 0;
    uint32_t flags = 0;
    int publish = 0;
    int ksk = 0;
    int zsk = 0;
    int keytag = 0; /* We are not actually interested but we must
        parse it to continue correctly in the stream.
        When reading 1.4.8 or later version backup file, the real value of keytag is 
        rfc5011, but not importat due to not using it.*/
    ods_log_assert(fd);

    if (!backup_read_check_str(fd, "locator") ||
        !backup_read_str(fd, &locator) ||
        !backup_read_check_str(fd, "algorithm") ||
        !backup_read_uint8_t(fd, &algorithm) ||
        !backup_read_check_str(fd, "flags") ||
        !backup_read_uint32_t(fd, &flags) ||
        !backup_read_check_str(fd, "publish") ||
        !backup_read_int(fd, &publish) ||
        !backup_read_check_str(fd, "ksk") ||
        !backup_read_int(fd, &ksk) ||
        !backup_read_check_str(fd, "zsk") ||
        !backup_read_int(fd, &zsk) ||
        !backup_read_check_str(fd, "keytag") ||
        !backup_read_int(fd, &keytag)) {
        if (locator) {
           free((void*)locator);
           locator = NULL;
        }
        return NULL;
    }
    /* key ok */
    return keylist_push(kl, locator, resourcerecord, algorithm, flags, publish, ksk, zsk);
}


/**
 * Backup key list.
 *
 */
void
keylist_backup(FILE* fd, keylist_type* kl, const char* version)
{
    uint16_t i = 0;
    if (!fd || !kl || kl->count <= 0) {
        return;
    }
    for (i=0; i < kl->count; i++) {
        key_backup(fd, &kl->keys[i], version);
    }
}
