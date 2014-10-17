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

#include "shared/file.h"
#include "shared/log.h"
#include "shared/util.h"
#include "signer/backup.h"
#include "signer/keys.h"
#include "signer/signconf.h"

static const char* key_str = "keys";


/**
 * Create a new key list.
 *
 */
keylist_type*
keylist_create(void* sc)
{
    signconf_type* signconf = (signconf_type*) sc;
    keylist_type* kl = NULL;

    if (!signconf || !signconf->allocator) {
        return NULL;
    }
    kl = (keylist_type*) allocator_alloc(signconf->allocator,
        sizeof(keylist_type));
    if (!kl) {
        ods_log_error("[%s] create list failed: allocator_alloc() failed",
            key_str);
        return NULL;
    }
    kl->sc = sc;
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
 * Lookup a key in the key list by dnskey.
 *
 */
key_type*
keylist_lookup_by_dnskey(keylist_type* kl, ldns_rr* dnskey)
{
    uint16_t i = 0;
    if (!kl || !dnskey || kl->count <= 0) {
        return NULL;
    }
    for (i=0; i < kl->count; i++) {
        if (&kl->keys[i] && kl->keys[i].dnskey) {
            if (ldns_rr_compare(kl->keys[i].dnskey, dnskey) == 0) {
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
keylist_push(keylist_type* kl, const char* locator,
    uint8_t algorithm, uint32_t flags, int publish, int ksk, int zsk,
    int rfc5011)
{
    key_type* keys_old = NULL;
    signconf_type* sc = NULL;

    ods_log_assert(kl);
    ods_log_assert(locator);
    ods_log_debug("[%s] add locator %s", key_str, locator);

    sc = (signconf_type*) kl->sc;
    keys_old = kl->keys;
    kl->keys = (key_type*) allocator_alloc(sc->allocator,
        (kl->count + 1) * sizeof(key_type));
    if (!kl->keys) {
        ods_fatal_exit("[%s] unable to add key: allocator_alloc() failed",
            key_str);
    }
    if (keys_old) {
        memcpy(kl->keys, keys_old, (kl->count) * sizeof(key_type));
    }
    allocator_deallocate(sc->allocator, (void*) keys_old);
    kl->count++;
    kl->keys[kl->count -1].locator = locator;
    kl->keys[kl->count -1].algorithm = algorithm;
    kl->keys[kl->count -1].flags = flags;
    kl->keys[kl->count -1].publish = publish;
    kl->keys[kl->count -1].ksk = ksk;
    kl->keys[kl->count -1].zsk = zsk;
    kl->keys[kl->count -1].rfc5011 = rfc5011;
    kl->keys[kl->count -1].dnskey = NULL;
    kl->keys[kl->count -1].hsmkey = NULL;
    kl->keys[kl->count -1].params = NULL;
    return &kl->keys[kl->count -1];
}


/**
 * Print key.
 *
 */
static void
key_print(FILE* fd, key_type* key)
{
    if (!fd || !key) {
        return;
    }
    fprintf(fd, "\t\t\t<Key>\n");
    fprintf(fd, "\t\t\t\t<Flags>%u</Flags>\n", key->flags);
    fprintf(fd, "\t\t\t\t<Algorithm>%u</Algorithm>\n", key->algorithm);
    if (key->locator) {
        fprintf(fd, "\t\t\t\t<Locator>%s</Locator>\n", key->locator);
    }
    if (key->ksk) {
        fprintf(fd, "\t\t\t\t<KSK />\n");
    }
    if (key->zsk) {
        fprintf(fd, "\t\t\t\t<ZSK />\n");
    }
    if (key->publish) {
        fprintf(fd, "\t\t\t\t<Publish />\n");
    }
    fprintf(fd, "\t\t\t</Key>\n");
    fprintf(fd, "\n");
    return;
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
    return;
}


/**
 * Print key list.
 *
 */
void
keylist_print(FILE* fd, keylist_type* kl)
{
    uint16_t i = 0;
    if (!fd || !kl || kl->count <= 0) {
        return;
    }
    for (i=0; i < kl->count; i++) {
        key_print(fd, &kl->keys[i]);
    }
    return;
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
    return;
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
    /* ldns_rr_free(key->dnskey); */
    hsm_key_free(key->hsmkey);
    hsm_sign_params_free(key->params);
    free((void*) key->locator);
    return;
}


/**
 * Clean up key list.
 *
 */
void
keylist_cleanup(keylist_type* kl)
{
    uint16_t i = 0;
    signconf_type* sc = NULL;
    if (!kl) {
        return;
    }
    for (i=0; i < kl->count; i++) {
        key_delfunc(&kl->keys[i]);
    }
    sc = (signconf_type*) kl->sc;
    allocator_deallocate(sc->allocator, (void*) kl->keys);
    allocator_deallocate(sc->allocator, (void*) kl);
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
    fprintf(fd, ";;Key: locator %s algorithm %u flags %u publish %i ksk %i "
        "zsk %i\n", key->locator, (unsigned) key->algorithm,
        (unsigned) key->flags, key->publish, key->ksk, key->zsk);
    if (strcmp(version, ODS_SE_FILE_MAGIC_V2) == 0) {
        if (key->dnskey) {
            (void)util_rr_print(fd, key->dnskey);
        }
        fprintf(fd, ";;Keydone\n");
    }
    return;
}


/**
 * Recover key from backup.
 *
 */
key_type*
key_recover2(FILE* fd, keylist_type* kl)
{
    const char* locator = NULL;
    uint8_t algorithm = 0;
    uint32_t flags = 0;
    int publish = 0;
    int ksk = 0;
    int zsk = 0;
    int rfc5011 = 0;

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
        !backup_read_check_str(fd, "rfc5011") ||
        !backup_read_int(fd, &rfc5011)) {
        if (locator) {
           free((void*)locator);
           locator = NULL;
        }
        return NULL;
    }
    /* key ok */
    return keylist_push(kl, locator, algorithm, flags, publish, ksk,
        zsk, rfc5011);
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
    return;
}
