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

#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/status.h"
#include "signer/backup.h"
#include "signer/keys.h"

static const char* key_str = "keys";


/**
 * Create a new key.
 *
 */
key_type*
key_create(allocator_type* allocator, const char* locator, uint8_t algorithm,
    uint32_t flags, int publish, int ksk, int zsk)
{
    key_type* key;

    if (!allocator) {
        ods_log_error("[%s] create key failed: no allocator available",
            key_str);
        return NULL;
    }
    ods_log_assert(allocator);

    if (!locator || !algorithm || !flags) {
        ods_log_error("[%s] create failed: missing required elements",
            key_str);
        return NULL;
    }
    ods_log_assert(locator);
    ods_log_assert(algorithm);
    ods_log_assert(flags);

    key = (key_type*) allocator_alloc(allocator, sizeof(key_type));
    if (!key) {
        ods_log_error("[%s] create key failed: allocator failed",
            key_str);
        return NULL;
    }
    ods_log_assert(key);

    key->allocator = allocator;
    key->locator = allocator_strdup(allocator, locator);
    key->dnskey = NULL;
    key->hsmkey = NULL;
    key->params = NULL;
    key->algorithm = algorithm;
    key->flags = flags;
    key->publish = publish;
    key->ksk = ksk;
    key->zsk = zsk;
    key->next = NULL;
    return key;
}


/**
 * Recover key from backup.
 *
 */
key_type*
key_recover(FILE* fd, allocator_type* allocator)
{
    key_type* key = NULL;
    const char* locator = NULL;
    uint8_t algorithm = 0;
    uint32_t flags = 0;
    int publish = 0;
    int ksk = 0;
    int zsk = 0;
    ldns_rr* rr = NULL;

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
        !backup_read_int(fd, &zsk)) {

        ods_log_error("[%s] key in backup corrupted", key_str);
        if (locator) {
           free((void*)locator);
           locator = NULL;
        }
        return NULL;
    }

    if (publish &&
        ldns_rr_new_frm_fp(&rr, fd, NULL, NULL, NULL) != LDNS_STATUS_OK) {
        ods_log_error("[%s] key in backup is published, but no rr found",
            key_str);
        if (locator) {
           free((void*)locator);
           locator = NULL;
        }
        return NULL;
    }

    if (!backup_read_check_str(fd, ";;Keydone")) {
        ods_log_error("[%s] key in backup corrupted", key_str);
        if (locator) {
           free((void*)locator);
           locator = NULL;
        }
        if (rr) {
            ldns_rr_free(rr);
            rr = NULL;
        }
        return NULL;
    }

    /* key ok */
    key = (key_type*) allocator_alloc(allocator, sizeof(key_type));
    if (!key) {
        ods_log_error("[%s] unable to recover key: allocator failed",
            key_str);
        if (locator) {
           free((void*)locator);
           locator = NULL;
        }
        if (rr) {
            ldns_rr_free(rr);
            rr = NULL;
        }
        return NULL;
    }
    ods_log_assert(key);

    key->allocator = allocator;
    key->locator = allocator_strdup(allocator, locator);
    key->dnskey = rr;
    key->hsmkey = NULL;
    key->params = NULL;
    key->algorithm = algorithm;
    key->flags = flags;
    key->publish = publish;
    key->ksk = ksk;
    key->zsk = zsk;
    key->next = NULL;

    if (locator) {
       free((void*)locator);
       locator = NULL;
    }
    return key;
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
 * Backup key.
 *
 */
static void
key_backup(FILE* fd, key_type* key)
{
    if (!fd || !key) {
        return;
    }

    fprintf(fd, ";;Key: locator %s algorithm %u flags %u publish %i ksk %i "
        "zsk %i\n", key->locator, (unsigned) key->algorithm,
        (unsigned) key->flags, key->publish, key->ksk, key->zsk);
    if (key->dnskey) {
        ldns_rr_print(fd, key->dnskey);
    }
    fprintf(fd, ";;Keydone\n");
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
 * Create a new key list.
 *
 */
keylist_type*
keylist_create(allocator_type* allocator)
{
    keylist_type* kl;

    if (!allocator) {
        ods_log_error("[%s] create list failed: no allocator available",
            key_str);
        return NULL;
    }
    ods_log_assert(allocator);

    kl = (keylist_type*) allocator_alloc(allocator, sizeof(keylist_type));
    if (!kl) {
        ods_log_error("[%s] create list failed: allocator failed",
            key_str);
        return NULL;
    }
    ods_log_assert(kl);

    kl->allocator = allocator;
    kl->count = 0;
    kl->first_key = NULL;
    return kl;
}


/**
 * Push a key to the key list.
 *
 */
ods_status
keylist_push(keylist_type* kl, key_type* key)
{
    key_type* walk = NULL;

    if (!kl || !key || !key->locator) {
        ods_log_error("[%s] push failed: no list or no key", key_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(kl);
    ods_log_assert(key);
    ods_log_debug("[%s] add locator %s", key_str, key->locator);

    if (kl->count == 0) {
        kl->first_key = key;
    } else {
        walk = kl->first_key;
        while (walk->next) {
            walk = walk->next;
        }
        walk->next = key;
    }
    kl->count += 1;
    return ODS_STATUS_OK;
}


/**
 * Lookup a key in the key list by locator.
 *
 */
key_type*
keylist_lookup(keylist_type* list, const char* locator)
{
    key_type* search = NULL;
    size_t i = 0;

    if (!list || !locator) {
        return NULL;
    }

    search = list->first_key;
    for (i=0; i < list->count; i++) {
        if (search && search->locator) {
            if (ods_strcmp(search->locator, locator) == 0) {
                return search;
            }
            search = search->next;
        } else {
            break;
        }
    }
    return NULL;
}


/**
 * Lookup a key in the key list by dnskey.
 *
 */
key_type*
keylist_lookup_by_dnskey(keylist_type* list, ldns_rr* dnskey)
{
    key_type* search = NULL;
    size_t i = 0;

    if (!list || !dnskey) {
        return NULL;
    }

    search = list->first_key;
    for (i=0; i < list->count; i++) {
        if (search && search->dnskey) {
            if (ldns_rr_compare(search->dnskey, dnskey) == 0) {
                return search;
            }
            search = search->next;
        } else {
            break;
        }
    }
    return NULL;
}


/**
 * Print key list.
 *
 */
void
keylist_print(FILE* fd, keylist_type* kl)
{
    key_type* walk = NULL;

    if (fd && kl) {
        walk = kl->first_key;
        while (walk) {
            key_print(fd, walk);
            walk = walk->next;
        }
    }
    return;
}


/**
 * Backup key list.
 *
 */
void
keylist_backup(FILE* fd, keylist_type* kl)
{
    key_type* walk = NULL;

    if (fd) {
        if (kl) {
            walk = kl->first_key;
            while (walk) {
                key_backup(fd, walk);
                walk = walk->next;
            }
        }
        fprintf(fd, ";;\n");
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
    key_type* walk = NULL;

    if (kl) {
        walk = kl->first_key;
        while (walk) {
            key_log(walk, name);
            walk = walk->next;
        }
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
    allocator_type* allocator;

    if (!key) {
        return;
    }
    if (key->dnskey) {
        ldns_rr_free(key->dnskey);
        key->dnskey = NULL;
    }
    if (key->hsmkey) {
        hsm_key_free(key->hsmkey);
        key->hsmkey = NULL;
    }
    if (key->params) {
        hsm_sign_params_free(key->params);
        key->params = NULL;
    }
    allocator = key->allocator;
    allocator_deallocate(allocator, (void*) key->locator);
    allocator_deallocate(allocator, (void*) key);
    return;
}


/**
 * Clean up key list.
 *
 */
void
keylist_cleanup(keylist_type* kl)
{
    key_type* walk = NULL;
    key_type* next = NULL;
    allocator_type* allocator;

    if (!kl) {
        return;
    }
    walk = kl->first_key;
    while (walk) {
        next = walk->next;
        key_delfunc(walk);
        walk = next;
    }
    allocator = kl->allocator;
    allocator_deallocate(allocator, (void*) kl);
    return;
}
