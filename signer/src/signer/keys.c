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
 * Recover a key from backup.
 *
 */
key_type*
key_recover_from_backup(FILE* fd)
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

    if (!backup_read_str(fd, &locator) ||
        !backup_read_uint8_t(fd, &algorithm) ||
        !backup_read_uint32_t(fd, &flags) ||
        !backup_read_int(fd, &publish) ||
        !backup_read_int(fd, &ksk) ||
        !backup_read_int(fd, &zsk) ||
        ldns_rr_new_frm_fp(&rr, fd, NULL, NULL, NULL) != LDNS_STATUS_OK ||
        !backup_read_check_str(fd, ";END"))
    {
        ods_log_error("[%s] key part in backup file is corrupted", key_str);
        if (locator) {
            free((void*)locator);
        }
        if (rr) {
            ldns_rr_free(rr);
            rr = NULL;
        }
        return NULL;
    }

    key = (key_type*) malloc(sizeof(key_type));
    key->locator = locator;
    key->dnskey = rr;
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
 * Print key.
 *
 */
static void
key_print(FILE* out, key_type* key)
{
    if (key && out) {
        fprintf(out, "\t\t\t<Key>\n");
        fprintf(out, "\t\t\t\t<Flags>%u</Flags>\n", key->flags);
        fprintf(out, "\t\t\t\t<Algorithm>%u</Algorithm>\n", key->algorithm);
        if (key->locator) {
            fprintf(out, "\t\t\t\t<Locator>%s</Locator>\n", key->locator);
        }
        if (key->ksk) {
            fprintf(out, "\t\t\t\t<KSK />\n");
        }
        if (key->zsk) {
            fprintf(out, "\t\t\t\t<ZSK />\n");
        }
        if (key->publish) {
            fprintf(out, "\t\t\t\t<Publish />\n");
        }
        fprintf(out, "\t\t\t</Key>\n");
        fprintf(out, "\n");
    }
    return;
}


/**
 * Log key.
 *
 */
static void
key_log(key_type* key, const char* name)
{
    if (key) {
        ods_log_debug("[%s] zone %s key: LOCATOR[%s] FLAGS[%u] ALGORITHM[%u] "
            "KSK[%i] ZSK[%i] PUBLISH[%i]", key_str, name?name:"(null)",
            key->locator, key->flags, key->algorithm, key->ksk, key->zsk,
            key->publish);
    }
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
 * Compare two key references.
 *
 */
int
key_compare(key_type* a, key_type* b)
{
    if (!a && !b) {
        return 0;
    }
    if (!a || !b) {
        return -1;
    }
    ods_log_assert(a);
    ods_log_assert(b);
    return ods_strcmp(a->locator, b->locator);
}


/**
 * Delete a key from the keylist.
 *
 */
int
keylist_delete(keylist_type* kl, key_type* key)
{
    key_type* walk = NULL, *prev = NULL;

    ods_log_assert(kl);
    ods_log_assert(key);
    ods_log_debug("[%s] delete key locator %s", key_str,
        key->locator?key->locator:"(null)");

    walk = kl->first_key;
    while (walk) {
        if (key_compare(walk, key) == 0) {
            key->next = walk->next;
            if (!prev) {
                kl->first_key = key;
            } else {
                prev->next = key;
            }
            kl->count -= 1;
            return 0;
        }
        prev = walk;
        walk = walk->next;
    }

    ods_log_error("[%s] key locator %s not found in list",
        key_str, key->locator?key->locator:"(null)");
    return 1;
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
        if (search) {
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
 * Compare two key lists.
 *
 */
int
keylist_compare(keylist_type* a, keylist_type* b)
{
    key_type* ka, *kb;
    int ret = 0;
    size_t i = 0;

    if (!a && !b) {
        return 0;
    }
    if (!a || !b) {
        return -1;
    }
    ods_log_assert(a);
    ods_log_assert(b);

    if (a->count != b->count) {
        return a->count - b->count;
    }

    ka = a->first_key;
    kb = b->first_key;
    for (i=0; i < a->count; i++) {
        if (!ka && !kb) {
            ods_log_warning("[%s] neither key a[%i] or key b[%i] exist",
                key_str, i, i);
            return 0;
        }
        if (!ka) {
            ods_log_warning("[%s] key a[%i] does not exist", key_str, i);
            return -1;
        }
        if (!kb) {
            ods_log_warning("key b[%i] does not exist", i);
            return -1;
        }
        ret = key_compare(ka, kb);
        if (ret == 0) {
            ret = ka->algorithm - kb->algorithm;
            if (ret == 0) {
                 ret = ka->flags - kb->flags;
                 if (ret == 0) {
                     ret = ka->publish - kb->publish;
                     if (ret == 0) {
                         ret = ka->ksk - kb->ksk;
                         if (ret == 0) {
                             ret = ka->zsk - kb->zsk;
                         }
                     }
                 }
            }
        }
        if (ret != 0) {
            return ret;
        }
        ka = ka->next;
        kb = kb->next;
    }
    return 0;
}


/**
 * Print key list.
 *
 */
void
keylist_print(FILE* out, keylist_type* kl)
{
    key_type* walk = NULL;

    if (out && kl) {
        walk = kl->first_key;
        while (walk) {
            key_print(out, walk);
            walk = walk->next;
        }
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

    if (kl) {
        walk = kl->first_key;
        while (walk) {
            key_delfunc(walk);
            walk = walk->next;
        }
    }
    return;
}
