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

#include "signer/se_key.h"
#include "util/file.h"
#include "util/log.h"
#include "util/se_malloc.h"


/**
 * Create a new key.
 *
 */
key_type*
key_create(const char* locator, uint32_t algorithm, uint32_t flags,
    int publish, int ksk, int zsk)
{
    key_type* key = (key_type*) se_malloc(sizeof(key_type));

    se_log_assert(locator);
    se_log_assert(algorithm);
    se_log_assert(flags);

    key->locator = se_strdup(locator);
    key->dnskey = NULL;
    key->algorithm = algorithm;
    key->flags = flags;
    key->publish = publish;
    key->ksk = ksk;
    key->zsk = zsk;
    key->next = NULL;
    return key;
}


/**
 * Clean up key.
 *
 */
void
key_cleanup(key_type* key)
{
    if (key) {
        if (key->next) {
            key_cleanup(key->next);
            key->next = NULL;
        }
        if (key->locator) {
            se_free((void*)key->locator);
            key->locator = NULL;
        }
        if (key->dnskey) {
            ldns_rr_free(key->dnskey);
            key->dnskey = NULL;
        }
        se_free((void*)key);
    } else {
        se_log_warning("cleanup empty key");
    }
}


/**
 * Print key.
 *
 */
void
key_print(FILE* out, key_type* key)
{
    se_log_assert(out);
    if (key) {
        fprintf(out, "\t\t\t<Key>\n");
        fprintf(out, "\t\t\t\t<Flags>%u</Flags>\n", key->flags);
        fprintf(out, "\t\t\t\t<Algorithm>%u</Algorithm>\n", key->algorithm);
        fprintf(out, "\t\t\t\t<Locator>%s</Locator>\n", key->locator);
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
 * Create a new key list.
 *
 */
keylist_type*
keylist_create(void)
{
    keylist_type* kl = (keylist_type*) se_malloc(sizeof(keylist_type));

    se_log_debug("create key list");
    kl->count = 0;
    kl->first_key = NULL;
    return kl;
}


/**
 * Add a key to the keylist.
 *
 */
int
keylist_add(keylist_type* kl, key_type* key)
{
    key_type* walk = NULL;

    se_log_assert(kl);
    se_log_assert(key);
    se_log_debug("add key locator %s", key->locator);

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
    return 0;
}


/**
 * Compare two key references.
 *
 */
int
key_compare(key_type* a, key_type* b)
{
    se_log_assert(a);
    se_log_assert(b);
    return se_strcmp(a->locator, b->locator);
}


/**
 * Delete a key from the keylist.
 *
 */
int
keylist_delete(keylist_type* kl, key_type* key)
{
    key_type* walk = NULL, *prev = NULL;

    se_log_assert(kl);
    se_log_assert(key);
    se_log_debug("delete key locator %s", key->locator);

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

    se_log_error("key locator %s not found in list", key->locator);
    return 1;
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

    se_log_assert(a);
    se_log_assert(b);

    if (a->count != b->count) {
        return a->count - b->count;
    }

    ka = a->first_key;
    kb = b->first_key;
    for (i=0; i < a->count; i++) {
        if (!ka && !kb) {
            se_log_warning("neither key a[%i] or key b[%i] exist", i, i);
            return 0;
        }
        if (!ka) {
            se_log_warning("key a[%i] does not exist", i);
            return -1;
        }
        if (!kb) {
            se_log_warning("key b[%i] does not exist", i);
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
 * Clean up key list.
 *
 */
void
keylist_cleanup(keylist_type* kl)
{
    if (kl) {
        se_log_debug("clean up key list");
        key_cleanup(kl->first_key);
        se_free((void*)kl);
    } else {
        se_log_warning("cleanup empty key list");
    }
}


/**
 * Print key list.
 *
 */
void
keylist_print(FILE* out, keylist_type* kl)
{
    key_type* walk = NULL;

    se_log_assert(out);
    if (kl) {
        walk = kl->first_key;
        while (walk) {
            key_print(out, walk);
            walk = walk->next;
        }
    }
    return;
}
