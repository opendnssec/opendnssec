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

#include "v2/se_key.h"
#include "v2/se_malloc.h"


/**
 * Create a new key.
 *
 */
key_type*
key_create(const char* locator, uint32_t algorithm, uint32_t flags,
    int publish, int ksk, int zsk)
{
    key_type* key = (key_type*) se_malloc(sizeof(key_type));
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
        key_cleanup(key->next);
        se_free((void*)key->locator);
        if (key->dnskey) {
            ldns_rr_free(key->dnskey);
        }
        se_free((void*)key);
    }
}


/**
 * Print key.
 *
 */
void
key_print(FILE* out, key_type* key)
{
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
}


/**
 * Create a new key list.
 *
 */
keylist_type*
keylist_create(void)
{
    keylist_type* kl = (keylist_type*) se_malloc(sizeof(keylist_type));
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
    const char* s1 = a->locator;
    const char* s2 = b->locator;

    if (!s1 && !s2) {
        return 0;
    } else if (!s1) {
        return -1;
    } else if (!s2) {
        return -1;
    } else if (strlen(s1) != strlen(s2)) {
        if (strncmp(s1, s2, strlen(s1)) == 0) {
            return strlen(s1) - strlen(s2);
        }
    }
    return strncmp(s1, s2, strlen(s1));
}


/**
 * Compare two key lists.
 *
 */
int
keylist_compare(keylist_type* a, keylist_type* b)
{
    key_type* ka, *kb;
    int ret, i;

    if (a->count != b->count) {
        return a->count - b->count;
    }

    ka = a->first_key;
    kb = b->first_key;
    for (i=0; i < a->count; i++) {
        if (!ka && !kb) {
            return 0;
        }
        if (!ka) {
            return -1;
        }
        if (!kb) {
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
        key_cleanup(kl->first_key);
        se_free((void*)kl);
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

    if (kl) {
        walk = kl->first_key;
        while (walk) {
            key_print(out, walk);
            walk = walk->next;
        }
    }
}
