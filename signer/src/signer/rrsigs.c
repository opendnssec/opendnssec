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
 * Signatures.
 *
 */

#include "config.h"
#include "signer/rrsigs.h"
#include "signer/se_key.h"
#include "util/log.h"
#include "util/se_malloc.h"
#include "util/util.h"

#include <ldns/ldns.h>


/**
 * Create new signature set.
 *
 */
rrsigs_type*
rrsigs_create(void)
{
    rrsigs_type* rrsigs = (rrsigs_type*) se_calloc(1, sizeof(rrsigs_type));
    rrsigs->rr = NULL;
    rrsigs->key_locator = NULL;
    rrsigs->key_flags = 0;
    rrsigs->next = NULL;
    return rrsigs;
}


/**
 * Add RRSIG to signature set.
 *
 */
int
rrsigs_add_sig(rrsigs_type* rrsigs, ldns_rr* rr, const char* locator,
    uint32_t flags)
{
    int cmp;
    uint32_t default_ttl = 0;
    uint32_t rr_ttl = 0;
    rrsigs_type* new_rrsigs = NULL;
    ldns_status status = LDNS_STATUS_OK;

    se_log_assert(rrsigs);
    se_log_assert(rr);

    if (!rrsigs->rr) {
        rrsigs->rr = rr;
        if (locator) {
            rrsigs->key_locator = se_strdup(locator);
        }
        rrsigs->key_flags = flags;
        return 0;
    }

    status = util_dnssec_rrs_compare(rrsigs->rr, rr, &cmp);
    if (status != LDNS_STATUS_OK) {
        return 1;
    }

    if (cmp < 0) {
        if (rrsigs->next) {
            return rrsigs_add_sig(rrsigs->next, rr, locator, flags);
        } else {
            new_rrsigs = rrsigs_create();
            new_rrsigs->rr = rr;
            if (locator) {
                new_rrsigs->key_locator = se_strdup(locator);
            }
            new_rrsigs->key_flags = flags;

            rrsigs->next = new_rrsigs;

            default_ttl = ldns_rr_ttl(rrsigs->rr);
            if (rr_ttl < default_ttl) {
                ldns_rr_set_ttl(rrsigs->rr, rr_ttl);
            } else {
                ldns_rr_set_ttl(new_rrsigs->rr, default_ttl);
            }
            return 0;
        }
    } else if (cmp > 0) {
        /* put the current old rr in the new next, put the new
           rr in the current container */
        new_rrsigs = rrsigs_create();
        new_rrsigs->rr = rrsigs->rr;
        new_rrsigs->next = rrsigs->next;

        rrsigs->rr = rr;
        rrsigs->next = new_rrsigs;
        if (locator) {
            rrsigs->key_locator = se_strdup(locator);
        }
        rrsigs->key_flags = flags;

        default_ttl = ldns_rr_ttl(new_rrsigs->rr);
        if (rr_ttl < default_ttl) {
            ldns_rr_set_ttl(new_rrsigs->rr, rr_ttl);
        } else {
            ldns_rr_set_ttl(rrsigs->rr, default_ttl);
        }
        return 0;
    } else {
        /* should we error on equal? or free memory of rr */
        se_log_warning("adding duplicate RRSIG?");
        return 2;
    }
    return 0;
}


/*
 * Clean up signature set.
 *
 */
void
rrsigs_cleanup(rrsigs_type* rrsigs)
{
    if (rrsigs) {
        if (rrsigs->next) {
            rrsigs_cleanup(rrsigs->next);
            rrsigs->next = NULL;
        }
        if (rrsigs->rr) {
            ldns_rr_free(rrsigs->rr);
            rrsigs->rr = NULL;
        }
        if (rrsigs->key_locator) {
            se_free((void*)rrsigs->key_locator);
            rrsigs->rr = NULL;
        }
        se_free((void*) rrsigs);
    } else {
        se_log_warning("cleanup empty rrsigs");
    }
    return;
}


/**
 * Print signature set.
 *
 */
void
rrsigs_print(FILE* fd, rrsigs_type* rrsigs, int print_key)
{
    rrsigs_type* print = NULL;

    se_log_assert(fd);

    print = rrsigs;
    while (print) {
        if (print_key) {
            fprintf(fd, ";RRSIG %s %u\n",
                rrsigs->key_locator?rrsigs->key_locator:"(null)",
                rrsigs->key_flags);
        }
        ldns_rr_print(fd, print->rr);

        print = print->next;
    }
    return;
}
