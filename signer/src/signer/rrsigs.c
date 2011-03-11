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
#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/util.h"
#include "signer/rrsigs.h"
#include "signer/keys.h"

#include <ldns/ldns.h>

static const char* rrsigs_str = "rrsig";


/**
 * Create new signature set.
 *
 */
rrsigs_type*
rrsigs_create(void)
{
    allocator_type* allocator = NULL;
    rrsigs_type* rrsigs = NULL;

    allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] unable to create RRSIGs: create allocator "
            "failed", rrsigs_str);
        return NULL;
    }
    ods_log_assert(allocator);

    rrsigs = (rrsigs_type*) allocator_alloc(allocator, sizeof(rrsigs_type));
    if (!rrsigs) {
        ods_log_error("[%s] unable to create RRSIGs: allocator failed",
            rrsigs_str);
        allocator_cleanup(allocator);
        return NULL;
    }
    ods_log_assert(rrsigs);

    rrsigs->allocator = allocator;
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
ods_status
rrsigs_add_sig(rrsigs_type* rrsigs, ldns_rr* rr, const char* l, uint32_t f)
{
    int cmp;
    rrsigs_type* new_rrsigs = NULL;
    ldns_status status = LDNS_STATUS_OK;

    if (!rrsigs) {
        ods_log_error("[%s] unable to add RRSIG: no storage", rrsigs_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rrsigs);

    if (!rr) {
        ods_log_error("[%s] unable to add RRSIG: no RRSIG RR", rrsigs_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rr);

    if (!rrsigs->rr) {
        rrsigs->rr = rr;
        if (l) {
            rrsigs->key_locator = allocator_strdup(rrsigs->allocator, l);
        }
        rrsigs->key_flags = f;
        return ODS_STATUS_OK;
    }

    status = util_dnssec_rrs_compare(rrsigs->rr, rr, &cmp);
    if (status != LDNS_STATUS_OK) {
        return ODS_STATUS_ERR;
    }
    if (cmp < 0) {
        if (rrsigs->next) {
            return rrsigs_add_sig(rrsigs->next, rr, l, f);
        } else {
            new_rrsigs = rrsigs_create();
            new_rrsigs->rr = rr;
            if (l) {
                new_rrsigs->key_locator = allocator_strdup(
                    rrsigs->allocator, l);
            }
            new_rrsigs->key_flags = f;
            rrsigs->next = new_rrsigs;
            return ODS_STATUS_OK;
        }
    } else if (cmp > 0) {
        /* put the current old rr in the new next, put the new
           rr in the current container */
        new_rrsigs = rrsigs_create();
        new_rrsigs->rr = rrsigs->rr;
        new_rrsigs->key_locator = rrsigs->key_locator;
        new_rrsigs->key_flags = rrsigs->key_flags;
        new_rrsigs->next = rrsigs->next;

        rrsigs->rr = rr;
        rrsigs->next = new_rrsigs;
        if (l) {
            rrsigs->key_locator = allocator_strdup(rrsigs->allocator, l);
        }
        rrsigs->key_flags = f;
        return ODS_STATUS_OK;
    } else {
        /* should we error on equal? or free memory of rr */
        ods_log_warning("[%s] adding duplicate RRSIG?", rrsigs_str);
        return ODS_STATUS_UNCHANGED;
    }
    /* not reached */
    return ODS_STATUS_ERR;
}


/**
 * Clean up signature set.
 *
 */
void
rrsigs_cleanup(rrsigs_type* rrsigs)
{
    allocator_type* allocator;
    if (!rrsigs) {
        return;
    }
    if (rrsigs->next) {
        rrsigs_cleanup(rrsigs->next);
        rrsigs->next = NULL;
    }
    if (rrsigs->rr) {
        ldns_rr_free(rrsigs->rr);
        rrsigs->rr = NULL;
    }
    allocator = rrsigs->allocator;
    allocator_deallocate(allocator, (void*) rrsigs->key_locator);
    allocator_deallocate(allocator, (void*) rrsigs);
    allocator_cleanup(allocator);
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

    if (!fd) {
        ods_log_error("[%s] unable to print: no fd", rrsigs_str);
        return;
    }
    ods_log_assert(fd);

    print = rrsigs;
    while (print) {
        if (print_key) {
            fprintf(fd, ";;RRSIG %s %u\n",
                rrsigs->key_locator?rrsigs->key_locator:"(null)",
                rrsigs->key_flags);
        }
        if (print->rr) {
            ldns_rr_print(fd, print->rr);
        }
        print = print->next;
    }
    return;
}
