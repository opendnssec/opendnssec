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
 * IXFR Journal.
 *
 */

#include "config.h"
#include "util.h"
#include "signer/ixfr.h"
#include "signer/rrset.h"
#include "signer/zone.h"

static const char* ixfr_str = "journal";


/**
 * Create a part of ixfr journal.
 *
 */
static part_type*
part_create()
{
    part_type* part = NULL;

    CHECKALLOC(part = (part_type*) malloc(sizeof(part_type)));
    part->soaplus = NULL;
    part->soamin = NULL;
    part->plus = ldns_rr_list_new();
    if (!part->plus) {
        ods_log_error("[%s] unable to create ixfr part: "
            "ldns_rr_list_new() failed", ixfr_str);
        free(part);
        return NULL;
    }
    part->min = ldns_rr_list_new();
    if (!part->min) {
        ods_log_error("[%s] unable to create ixfr part: "
            "ldns_rr_list_new() failed", ixfr_str);
        ldns_rr_list_free(part->plus);
        free(part);
        return NULL;
    }
    return part;
}


/**
 * Clean up a part of ixfr journal and free it.
 *
 */
static void
part_free(part_type* part)
{
    if (!part) return;
    ldns_rr_list_deep_free(part->min);
    ldns_rr_list_deep_free(part->plus);
    free(part);
}


/**
 * Create a new ixfr journal.
 *
 */
ixfr_type*
ixfr_create()
{
    size_t i = 0;
    ixfr_type* xfr;

    CHECKALLOC(xfr = (ixfr_type*) calloc(1, sizeof(ixfr_type)));
    pthread_mutex_init(&xfr->ixfr_lock, NULL);
    return xfr;
}


/**
 * Add +RR to ixfr journal.
 *
 */
void
ixfr_add_rr(ixfr_type* ixfr, ldns_rr* rr)
{
    ldns_rr* rr_copy = ldns_rr_clone(rr);

    ods_log_assert(ixfr)
    ods_log_assert(rr);
    ods_log_assert(ixfr->part[0]);
    ods_log_assert(ixfr->part[0]->plus);

    if (!ldns_rr_list_push_rr(ixfr->part[0]->plus, rr_copy)) {
        ldns_rr_free(rr_copy);
        ods_fatal_exit("[%s] fatal unable to +RR: ldns_rr_list_push_rr() failed",
            ixfr_str);
    }
    if (ldns_rr_get_type(rr_copy) == LDNS_RR_TYPE_SOA) {
        ixfr->part[0]->soaplus = rr_copy;
    }
}


/**
 * Add -RR to ixfr journal.
 *
 */
void
ixfr_del_rr(ixfr_type* ixfr, ldns_rr* rr)
{
    ldns_rr* rr_copy = ldns_rr_clone(rr);

    ods_log_assert(ixfr)
    ods_log_assert(rr);
    ods_log_assert(ixfr->part[0]);
    ods_log_assert(ixfr->part[0]->min);

    if (!ldns_rr_list_push_rr(ixfr->part[0]->min, rr_copy)) {
        ldns_rr_free(rr_copy);
        ods_fatal_exit("[%s] fatal unable to -RR: ldns_rr_list_push_rr() failed",
            ixfr_str);
    }
    if (ldns_rr_get_type(rr_copy) == LDNS_RR_TYPE_SOA) {
        ixfr->part[0]->soamin = rr_copy;
    }
}


/**
 * Print all RRs in list, except SOA RRs.
 *
 */
static int
part_rr_list_print_nonsoa(FILE* fd, ldns_rr_list* list)
{
    size_t i = 0;
    int error = 0;
    if (!list || !fd) {
        return 1;
    }
    for (i = 0; i < ldns_rr_list_rr_count(list); i++) {
        if (ldns_rr_get_type(ldns_rr_list_rr(list, i)) != LDNS_RR_TYPE_SOA) {
            if (util_rr_print(fd, ldns_rr_list_rr(list, i)) != ODS_STATUS_OK) {
                error = 1;
            }
        }
    }
    return error;
}


/**
 * Print part of the ixfr journal.
 *
 */
static int
part_print(FILE* fd, ixfr_type* ixfr, size_t i)
{
    part_type* part = NULL;
    int error = 0;

    ods_log_assert(ixfr);
    ods_log_assert(fd);

    part = ixfr->part[i];
    if (!part || !part->soamin || !part->soaplus) {
        return 0; /* due to code buggyness this is not considered an
            error condition*/
    }
    ods_log_assert(part->min);
    ods_log_assert(part->plus);
    ods_log_assert(part->soamin);
    ods_log_assert(part->soaplus);

    if (util_rr_print(fd, part->soamin) != ODS_STATUS_OK) {
        return 1;
    } else if (part_rr_list_print_nonsoa(fd, part->min)) {
        return 1;
    } else if (util_rr_print(fd, part->soaplus) != ODS_STATUS_OK) {
        return 1;
    } else if (part_rr_list_print_nonsoa(fd, part->plus)) {
        return 1;
    }
    return 0;
}


/**
 * Print the ixfr journal.
 *
 */
int
ixfr_print(FILE* fd, ixfr_type* ixfr)
{
    int i = 0, error = 0;

    ods_log_assert(fd);
    ods_log_assert(ixfr);

    ods_log_debug("[%s] print ixfr", ixfr_str);
    for (i = IXFR_MAX_PARTS - 1; i >= 0; i--) {
        ods_log_deeebug("[%s] print ixfr part #%d", ixfr_str, i);
        if (part_print(fd, ixfr, i)) {
            return 1;
        }
    }
    return 0;
}


/**
 * Purge the ixfr journal.
 *
 */
void
ixfr_purge(ixfr_type* ixfr, char const *zonename)
{
    int i = 0;

    ods_log_assert(ixfr);
    ods_log_assert(zonename);

    if (ixfr->part[0] &&
        (!ixfr->part[0]->soamin || !ixfr->part[0]->soaplus))
    {
        /* Somehow the signer does a double purge without having used
         * this part. There is no need to create a new one. In fact,
         * we should not. It would cause an assertion later on when
         * printing to file */
        return;
    }

    ods_log_debug("[%s] purge ixfr for zone %s", ixfr_str, zonename);
    for (i = IXFR_MAX_PARTS - 1; i >= 0; i--) {
        if (i == (IXFR_MAX_PARTS - 1)) {
            part_free(ixfr->part[i]);
            ixfr->part[i] = NULL;
        } else {
            ixfr->part[i+1] = ixfr->part[i];
            ixfr->part[i] = NULL;
        }
    }
    ixfr->part[0] = part_create();
}


/**
 * Cleanup the ixfr journal.
 *
 */
void
ixfr_cleanup(ixfr_type* ixfr)
{
    int i = 0;
    if (!ixfr) {
        return;
    }
    for (i = IXFR_MAX_PARTS - 1; i >= 0; i--) {
        part_free(ixfr->part[i]);
    }
    pthread_mutex_destroy(&ixfr->ixfr_lock);
    free(ixfr);
}
