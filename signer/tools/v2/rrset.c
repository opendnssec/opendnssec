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
 * RRset.
 *
 */

#include "config.h"
#include "v2/rrset.h"
#include "v2/hsm.h"
#include "v2/se_malloc.h"


/**
 * Create new RRset.
 *
 */
rrset_type*
rrset_create(ldns_rr* rr)
{
    rrset_type* rrset = (rrset_type*) se_calloc(1, sizeof(rrset_type));
    rrset->rr_type = ldns_rr_get_type(rr);
    rrset->rrs = ldns_dnssec_rrs_new();
    rrset->rrs->rr = rr;
    rrset->rrsigs = NULL;
    rrset->next = NULL;
    return rrset;
}


/**
 * Clean up RRset.
 *
 */
void
rrset_cleanup(rrset_type* rrset)
{
    if (rrset) {
        if (rrset->next) {
            rrset_cleanup(rrset->next);
        }
        if (rrset->rrs) {
            ldns_dnssec_rrs_deep_free(rrset->rrs);
        }
        if (rrset->rrsigs) {
            ldns_dnssec_rrs_deep_free(rrset->rrsigs);
        }
        se_free((void*) rrset);
    }
    return;
}


/** Look if the RR is already present in the RRset */
static int
rrset_covers_rr(ldns_dnssec_rrs* rrs, ldns_rr* rr)
{
    int cmp;
    if (!rrs || !rr) {
        return 0;
    }

    while (rrs) {
        cmp = ldns_rr_compare(rrs->rr, rr);
        if (cmp == 0) {
            return 1;
        }
        rrs = rrs->next;
    }
    return 0;
}


/**
 * Look if the RR is already present in the RRset.
 *
 */
int
rrset_covers_rrtype(rrset_type* rrset, ldns_rr_type rr_type)
{
    while (rrset) {
        if (rrset->rr_type == rr_type &&
            rrset->rrs && rrset->rrs->rr) {
            return 1;
        }
        rrset = rrset->next;
    }
    return 0;
}


/**
 * Add RR to RRset.
 *
 */
int
rrset_add_rr(rrset_type* rrset, ldns_rr* rr)
{
    int is_rrsig = 0;
    rrset_type* walk_rrset = NULL;
    rrset_type* new_rrset = NULL;
    ldns_dnssec_rrs* new_rrs = NULL;
    ldns_rr_type type = 0;
    ldns_status status = LDNS_STATUS_OK;
    char* rr_str = NULL;

    type = ldns_rr_get_type(rr); /* get rrtype */
    if (type == LDNS_RR_TYPE_RRSIG) {
        /* if signature, type = type covered */
        type = ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(rr));
        is_rrsig = 1;
    }

    walk_rrset = rrset;
    while (walk_rrset && type > walk_rrset->rr_type) {
        if (walk_rrset->next) {
            /* this type of rr belongs to one of the next RRsets */
            walk_rrset = walk_rrset->next;
        } else if (!is_rrsig) {
            /* if there is no next RRset, create it now. */
            walk_rrset->next = rrset_create(rr);
            return 0;
        } else {
            fprintf(stderr, "cannot add RRSIG rr if the corresponding RRset (%i) is missing\n", type);
            ldns_rr_free(rr);
            return 1;
        }
    }

    if (type == walk_rrset->rr_type) {
        /* found the corresponding rrset */
        if (is_rrsig) {
            /* RRSIG rr */
            if (walk_rrset->rrsigs && rrset_covers_rr(walk_rrset->rrsigs, rr)) {
                /* we have this RRSIG already */
                rr_str = ldns_rr2str(rr);
                rr_str[strlen(rr_str)-1] = '\0';
                se_free((void*)rr_str);
                ldns_rr_free(rr);
                return 0;
            } else {
                /* new RRSIG, add it */
                if (!walk_rrset->rrsigs) {
                    walk_rrset->rrsigs = ldns_dnssec_rrs_new();
                    walk_rrset->rrsigs->rr = rr;
                    return 0;
                } else {
                    status = ldns_dnssec_rrs_add_rr(walk_rrset->rrsigs, rr);
                    if (status != LDNS_STATUS_OK) {
                        fprintf(stderr, "error adding RR to RRset (%i): %s\n", type,
                             ldns_get_errorstr_by_id(status));
                        return 1;
                    }
                    return 0;
                }
            }
        } else {
           /* other RR */
            if (rrset_covers_rr(walk_rrset->rrs, rr)) {
                /* we have this one already */
                rr_str = ldns_rr2str(rr);
                rr_str[strlen(rr_str)-1] = '\0';
                se_free((void*)rr_str);
                ldns_rr_free(rr);
                return 0;
            } else {
                if (walk_rrset->rr_type == LDNS_RR_TYPE_NSEC3PARAMS) {
                    if (walk_rrset->rrs) {
                        ldns_dnssec_rrs_deep_free(walk_rrset->rrs);
                    }
                    if (walk_rrset->rrsigs) {
                        ldns_dnssec_rrs_deep_free(walk_rrset->rrsigs);
                    }
                }

                /* new RR, add it */
                if (!walk_rrset->rrs) {
                    walk_rrset->rrs = ldns_dnssec_rrs_new();
                }
                status = ldns_dnssec_rrs_add_rr(walk_rrset->rrs, rr);
                if (status != LDNS_STATUS_OK) {
                    fprintf(stderr, "error adding RR to RRset (%i): %s\n", type,
                        ldns_get_errorstr_by_id(status));
                    return 1;
                }
                return 0;
            }
        }
    }

    /* no such RRset, create new */
    if (type < walk_rrset->rr_type) {
        if (is_rrsig) {
            fprintf(stderr, "cannot add RRSIG rr if the corresponding RRset (%i) is missing\n", type);
            ldns_rr_free(rr);
            return 1;
        }
        new_rrset = rrset_create(rr);
        new_rrs = new_rrset->rrs;
        /* copy the current RRsets values to the new one */
        new_rrset->rr_type = walk_rrset->rr_type;
        new_rrset->rrs = walk_rrset->rrs;
        new_rrset->rrsigs = walk_rrset->rrsigs;
        new_rrset->next = walk_rrset->next;

        /* override the current RRsets with the RR values */
        walk_rrset->rr_type = type;
        walk_rrset->rrs = new_rrs;
        walk_rrset->rrsigs = NULL;
        walk_rrset->next = new_rrset;
        return 0;
    }
    return 1;
}


/**
 * Print RRset.
 *
 */
void
rrset_print(FILE* fd, rrset_type* rrset, const char* comments, int follow,
    int glue_only, int skip_soa)
{
    rrset_type* walk_rrset = rrset;

    while (walk_rrset) {
        if (!walk_rrset->rrs || !walk_rrset->rrs->rr) {
            walk_rrset = walk_rrset->next;
            continue;
        }

        if (comments) {
            fprintf(fd, "; %s\n", comments);
            comments = NULL;
        }

        if (walk_rrset->rr_type == LDNS_RR_TYPE_SOA && skip_soa) {
            walk_rrset = walk_rrset->next;
            continue;
        }

        if ((walk_rrset->rr_type != LDNS_RR_TYPE_A &&
             walk_rrset->rr_type != LDNS_RR_TYPE_AAAA) && glue_only) {
            walk_rrset = walk_rrset->next;
            continue;
        }

        ldns_dnssec_rrs_print(fd, walk_rrset->rrs);
        if (walk_rrset->rrsigs) {
            ldns_dnssec_rrs_print(fd, walk_rrset->rrsigs);
        }

        if (!follow) {
            break;
        }

        walk_rrset = walk_rrset->next;
    }
}
