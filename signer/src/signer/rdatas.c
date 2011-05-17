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
 * Resource Records RDATA.
 *
 */

#include "config.h"
#include "shared/log.h"
#include "shared/status.h"
#include "signer/rdatas.h"

#include <ldns/ldns.h>

static const char* rr_str = "rr";


/**
 * Push RDATA
 *
 */
static ods_status
ods_rr_push_rdf(ods_rr* rr, const ldns_rdf* f)
{
    size_t rd_count;
    ldns_rdf **rdata_fields;

    if (!rr || !f) {
        return ODS_STATUS_ASSERT_ERR;
    }
    rd_count = rr->rd_count;
    rdata_fields = realloc(rr->rdata_fields,
        sizeof(ldns_rdf*) * (rd_count + 1));
    if (!rdata_fields) {
        return ODS_STATUS_MALLOC_ERR;
    }
    rr->rdata_fields = rdata_fields;
    rr->rdata_fields[rd_count] = (ldns_rdf*)f;
    rr->rd_count = rd_count + 1;
    return ODS_STATUS_OK;
}


/**
 * Create new RR.
 *
 */
ods_rr*
ods_rr_new(ldns_rr* ldnsrr)
{
    ods_rr* odsrr = NULL;
    ods_status status = ODS_STATUS_OK;
    size_t i;

    if (!ldnsrr) {
        return NULL;
    }
    odsrr = malloc(sizeof(ods_rr));
    if (!odsrr) {
        return NULL;
    }

    odsrr->rd_count = 0;
    odsrr->rdata_fields = NULL;
    for (i = 0; i < ldns_rr_rd_count(ldnsrr); i++) {
        if (ldns_rr_rdf(ldnsrr,i)) {
            status = ods_rr_push_rdf(odsrr,
                ldns_rdf_clone(ldns_rr_rdf(ldnsrr, i)));
            if (status != ODS_STATUS_OK) {
                ods_rr_free(odsrr);
                return NULL;
            }
        }
    }
    ods_log_assert(odsrr->rd_count == ldnsrr->_rd_count);
    return odsrr;
}


/**
 * Get a RDATA element.
 *
 */
ldns_rdf*
ods_rr_rdf(ods_rr* rr, size_t pos)
{
    if (!rr) {
        return NULL;
    }
    if (pos < rr->rd_count) {
        return rr->rdata_fields[pos];
    }
    return NULL;
}


/**
 * Set a RDATA element.
 *
 */
ldns_rdf *
ods_rr_set_rdf(ods_rr *rr, const ldns_rdf* rdf, size_t pos)
{
    ldns_rdf *pop;

    if (!rr || !rdf) {
        return NULL;
    }
    if (pos < rr->rd_count) {
        /* dicard the old one */
        pop = rr->rdata_fields[pos];
        rr->rdata_fields[pos] = (ldns_rdf*) rdf;
        return pop;
    }
    return NULL;
}

/**
 * Clone RR.
 *
 */
ods_rr*
ods_rr_clone(const ods_rr* rr)
{
    ods_rr* odsrr = NULL;
    ldns_rdf* rdf = NULL;
    ldns_rdf* clone = NULL;
    ods_status status = ODS_STATUS_OK;
    size_t i;

    if (!rr) {
        return NULL;
    }
    odsrr = malloc(sizeof(ods_rr));
    if (!odsrr) {
        return NULL;
    }

    odsrr->rd_count = 0;
    odsrr->rdata_fields = NULL;
    for (i = 0; i < rr->rd_count; i++) {
        rdf = ods_rr_rdf((ods_rr*) rr, i);
        if (!rdf) {
            ods_rr_free(odsrr);
            return NULL;
        }
        clone = ldns_rdf_clone(rdf);
        if (!clone) {
            ods_rr_free(odsrr);
            return NULL;
        }
        status = ods_rr_push_rdf(odsrr, clone);
        if (status != ODS_STATUS_OK) {
            ods_rr_free(odsrr);
            return NULL;
        }
    }
    ods_log_assert(odsrr->rd_count == rr->rd_count);
    return odsrr;
}


/**
 * Create new ldns RR, based on a given opendnssec-format RR.
 *
 */
ldns_rr*
ods_rr_2ldns(ldns_rdf* owner, uint32_t ttl, ldns_rr_class klass,
    ldns_rr_type rrtype, ods_rr* odsrr)
{
    ldns_rr *rr = NULL;
    ldns_rdf* clone = NULL;
    ldns_status status = LDNS_STATUS_OK;
    int success = 0;
    const ldns_rr_descriptor *desc;
    size_t i;

    if (!owner || !klass || !rrtype || !odsrr) {
        ods_log_error("[%s] unable to convert RR to ldns-format: "
            "owner, class, type or rdata missing", rr_str);
        return NULL;
    }
    rr = malloc(sizeof(ldns_rr));
    if (!rr) {
        ods_log_error("[%s] unable to convert RR to ldns-format: "
            "malloc() failed", rr_str);
        return NULL;
    }
    desc = ldns_rr_descript(rrtype);
    rr->_rdata_fields = calloc(sizeof(ldns_rdf*),
        ldns_rr_descriptor_minimum(desc));
    if(!rr->_rdata_fields) {
        free(rr);
        ods_log_error("[%s] unable to convert RR to ldns-format: "
            "calloc() failed", rr_str);
        return NULL;
    }
    for (i = 0; i < ldns_rr_descriptor_minimum(desc); i++) {
        rr->_rdata_fields[i] = NULL;
    }
    ldns_rr_set_owner(rr, ldns_rdf_clone(owner));
    ldns_rr_set_question(rr, false);
    ldns_rr_set_class(rr, klass);
    ldns_rr_set_ttl(rr, ttl);
    ldns_rr_set_type(rr, rrtype);

    ldns_rr_set_rd_count(rr, 0);
    for (i = 0; i < odsrr->rd_count; i++) {
        if (ods_rr_rdf(odsrr, i)) {
            clone = ldns_rdf_clone(ods_rr_rdf(odsrr, i));
            if (!clone) {
                ods_log_error("[%s] unable to convert RR to ldns-format: "
                    "ldns_rdf_clone() failed", rr_str);
                ldns_rr_free(rr);
                return NULL;
            }

            success = (int) ldns_rr_push_rdf(rr, clone);
            if (!success) {
                ods_log_error("[%s] unable to convert RR to ldns-format: "
                    "ldns_rr_push_rdf() failed (%s)", rr_str,
                    ldns_get_errorstr_by_id(status));
                ldns_rr_free(rr);
                return NULL;
            }
            clone = NULL;
        }
    }
    return rr;
}


/**
 * Get the algorithm field from a RRSIG RR.
 *
 */
ldns_rdf*
ods_rr_rrsig_algorithm(ods_rr* rr)
{
    return ods_rr_rdf(rr, 1);
}

/**
 * Get the inception field from a RRSIG RR.
 *
 */
ldns_rdf*
ods_rr_rrsig_inception(ods_rr* rr)
{
    return ods_rr_rdf(rr, 5);
}


/**
 * Get the expiration field from a RRSIG RR.
 *
 */
ldns_rdf*
ods_rr_rrsig_expiration(ods_rr* rr)
{
    return ods_rr_rdf(rr, 4);
}


/**
 * Print the RR to a given file stream.
 *
 */
void
ods_rr_print(FILE *fd, ldns_rdf* owner, uint32_t ttl, ldns_rr_class klass,
    ldns_rr_type rrtype, ods_rr* odsrr)
{
    ldns_rr* rr = NULL;
    if (!fd) {
        return;
    }
    rr = ods_rr_2ldns(owner, ttl, klass, rrtype, odsrr);
    if (!rr) {
        ods_log_alert("[%s] print RR failed!");
        fprintf(fd, "; print RR failed!\n");
        return;
    }
    ldns_rr_print(fd, rr);
    ldns_rr_free(rr);
    return;
}


/**
 * Clean up RR.
 *
 */
void
ods_rr_free(ods_rr *rr)
{
    size_t i;
    if (rr) {
        for (i = 0; i < rr->rd_count; i++) {
            ldns_rdf_deep_free(ods_rr_rdf(rr, i));
        }
        free(rr->rdata_fields);
        free(rr);
    }
    return;
}


/**
 * Creates a new entry for 1 pointer to an rr and 1 pointer to the next rrs
 *
 */
ods_dnssec_rrs*
ods_dnssec_rrs_new(void)
{
    ods_dnssec_rrs *new_rrs;
    new_rrs = malloc(sizeof(ods_dnssec_rrs));
    if(!new_rrs) {
        return NULL;
    }
    new_rrs->rr = NULL;
    new_rrs->next = NULL;
    return new_rrs;
}


/**
 * Get uncompressed size.
 *
 */
size_t
ods_rr_uncompressed_size(const ods_rr* r)
{
    size_t rrsize = 0;
    size_t i = 0;

    if (!r) {
        return 0;
    }

    /* add all the rdf sizes */
    for(i = 0; i < r->rd_count; i++) {
        rrsize += ldns_rdf_size(ods_rr_rdf((ods_rr*) r, i));
    }
    rrsize += 2; /* RDLEN */
    return rrsize;
}


/**
 * Convert ods_rr to ldns_buffer for comparing.
 *
 */
static ldns_status
ods_rr2buffer_wire_canonical(ldns_buffer* buffer, ods_rr* rr,
    ldns_rr_type rrtype)
{
    uint16_t i;
    uint16_t rdl_pos = 0;
    int pre_rfc3597 = 0;

    switch (rrtype) {
        case LDNS_RR_TYPE_NS:
        case LDNS_RR_TYPE_MD:
        case LDNS_RR_TYPE_MF:
        case LDNS_RR_TYPE_CNAME:
        case LDNS_RR_TYPE_SOA:
        case LDNS_RR_TYPE_MB:
        case LDNS_RR_TYPE_MG:
        case LDNS_RR_TYPE_MR:
        case LDNS_RR_TYPE_PTR:
        case LDNS_RR_TYPE_HINFO:
        case LDNS_RR_TYPE_MINFO:
        case LDNS_RR_TYPE_MX:
        case LDNS_RR_TYPE_RP:
        case LDNS_RR_TYPE_AFSDB:
        case LDNS_RR_TYPE_RT:
        case LDNS_RR_TYPE_SIG:
        case LDNS_RR_TYPE_PX:
        case LDNS_RR_TYPE_NXT:
        case LDNS_RR_TYPE_NAPTR:
        case LDNS_RR_TYPE_KX:
        case LDNS_RR_TYPE_SRV:
        case LDNS_RR_TYPE_DNAME:
        case LDNS_RR_TYPE_A6:
            pre_rfc3597 = true;
            break;
        default:
            break;
    }

    if (ldns_buffer_reserve(buffer, 2)) {
        rdl_pos = ldns_buffer_position(buffer);
        ldns_buffer_write_u16(buffer, 0);
    }

    for (i = 0; i < rr->rd_count; i++) {
        if (pre_rfc3597) {
            (void) ldns_rdf2buffer_wire_canonical(buffer, ods_rr_rdf(rr, i));
        } else {
            (void) ldns_rdf2buffer_wire(buffer, ods_rr_rdf(rr, i));
        }
    }
    ldns_buffer_write_u16_at(buffer, rdl_pos,
        ldns_buffer_position(buffer) - rdl_pos - 2);
    return ldns_buffer_status(buffer);
}


/**
 * Compare RR in wire format.
 *
 */
static int
ods_rr_compare_wire(ldns_buffer* rr1_buf, ldns_buffer* rr2_buf)
{
    size_t rr1_len, rr2_len, min_len, i, offset;

    rr1_len = ldns_buffer_capacity(rr1_buf);
    rr2_len = ldns_buffer_capacity(rr2_buf);

    offset = 3;
    min_len = (rr1_len < rr2_len) ? rr1_len : rr2_len;
    /* Compare RRs RDATA byte for byte. */
    for (i = offset; i < min_len; i++) {
        /**
         * TODO: sometimes valgrind complains here:
         * Conditional jump or move depends on uninitialised value(s)
         */
        if (*ldns_buffer_at(rr1_buf, i) < *ldns_buffer_at(rr2_buf, i)) {
            return -1;
        } else if (*ldns_buffer_at(rr1_buf,i) > *ldns_buffer_at(rr2_buf,i)) {
            return +1;
        }
    }

    /**
     * If both RDATAs are the same up to min_len,
     * then the shorter one sorts first.
     */
    if (rr1_len < rr2_len) {
        return -1;
    } else if (rr1_len > rr2_len) {
        return +1;
    }
    /* The RDATAs are equal. */
    return 0;
}


/**
 * Compare RRs.
 *
 */
ldns_status
ods_dnssec_rrs_compare(ods_rr* rr1, ods_rr* rr2, ldns_rr_type rrtype,
    int* cmp)
{
    ldns_status status = LDNS_STATUS_OK;
    size_t rr1_len;
    size_t rr2_len;
    ldns_buffer* rr1_buf;
    ldns_buffer* rr2_buf;

    if (!rr1 || !rr2) {
        return LDNS_STATUS_ERR;
    }
    rr1_len = ods_rr_uncompressed_size(rr1);
    rr2_len = ods_rr_uncompressed_size(rr2);
    rr1_buf = ldns_buffer_new(rr1_len);
    rr2_buf = ldns_buffer_new(rr2_len);
    /* name, class and type should already be equal */
    status = ods_rr2buffer_wire_canonical(rr1_buf, rr1, rrtype);
    if (status != LDNS_STATUS_OK) {
        ldns_buffer_free(rr1_buf);
        ldns_buffer_free(rr2_buf);
        /* critical */
        return status;
    }
    status = ods_rr2buffer_wire_canonical(rr2_buf, rr2, rrtype);
    if (status != LDNS_STATUS_OK) {
        ldns_buffer_free(rr1_buf);
        ldns_buffer_free(rr2_buf);
        /* critical */
        return status;
    }

    *cmp = ods_rr_compare_wire(rr1_buf, rr2_buf);
    ldns_buffer_free(rr1_buf);
    ldns_buffer_free(rr2_buf);
    return LDNS_STATUS_OK;
}


/**
 * Adds an RR to the list of RRs.
 *
 */
ldns_status
ods_dnssec_rrs_add_rr(ods_dnssec_rrs *rrs, ods_rr *rr, ldns_rr_type rrtype)
{
    int cmp = 0;
    ods_dnssec_rrs *new_rrs = NULL;
    ldns_status status = LDNS_STATUS_OK;

    if (!rrs || !rrs->rr || !rr) {
        return LDNS_STATUS_ERR;
    }
    status = ods_dnssec_rrs_compare(rrs->rr, rr, rrtype, &cmp);
    if (status != LDNS_STATUS_OK) {
        /* critical */
        return status;
    }
    if (cmp < 0) {
        if (rrs->next) {
            return ods_dnssec_rrs_add_rr(rrs->next, rr, rrtype);
        } else {
            new_rrs = ods_dnssec_rrs_new();
            new_rrs->rr = rr;
            rrs->next = new_rrs;
            return LDNS_STATUS_OK;
        }
    } else if (cmp > 0) {
        /* put the current old rr in the new next, put the new
           rr in the current container */
        new_rrs = ods_dnssec_rrs_new();
        new_rrs->rr = rrs->rr;
        new_rrs->next = rrs->next;

        rrs->rr = rr;
        rrs->next = new_rrs;

/* TODO: This has to go in rrset.c
        default_ttl = ldns_rr_ttl(new_rrs->rr);
        if (rr_ttl < default_ttl) {
            ldns_rr_set_ttl(new_rrs->rr, rr_ttl);
        } else {
            ldns_rr_set_ttl(rrs->rr, default_ttl);
        }
*/
        return LDNS_STATUS_OK;
    } else {
        /* should we error on equal? or free memory of rr */
        ods_log_warning("[%s] adding duplicate RR?", rr_str);
        return LDNS_STATUS_NO_DATA;
    }
    return LDNS_STATUS_OK;
}


/**
 * Frees the list of rrs, but *not* the individual ods_rr records.
 *
 */
void
ods_dnssec_rrs_print(FILE* fd, ldns_rdf* owner, uint32_t ttl,
    ldns_rr_class klass, ldns_rr_type rrtype, ods_dnssec_rrs* rrs)
{
    if (!rrs) {
        fprintf(fd, "; <void>");
    } else {
        if (rrs->rr) {
            ods_rr_print(fd, owner, ttl, klass, rrtype, rrs->rr);
        }
        if (rrs->next) {
            ods_dnssec_rrs_print(fd, owner, ttl, klass, rrtype, rrs->next);
        }
    }
    return;
}


/**
 * Internal function to free the list of rrs.
 *
 */
static void
ods_dnssec_rrs_free_internal(ods_dnssec_rrs *rrs, int deep)
{
    ods_dnssec_rrs *next;
    while (rrs) {
        next = rrs->next;
        if (deep) {
            ods_rr_free(rrs->rr);
        }
        free(rrs);
        rrs = next;
    }
    return;
}


/**
 * Frees the list of rrs, but *not* the individual ods_rr records.
 *
 */
void
ods_dnssec_rrs_free(ods_dnssec_rrs *rrs)
{
    ods_dnssec_rrs_free_internal(rrs, 0);
    return;
}


/**
 * Frees the list of rrs, *and* the individual ldns_rr records.
 *
 */
void
ods_dnssec_rrs_deep_free(ods_dnssec_rrs *rrs)
{
    ods_dnssec_rrs_free_internal(rrs, 1);
    return;
}
