/*
 * $Id: axfr.c 4958 2011-04-18 07:11:09Z matthijs $
 *
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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
 * AXFR.
 *
 */

#include "config.h"
#include "adapter/addns.h"
#include "adapter/adutil.h"
#include "shared/file.h"
#include "wire/axfr.h"
#include "wire/buffer.h"
#include "wire/query.h"
#include "wire/sock.h"

#define AXFR_TSIG_SIGN_EVERY_NTH 96 /* tsig sign every N packets. */

const char* axfr_str = "axfr";


/**
 * Do AXFR.
 *
 */
query_state
axfr(query_type* q, engine_type* engine)
{
    char* xfrfile = NULL;
    ldns_rr* rr = NULL;
    ldns_rdf* prev = NULL;
    ldns_rdf* orig = NULL;
    uint16_t total_added = 0;
    uint32_t ttl = 0;
    ldns_status status = LDNS_STATUS_OK;
    char line[SE_ADFILE_MAXLINE];
    unsigned soa_seen = 0;
    unsigned l = 0;
    long fpos = 0;

    ods_log_assert(q);
    ods_log_assert(engine);

    if (q->axfr_is_done) {
        return QUERY_PROCESSED;
    }
    if (q->maxlen > AXFR_MAX_MESSAGE_LEN) {
        q->maxlen = AXFR_MAX_MESSAGE_LEN;
    }

    /* prepare tsig */
    q->tsig_prepare_it = 0;
    q->tsig_update_it = 1;
    if (q->tsig_sign_it) {
        q->tsig_prepare_it = 1;
        q->tsig_sign_it = 0;
    }
    ods_log_assert(q->tsig_rr);
    ods_log_assert(q->zone);
    ods_log_assert(q->zone->name);
    if (q->axfr_fd == NULL) {
        /* start axfr */
        xfrfile = ods_build_path(q->zone->name, ".axfr", 0);
        q->axfr_fd = ods_fopen(xfrfile, NULL, "r");
        free((void*)xfrfile);
        if (!q->axfr_fd) {
            ods_log_error("[%s] unable to open axfr file %s for zone %s",
                axfr_str, xfrfile, q->zone->name);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
        if (q->tsig_rr->status == TSIG_OK) {
            q->tsig_sign_it = 1; /* sign first packet in stream */
        }
        /* compression? */

        /* add soa rr */
        fpos = ftell(q->axfr_fd);
        rr = addns_read_rr(q->axfr_fd, line, &orig, &prev, &ttl, &status,
            &l);
        if (!rr) {
            /* no SOA no transfer */
            ods_log_error("[%s] bad axfr zone %s, corrupted file",
                axfr_str, q->zone->name);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
        if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA) {
            ods_log_error("[%s] bad axfr zone %s, first rr is not soa",
                axfr_str, q->zone->name);
            ldns_rr_free(rr);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
        /* does it fit? */
        if (buffer_write_rr(q->buffer, rr)) {
            buffer_pkt_set_ancount(q->buffer, buffer_pkt_ancount(q->buffer)+1);
            total_added++;
            ldns_rr_free(rr);
            rr = NULL;
        } else {
            ldns_rr_free(rr);
            rr = NULL;
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
    } else {
        /* subsequent axfr packets */
        buffer_set_limit(q->buffer, BUFFER_PKT_HEADER_SIZE);
        buffer_pkt_set_qdcount(q->buffer, 0);
        query_prepare(q);
    }
    /* add as many records as fit */
    fpos = ftell(q->axfr_fd);
    while ((rr = addns_read_rr(q->axfr_fd, line, &orig, &prev, &ttl,
        &status, &l)) != NULL) {
        if (status != LDNS_STATUS_OK) {
            ldns_rr_free(rr);
            rr = NULL;
            ods_log_error("[%s] error reading rr at line %i (%s): %s",
                axfr_str, l, ldns_get_errorstr_by_id(status), line);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
        /* does it fit? */
        if (buffer_write_rr(q->buffer, rr)) {
            fpos = ftell(q->axfr_fd);
            buffer_pkt_set_ancount(q->buffer, buffer_pkt_ancount(q->buffer)+1);
            total_added++;
            ldns_rr_free(rr);
            rr = NULL;
        } else {
            ldns_rr_free(rr);
            rr = NULL;
            if (fseek(q->axfr_fd, fpos, SEEK_SET) != 0) {
                ods_log_error("[%s] unable to reset file position in axfr "
                    "file: fseek() failed (%s)", axfr_str, strerror(errno));
                buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
                return QUERY_PROCESSED;
            } else {
                goto return_answer;
            }
        }
    }
    q->tsig_sign_it = 1; /* sign last packet */
    q->axfr_is_done = 1;

return_answer:
    buffer_pkt_set_ancount(q->buffer, total_added);
    buffer_pkt_set_nscount(q->buffer, 0);
    buffer_pkt_set_arcount(q->buffer, 0);

    /* check if it needs tsig signatures */
    if (q->tsig_rr->status == TSIG_OK) {
        if (q->tsig_rr->update_since_last_prepare >= AXFR_TSIG_SIGN_EVERY_NTH) {
            q->tsig_sign_it = 1;
        }
    }
    return QUERY_PROCESSED;
}


/**
 * Do IXFR (equal to AXFR for now).
 *
 */
query_state
ixfr(query_type* q, engine_type* engine)
{
    char* xfrfile = NULL;
    ldns_rr* rr = NULL;
    ldns_rdf* prev = NULL;
    ldns_rdf* orig = NULL;
    uint16_t total_added = 0;
    uint32_t ttl = 0;
    ldns_status status = LDNS_STATUS_OK;
    char line[SE_ADFILE_MAXLINE];
    unsigned soa_seen = 0;
    unsigned l = 0;
    long fpos = 0;

    ods_log_assert(q);
    ods_log_assert(engine);

    if (q->axfr_is_done) {
        return QUERY_PROCESSED;
    }
    if (q->maxlen > AXFR_MAX_MESSAGE_LEN) {
        q->maxlen = AXFR_MAX_MESSAGE_LEN;
    }

    /* prepare tsig */
    q->tsig_prepare_it = 0;
    q->tsig_update_it = 1;
    if (q->tsig_sign_it) {
        q->tsig_prepare_it = 1;
        q->tsig_sign_it = 0;
    }
    ods_log_assert(q->tsig_rr);
    ods_log_assert(q->zone);
    ods_log_assert(q->zone->name);
    if (q->axfr_fd == NULL) {
        /* start axfr */
        xfrfile = ods_build_path(q->zone->name, ".axfr", 0);
        q->axfr_fd = ods_fopen(xfrfile, NULL, "r");
        free((void*)xfrfile);
        if (!q->axfr_fd) {
            ods_log_error("[%s] unable to open axfr file %s for zone %s",
                axfr_str, xfrfile, q->zone->name);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
        if (q->tsig_rr->status == TSIG_OK) {
            q->tsig_sign_it = 1; /* sign first packet in stream */
        }
        /* compression? */

        /* add soa rr */
        fpos = ftell(q->axfr_fd);
        rr = addns_read_rr(q->axfr_fd, line, &orig, &prev, &ttl, &status,
            &l);
        if (!rr) {
            /* no SOA no transfer */
            ods_log_error("[%s] bad axfr zone %s, corrupted file",
                axfr_str, q->zone->name);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
        if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA) {
            ods_log_error("[%s] bad axfr zone %s, first rr is not soa",
                axfr_str, q->zone->name);
            ldns_rr_free(rr);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
        /* does it fit? */
        if (buffer_write_rr(q->buffer, rr)) {
            buffer_pkt_set_ancount(q->buffer, buffer_pkt_ancount(q->buffer)+1);
            total_added++;
            ldns_rr_free(rr);
            rr = NULL;
        } else {
            ldns_rr_free(rr);
            rr = NULL;
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
    } else {
        /* subsequent axfr packets */
        buffer_set_limit(q->buffer, BUFFER_PKT_HEADER_SIZE);
        buffer_pkt_set_qdcount(q->buffer, 0);
        query_prepare(q);
    }
    /* add as many records as fit */
    fpos = ftell(q->axfr_fd);
    while ((rr = addns_read_rr(q->axfr_fd, line, &orig, &prev, &ttl,
        &status, &l)) != NULL) {
        if (status != LDNS_STATUS_OK) {
            ldns_rr_free(rr);
            rr = NULL;
            ods_log_error("[%s] error reading rr at line %i (%s): %s",
                axfr_str, l, ldns_get_errorstr_by_id(status), line);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
        /* does it fit? */
        if (buffer_write_rr(q->buffer, rr)) {
            fpos = ftell(q->axfr_fd);
            buffer_pkt_set_ancount(q->buffer, buffer_pkt_ancount(q->buffer)+1);
            total_added++;
            ldns_rr_free(rr);
            rr = NULL;
        } else {
            ldns_rr_free(rr);
            rr = NULL;
            if (fseek(q->axfr_fd, fpos, SEEK_SET) != 0) {
                ods_log_error("[%s] unable to reset file position in axfr "
                    "file: fseek() failed (%s)", axfr_str, strerror(errno));
                buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
                return QUERY_PROCESSED;
            } else {
                goto return_answer;
            }
        }
    }
    q->tsig_sign_it = 1; /* sign last packet */
    q->axfr_is_done = 1;

return_answer:
    buffer_pkt_set_ancount(q->buffer, total_added);
    buffer_pkt_set_nscount(q->buffer, 0);
    buffer_pkt_set_arcount(q->buffer, 0);

    /* check if it needs tsig signatures */
    if (q->tsig_rr->status == TSIG_OK) {
        if (q->tsig_rr->update_since_last_prepare >= AXFR_TSIG_SIGN_EVERY_NTH) {
            q->tsig_sign_it = 1;
        }
    }
    return QUERY_PROCESSED;
}
