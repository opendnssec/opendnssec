/*
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

#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "adapter/addns.h"
#include "adapter/adutil.h"
#include "file.h"
#include "util.h"
#include "wire/axfr.h"
#include "wire/buffer.h"
#include "wire/edns.h"
#include "wire/query.h"
#include "wire/sock.h"

#define AXFR_TSIG_SIGN_EVERY_NTH 96 /* tsig sign every N packets. */

const char* axfr_str = "axfr";

/**
 * Handle SOA request.
 *
 */
query_state
soa_request(query_type* q, engine_type* engine)
{
    char* xfrfile = NULL;
    ldns_rr* rr = NULL;
    ldns_rdf* prev = NULL;
    ldns_rdf* orig = NULL;
    uint32_t ttl = 0;
    time_t expire = 0;
    ldns_status status = LDNS_STATUS_OK;
    char line[SE_ADFILE_MAXLINE];
    unsigned l = 0;
    FILE* fd = NULL;
    ods_log_assert(q);
    ods_log_assert(q->buffer);
    ods_log_assert(q->zone);
    ods_log_assert(q->zone->name);
    ods_log_assert(engine);
    xfrfile = ods_build_path(q->zone->name, ".axfr", 0, 1);
    if (xfrfile) {
        fd = ods_fopen(xfrfile, NULL, "r");
    }
    if (!fd) {
        ods_log_error("[%s] unable to open file %s for zone %s",
            axfr_str, xfrfile, q->zone->name);
        free((void*)xfrfile);
        buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
        return QUERY_PROCESSED;
    }
    free((void*)xfrfile);
    if (q->tsig_rr->status == TSIG_OK) {
        q->tsig_sign_it = 1; /* sign first packet in stream */
    }
    /* compression? */

    /* add SOA RR */
    rr = addns_read_rr(fd, line, &orig, &prev, &ttl, &status, &l);
    if (!rr) {
        /* no SOA no transfer */
        ods_log_error("[%s] bad axfr zone %s, corrupted file", axfr_str,
            q->zone->name);
        buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
        ods_fclose(fd);
        return QUERY_PROCESSED;
    }
    /* first RR must be SOA */
    if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA) {
        ods_log_error("[%s] bad axfr zone %s, first rr is not soa",
            axfr_str, q->zone->name);
        ldns_rr_free(rr);
        buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
        ods_fclose(fd);
        return QUERY_PROCESSED;
    }
    /* zone not expired? */
    if (q->zone->xfrd) {
        expire = q->zone->xfrd->serial_xfr_acquired;
        expire += ldns_rdf2native_int32(ldns_rr_rdf(rr, SE_SOA_RDATA_EXPIRE));
        if (expire < time_now()) {
            ods_log_warning("[%s] zone %s expired at %lld, and it is now %lld: "
                "not serving soa", axfr_str, q->zone->name, (long long)expire, (long long)time_now());
            ldns_rr_free(rr);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            ods_fclose(fd);
            return QUERY_PROCESSED;
        }
    }
    /* does it fit? */
    if (query_add_rr(q, rr)) {
        ods_log_debug("[%s] set soa in response %s", axfr_str,
            q->zone->name);
        buffer_pkt_set_ancount(q->buffer, buffer_pkt_ancount(q->buffer)+1);
        ldns_rr_free(rr);
        rr = NULL;
    } else {
        ods_log_error("[%s] soa does not fit in response %s",
            axfr_str, q->zone->name);
        ldns_rr_free(rr);
        buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
        ods_fclose(fd);
        return QUERY_PROCESSED;
    }
    ods_fclose(fd);
    buffer_pkt_set_ancount(q->buffer, 1);
    buffer_pkt_set_nscount(q->buffer, 0);
    buffer_pkt_set_arcount(q->buffer, 0);
    buffer_pkt_set_aa(q->buffer);
    /* check if it needs TSIG signatures */
    if (q->tsig_rr->status == TSIG_OK) {
        q->tsig_sign_it = 1;
    }
    return QUERY_PROCESSED;
}


/**
 * Do AXFR.
 *
 */
query_state
axfr(query_type* q, engine_type* engine, int fallback)
{
    ldns_rr* rr = NULL;
    ldns_rdf* prev = NULL;
    ldns_rdf* orig = NULL;
    uint16_t total_added = 0;
    uint32_t ttl = 0;
    time_t expire = 0;
    ldns_status status = LDNS_STATUS_OK;
    char line[SE_ADFILE_MAXLINE];
    unsigned l = 0;
    long fpos = 0;
    size_t bufpos = 0;
    ods_log_assert(q);
    ods_log_assert(q->buffer);
    ods_log_assert(q->zone);
    ods_log_assert(q->zone->name);
    ods_log_assert(engine);
    if (q->axfr_is_done) {
        ods_log_debug("[%s] zone transfer %s completed", axfr_str,
            q->zone->name);
        return QUERY_PROCESSED;
    }
    if (q->maxlen > AXFR_MAX_MESSAGE_LEN) {
        q->maxlen = AXFR_MAX_MESSAGE_LEN;
    }

    /* prepare TSIG */
    if (!fallback) {
        q->tsig_prepare_it = 0;
        q->tsig_update_it = 1;
        if (q->tsig_sign_it) {
            q->tsig_prepare_it = 1;
            q->tsig_sign_it = 0;
        }
    }
    ods_log_assert(q->tsig_rr);
    if (q->axfr_fd == NULL) {
        /* start AXFR */
        q->axfr_fd = getxfr(q->zone, ".axfr", NULL);
        if (!q->axfr_fd) {
            ods_log_error("[%s] unable to open axfr file for zone %s",
                axfr_str, q->zone->name);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
        if (q->tsig_rr->status == TSIG_OK) {
            q->tsig_sign_it = 1; /* sign first packet in stream */
        }
        /* compression? */

        /* add SOA RR */
        fpos = ftell(q->axfr_fd);
        if (fpos < 0) {
            ods_log_error("[%s] unable to read axfr for zone %s: "
                "ftell() failed (%s)", axfr_str, q->zone->name,
                strerror(errno));
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
        rr = addns_read_rr(q->axfr_fd, line, &orig, &prev, &ttl, &status,
            &l);
        if (!rr) {
            /* no SOA no transfer */
            ods_log_error("[%s] bad axfr zone %s, corrupted file",
                axfr_str, q->zone->name);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            ods_fclose(q->axfr_fd);
            q->axfr_fd = NULL;
            return QUERY_PROCESSED;
        }
        /* first RR must be SOA */
        if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA) {
            ods_log_error("[%s] bad axfr zone %s, first rr is not soa",
                axfr_str, q->zone->name);
            ldns_rr_free(rr);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            ods_fclose(q->axfr_fd);
            q->axfr_fd = NULL;
            return QUERY_PROCESSED;
        }
        /* zone not expired? */
        if (q->zone->xfrd) {
            expire = q->zone->xfrd->serial_xfr_acquired;
            expire += ldns_rdf2native_int32(ldns_rr_rdf(rr, SE_SOA_RDATA_EXPIRE));
            if (expire < time_now()) {
                ods_log_warning("[%s] zone %s expired, not transferring zone",
                    axfr_str, q->zone->name);
                ldns_rr_free(rr);
                buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
                ods_fclose(q->axfr_fd);
                q->axfr_fd = NULL;
                return QUERY_PROCESSED;
            }
        }
        /* does it fit? */
        if (query_add_rr(q, rr)) {
            ods_log_debug("[%s] set soa in axfr zone %s", axfr_str,
                q->zone->name);
            buffer_pkt_set_ancount(q->buffer, buffer_pkt_ancount(q->buffer)+1);
            total_added++;
            ldns_rr_free(rr);
            rr = NULL;
            bufpos = buffer_position(q->buffer);
        } else {
            ods_log_error("[%s] soa does not fit in axfr zone %s",
                axfr_str, q->zone->name);
            ldns_rr_free(rr);
            rr = NULL;
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            ods_fclose(q->axfr_fd);
            q->axfr_fd = NULL;
            return QUERY_PROCESSED;
        }
    } else if (q->tcp) {
        /* subsequent AXFR packets */
        ods_log_debug("[%s] subsequent axfr packet zone %s", axfr_str,
            q->zone->name);
        q->edns_rr->status = EDNS_NOT_PRESENT;
        buffer_set_limit(q->buffer, BUFFER_PKT_HEADER_SIZE);
        buffer_pkt_set_qdcount(q->buffer, 0);
        query_prepare(q);
    }
    /* add as many records as fit */
    fpos = ftell(q->axfr_fd);
    if (fpos < 0) {
        ods_log_error("[%s] unable to read axfr for zone %s: "
            "ftell() failed (%s)", axfr_str, q->zone->name,
            strerror(errno));
        buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
        ods_fclose(q->axfr_fd);
        q->axfr_fd = NULL;
        return QUERY_PROCESSED;
    }
    while ((rr = addns_read_rr(q->axfr_fd, line, &orig, &prev, &ttl,
        &status, &l)) != NULL) {
        ods_log_deeebug("[%s] read rr at line %d", axfr_str, l);
        if (status != LDNS_STATUS_OK) {
            ldns_rr_free(rr);
            rr = NULL;
            ods_log_error("[%s] error reading rr at line %i (%s): %s",
                axfr_str, l, ldns_get_errorstr_by_id(status), line);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            ods_fclose(q->axfr_fd);
            q->axfr_fd = NULL;
            return QUERY_PROCESSED;
        }
        /* does it fit? */
        if (query_add_rr(q, rr)) {
            ods_log_deeebug("[%s] add rr at line %d", axfr_str, l);
            ldns_rr_free(rr);
            rr = NULL;
            fpos = ftell(q->axfr_fd);
            if (fpos < 0) {
                ods_log_error("[%s] unable to read axfr for zone %s: "
                    "ftell() failed (%s)", axfr_str, q->zone->name,
                    strerror(errno));
                buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
                ods_fclose(q->axfr_fd);
                q->axfr_fd = NULL;
                return QUERY_PROCESSED;
            }
            buffer_pkt_set_ancount(q->buffer, buffer_pkt_ancount(q->buffer)+1);
            total_added++;
        } else {
            ods_log_deeebug("[%s] rr at line %d does not fit", axfr_str, l);
            ldns_rr_free(rr);
            rr = NULL;
            if (fseek(q->axfr_fd, fpos, SEEK_SET) != 0) {
                ods_log_error("[%s] unable to reset file position in axfr "
                    "file: fseek() failed (%s)", axfr_str, strerror(errno));
                buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
                ods_fclose(q->axfr_fd);
                q->axfr_fd = NULL;
                return QUERY_PROCESSED;
            } else if (q->tcp) {
                goto return_axfr;
            } else {
                goto udp_overflow;
            }
        }
    }
    ods_log_debug("[%s] axfr zone %s is done", axfr_str, q->zone->name);
    q->tsig_sign_it = 1; /* sign last packet */
    q->axfr_is_done = 1;
    ods_fclose(q->axfr_fd);
    q->axfr_fd = NULL;

return_axfr:
    if (q->tcp) {
        ods_log_debug("[%s] return part axfr zone %s", axfr_str,
            q->zone->name);
        buffer_pkt_set_aa(q->buffer);
        buffer_pkt_set_ancount(q->buffer, total_added);
        buffer_pkt_set_nscount(q->buffer, 0);
        buffer_pkt_set_arcount(q->buffer, 0);
        /* check if it needs TSIG signatures */
        if (q->tsig_rr->status == TSIG_OK) {
            if (q->tsig_rr->update_since_last_prepare >=
                AXFR_TSIG_SIGN_EVERY_NTH) {
                q->tsig_sign_it = 1;
            }
        }
        return QUERY_AXFR;
    }
    ods_log_error("[%s] zone transfer %s not tcp", axfr_str,
            q->zone->name);

udp_overflow:
    /* UDP Overflow */
    ods_log_info("[%s] axfr udp overflow zone %s", axfr_str, q->zone->name);
    buffer_set_position(q->buffer, bufpos);
    buffer_pkt_set_aa(q->buffer);
    buffer_pkt_set_ancount(q->buffer, 1);
    buffer_pkt_set_nscount(q->buffer, 0);
    buffer_pkt_set_arcount(q->buffer, 0);
    /* check if it needs TSIG signatures */
    if (q->tsig_rr->status == TSIG_OK) {
        q->tsig_sign_it = 1;
    }
    ods_log_debug("[%s] zone transfer %s udp overflow", axfr_str,
        q->zone->name);
    return QUERY_PROCESSED;
}


/**
 * Do IXFR (equal to AXFR for now).
 *
 */
query_state
ixfr(query_type* q, engine_type* engine)
{
    ldns_rr* rr = NULL;
    ldns_rdf* prev = NULL;
    ldns_rdf* orig = NULL;
    uint16_t total_added = 0;
    uint32_t ttl = 0;
    time_t expire = 0;
    ldns_status status = LDNS_STATUS_OK;
    char line[SE_ADFILE_MAXLINE];
    unsigned l = 0;
    long fpos = 0;
    size_t bufpos = 0;
    uint32_t new_serial = 0;
    unsigned del_mode = 0;
    unsigned soa_found = 0;
    ods_log_assert(engine);
    ods_log_assert(q);
    ods_log_assert(q->buffer);
    ods_log_assert(q->zone);
    ods_log_assert(q->zone->name);
    if (q->axfr_is_done) {
        return QUERY_PROCESSED;
    }
    if (q->maxlen > AXFR_MAX_MESSAGE_LEN) {
        q->maxlen = AXFR_MAX_MESSAGE_LEN;
    }
    /* prepare TSIG */
    q->tsig_prepare_it = 0;
    q->tsig_update_it = 1;
    if (q->tsig_sign_it) {
        q->tsig_prepare_it = 1;
        q->tsig_sign_it = 0;
    }
    ods_log_assert(q->tsig_rr);
    if (q->axfr_fd == NULL) {
        /* start IXFR */
        q->axfr_fd = getxfr(q->zone, ".ixfr", &q->zone->xfrd->serial_xfr_acquired);
        if (!q->axfr_fd) {
            ods_log_error("[%s] unable to open ixfr file for zone %s",
                axfr_str, q->zone->name);
            ods_log_info("[%s] axfr fallback zone %s", axfr_str,
                q->zone->name);
            buffer_set_position(q->buffer, q->startpos);
            return axfr(q, engine, 1);
        }
        if (q->tsig_rr->status == TSIG_OK) {
            q->tsig_sign_it = 1; /* sign first packet in stream */
        }
        /* compression? */

        /* add SOA RR */
        fpos = ftell(q->axfr_fd);
        if (fpos < 0) {
            ods_log_error("[%s] unable to read ixfr for zone %s: ftell() "
                "failed (%s)", axfr_str, q->zone->name, strerror(errno));
            ods_log_info("[%s] axfr fallback zone %s", axfr_str,
                q->zone->name);
            ods_fclose(q->axfr_fd);
            q->axfr_fd = NULL;
            buffer_set_position(q->buffer, q->startpos);
            return axfr(q, engine, 1);
        }
        rr = addns_read_rr(q->axfr_fd, line, &orig, &prev, &ttl, &status,
            &l);
        if (!rr) {
            /* no SOA no transfer */
            ods_log_error("[%s] bad ixfr zone %s, corrupted file",
                axfr_str, q->zone->name);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
        /* first RR must be SOA */
        if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA) {
            ods_log_error("[%s] bad ixfr zone %s, first rr is not soa",
                axfr_str, q->zone->name);
            ldns_rr_free(rr);
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
        /* zone not expired? */
        if (q->zone->xfrd) {
            expire = q->zone->xfrd->serial_xfr_acquired;
            expire += ldns_rdf2native_int32(ldns_rr_rdf(rr, SE_SOA_RDATA_EXPIRE));
            if (expire < time_now()) {
                ods_log_warning("[%s] zone %s expired, not transferring zone",
                    axfr_str, q->zone->name);
                ldns_rr_free(rr);
                buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
                ods_fclose(q->axfr_fd);
                q->axfr_fd = NULL;
                return QUERY_PROCESSED;
            }
        }
        /* newest serial */
        new_serial = ldns_rdf2native_int32(
            ldns_rr_rdf(rr, SE_SOA_RDATA_SERIAL));
        /* does it fit? */
        buffer_set_position(q->buffer, q->startpos);
        if (query_add_rr(q, rr)) {
            ods_log_debug("[%s] set soa in ixfr zone %s", axfr_str,
                q->zone->name);
            buffer_pkt_set_ancount(q->buffer, buffer_pkt_ancount(q->buffer)+1);
            total_added++;
            ldns_rr_free(rr);
            rr = NULL;
            bufpos = buffer_position(q->buffer);
        } else {
            ods_log_error("[%s] soa does not fit in ixfr zone %s",
                axfr_str, q->zone->name);
            ldns_rr_free(rr);
            rr = NULL;
            buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
            return QUERY_PROCESSED;
        }
        if (util_serial_gt(q->serial, new_serial)) {
            goto axfr_fallback;
        }
    } else if (q->tcp) {
        /* subsequent IXFR packets */
        ods_log_debug("[%s] subsequent ixfr packet zone %s", axfr_str,
            q->zone->name);
        buffer_set_limit(q->buffer, BUFFER_PKT_HEADER_SIZE);
        buffer_pkt_set_qdcount(q->buffer, 0);
        query_prepare(q);
        soa_found = 1;
    }

    /* add as many records as fit */
    fpos = ftell(q->axfr_fd);
    if (fpos < 0) {
        ods_log_error("[%s] unable to read ixfr for zone %s: ftell() failed "
            "(%s)", axfr_str, q->zone->name, strerror(errno));
        ods_log_info("[%s] axfr fallback zone %s", axfr_str,
            q->zone->name);
        ods_fclose(q->axfr_fd);
        q->axfr_fd = NULL;
        buffer_set_position(q->buffer, q->startpos);
        return axfr(q, engine, 1);
    }
    while ((rr = addns_read_rr(q->axfr_fd, line, &orig, &prev, &ttl,
        &status, &l)) != NULL) {
        ods_log_deeebug("[%s] read rr at line %d", axfr_str, l);
        if (status != LDNS_STATUS_OK) {
            ldns_rr_free(rr);
            rr = NULL;
            ods_log_error("[%s] error reading rr at line %i (%s): %s",
                axfr_str, l, ldns_get_errorstr_by_id(status), line);
            goto axfr_fallback;
        }
        if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_SOA) {
            del_mode = !del_mode;
        }
        if (!soa_found) {
            if (del_mode && ldns_rr_get_type(rr) == LDNS_RR_TYPE_SOA &&
                q->serial == ldns_rdf2native_int32(
                ldns_rr_rdf(rr, SE_SOA_RDATA_SERIAL))) {
                soa_found = 1;
            } else {
                ods_log_deeebug("[%s] soa serial %u not found for rr at line %d",
                    axfr_str, q->serial, l);
                ldns_rr_free(rr);
                rr = NULL;
                continue;
            }
        }
        /* does it fit? */
        if (query_add_rr(q, rr)) {
            ods_log_deeebug("[%s] add rr at line %d", axfr_str, l);
            ldns_rr_free(rr);
            rr = NULL;
            fpos = ftell(q->axfr_fd);
            if (fpos < 0) {
                ods_log_error("[%s] unable to read ixfr for zone %s: ftell() "
                    "failed (%s)", axfr_str, q->zone->name, strerror(errno));
                ods_log_info("[%s] axfr fallback zone %s", axfr_str,
                    q->zone->name);
                ods_fclose(q->axfr_fd);
                q->axfr_fd = NULL;
                buffer_set_position(q->buffer, q->startpos);
                return axfr(q, engine, 1);
            }
            buffer_pkt_set_ancount(q->buffer, buffer_pkt_ancount(q->buffer)+1);
            total_added++;
        } else {
            ods_log_deeebug("[%s] rr at line %d does not fit", axfr_str, l);
            ldns_rr_free(rr);
            rr = NULL;
            if (fseek(q->axfr_fd, fpos, SEEK_SET) != 0) {
                ods_log_error("[%s] unable to reset file position in ixfr "
                    "file: fseek() failed (%s)", axfr_str, strerror(errno));
                buffer_pkt_set_rcode(q->buffer, LDNS_RCODE_SERVFAIL);
                return QUERY_PROCESSED;
            } else if (q->tcp) {
                goto return_ixfr;
            } else {
                goto axfr_fallback;
            }
        }
    }
    if (!soa_found) {
        ods_log_warning("[%s] zone %s journal not found for serial %u",
            axfr_str, q->zone->name, q->serial);
        goto axfr_fallback;
    }
    ods_log_debug("[%s] ixfr zone %s is done", axfr_str, q->zone->name);
    q->tsig_sign_it = 1; /* sign last packet */
    q->axfr_is_done = 1;
    ods_fclose(q->axfr_fd);
    q->axfr_fd = NULL;

return_ixfr:
    ods_log_debug("[%s] return part ixfr zone %s", axfr_str, q->zone->name);
    buffer_pkt_set_ancount(q->buffer, total_added);
    buffer_pkt_set_nscount(q->buffer, 0);
    buffer_pkt_set_arcount(q->buffer, 0);

    /* check if it needs TSIG signatures */
    if (q->tsig_rr->status == TSIG_OK) {
        if (q->tsig_rr->update_since_last_prepare >= AXFR_TSIG_SIGN_EVERY_NTH) {
            q->tsig_sign_it = 1;
        }
    }
    return QUERY_IXFR;

axfr_fallback:
    if (q->tcp) {
        ods_log_info("[%s] axfr fallback zone %s", axfr_str, q->zone->name);
        if (q->axfr_fd) {
            ods_fclose(q->axfr_fd);
            q->axfr_fd = NULL;
        }
        buffer_set_position(q->buffer, q->startpos);
        return axfr(q, engine, 1);
    }
    /* UDP Overflow */
    ods_log_info("[%s] ixfr udp overflow zone %s", axfr_str, q->zone->name);
    buffer_set_position(q->buffer, bufpos);
    buffer_pkt_set_ancount(q->buffer, 1);
    buffer_pkt_set_nscount(q->buffer, 0);
    buffer_pkt_set_arcount(q->buffer, 0);
    /* check if it needs TSIG signatures */
    if (q->tsig_rr->status == TSIG_OK) {
        q->tsig_sign_it = 1;
    }
    return QUERY_PROCESSED;
}
