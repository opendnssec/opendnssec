/*
 * Copyright (c) 2011-2018 NLNet Labs.
 * All rights reserved.
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
 */

/**
 * Query.
 *
 */

#include "config.h"
#include "daemon/dnshandler.h"
#include "daemon/engine.h"
#include "file.h"
#include "util.h"
#include "wire/axfr.h"
#include "wire/query.h"

const char* query_str = "query";


/**
 * Create query.
 *
 */
query_type*
query_create(void)
{
    query_type* q = NULL;
    CHECKALLOC(q = (query_type*) malloc(sizeof(query_type)));
    q->buffer = NULL;
    q->tsig_rr = NULL;
    q->axfr_fd = NULL;
    q->buffer = buffer_create(PACKET_BUFFER_SIZE);
    if (!q->buffer) {
        query_cleanup(q);
        return NULL;
    }
    q->tsig_rr = tsig_rr_create();
    if (!q->tsig_rr) {
        query_cleanup(q);
        return NULL;
    }
    q->edns_rr = edns_rr_create();
    if (!q->edns_rr) {
        query_cleanup(q);
        return NULL;
    }
    query_reset(q, UDP_MAX_MESSAGE_LEN, 0);
    return q;
}


/**
 * Reset query.
 *
 */
void
query_reset(query_type* q, size_t maxlen, int is_tcp)
{
    if (!q) {
        return;
    }
    q->addrlen = sizeof(q->addr);
    q->maxlen = maxlen;
    q->reserved_space = 0;
    buffer_clear(q->buffer);
    tsig_rr_reset(q->tsig_rr, NULL, NULL);
    edns_rr_reset(q->edns_rr);
    q->tsig_prepare_it = 1;
    q->tsig_update_it = 1;
    q->tsig_sign_it = 1;
    q->tcp = is_tcp;
    /* qname, qtype, qclass */
    q->zone = NULL;
    /* domain, opcode, cname count, delegation, compression, temp */
    q->axfr_is_done = 0;
    if (q->axfr_fd) {
        ods_fclose(q->axfr_fd);
        q->axfr_fd = NULL;
    }
    q->serial = 0;
    q->startpos = 0;
}


/**
 * Error.
 *
 */
static query_state
query_error(query_type* q, ldns_pkt_rcode rcode)
{
    size_t limit = 0;
    if (!q) {
        return QUERY_DISCARDED;
    }
    limit = buffer_limit(q->buffer);
    buffer_clear(q->buffer);
    buffer_pkt_set_qr(q->buffer);
    buffer_pkt_set_rcode(q->buffer, rcode);
    buffer_pkt_set_ancount(q->buffer, 0);
    buffer_pkt_set_nscount(q->buffer, 0);
    buffer_pkt_set_arcount(q->buffer, 0);
    buffer_set_position(q->buffer, limit);
    return QUERY_PROCESSED;
}


/**
 * FORMERR.
 *
 */
static query_state
query_formerr(query_type* q)
{
    ldns_pkt_opcode opcode = LDNS_PACKET_QUERY;
    if (!q) {
        return QUERY_DISCARDED;
    }
    opcode = buffer_pkt_opcode(q->buffer);
    /* preserve the RD flag, clear the rest */
    buffer_pkt_set_flags(q->buffer, buffer_pkt_flags(q->buffer) & 0x0100U);
    buffer_pkt_set_opcode(q->buffer, opcode);
    buffer_pkt_set_qdcount(q->buffer, 0);
    ods_log_debug("[%s] formerr", query_str);
    return query_error(q, LDNS_RCODE_FORMERR);
}


/**
 * SERVFAIL.
 *
 */
static query_state
query_servfail(query_type* q)
{
    if (!q) {
        return QUERY_DISCARDED;
    }
    ods_log_debug("[%s] servfail", query_str);
    buffer_set_position(q->buffer, 0);
    buffer_set_limit(q->buffer, BUFFER_PKT_HEADER_SIZE);
    buffer_pkt_set_qdcount(q->buffer, 0);
    return query_error(q, LDNS_RCODE_SERVFAIL);
}


/**
 * NOTIMPL.
 *
 */
static query_state
query_notimpl(query_type* q)
{
    if (!q) {
        return QUERY_DISCARDED;
    }
    ods_log_debug("[%s] notimpl", query_str);
    return query_error(q, LDNS_RCODE_NOTIMPL);
}


/**
 * REFUSED.
 *
 */
static query_state
query_refused(query_type* q)
{
    if (!q) {
        return QUERY_DISCARDED;
    }
    ods_log_debug("[%s] refused", query_str);
    return query_error(q, LDNS_RCODE_REFUSED);
}


/**
 * NOTAUTH.
 *
 */
static query_state
query_notauth(query_type* q)
{
    if (!q) {
        return QUERY_DISCARDED;
    }
    ods_log_debug("[%s] notauth", query_str);
    return query_error(q, LDNS_RCODE_NOTAUTH);
}


/**
 * Parse SOA RR in packet.
 * (kind of similar to xfrd_parse_soa)
 *
 */
static int
query_parse_soa(buffer_type* buffer, uint32_t* serial)
{
    ldns_rr_type type = 0;
    ods_log_assert(buffer);
    if (!buffer_available(buffer, 10)) {
        ods_log_error("[%s] bad soa: packet too short", query_str);
        return 0;
    }
    type = (ldns_rr_type) buffer_read_u16(buffer);
    if (type != LDNS_RR_TYPE_SOA) {
        ods_log_error("[%s] bad soa: rr is not soa (%d)", query_str, type);
        return 0;
    }
    (void)buffer_read_u16(buffer);
    (void)buffer_read_u32(buffer);
    /* rdata length */
    if (!buffer_available(buffer, buffer_read_u16(buffer))) {
        ods_log_error("[%s] bad soa: missing rdlength", query_str);
        return 0;
    }
    /* MNAME */
    if (!buffer_skip_dname(buffer)) {
        ods_log_error("[%s] bad soa: missing mname", query_str);
        return 0;
    }
    /* RNAME */
    if (!buffer_skip_dname(buffer)) {
        ods_log_error("[%s] bad soa: missing rname", query_str);
        return 0;
    }
    if (serial) {
        *serial = buffer_read_u32(buffer);
    }
    return 1;
}


/**
 * NOTIFY.
 * Parse notify query and initiate zone transfer if received serial is
 * newer than serial on disk. On success return QUERY_PROCESSED and
 * prepare notify reply packet in q->buffer.
 */
static query_state
query_process_notify(query_type* q, ldns_rr_type qtype, engine_type* engine)
{
    dnsin_type* dnsin = NULL;
    uint16_t count = 0;
    uint16_t rrcount = 0;
    uint32_t serial = 0;
    size_t pos = 0;
    char address[128];
    if (!engine || !q || !q->zone) {
        return QUERY_DISCARDED;
    }
    ods_log_assert(engine->dnshandler);
    ods_log_assert(q->zone->name);
    ods_log_verbose("[%s] incoming notify for zone %s", query_str,
        q->zone->name);
    if (buffer_pkt_rcode(q->buffer) != LDNS_RCODE_NOERROR ||
        buffer_pkt_qr(q->buffer) ||
        !buffer_pkt_aa(q->buffer) ||
        buffer_pkt_tc(q->buffer) ||
        buffer_pkt_rd(q->buffer) ||
        buffer_pkt_ra(q->buffer) ||
        buffer_pkt_ad(q->buffer) ||
        buffer_pkt_cd(q->buffer) ||
        buffer_pkt_qdcount(q->buffer) != 1 ||
        buffer_pkt_ancount(q->buffer) > 1 ||
        qtype != LDNS_RR_TYPE_SOA) {
        return query_formerr(q);
    }
    if (!q->zone->adinbound || q->zone->adinbound->type != ADAPTER_DNS) {
        ods_log_error("[%s] zone %s is not configured to have input dns "
            "adapter", query_str, q->zone->name);
        return query_notauth(q);
    }
    ods_log_assert(q->zone->adinbound->config);
    dnsin = (dnsin_type*) q->zone->adinbound->config;
    if (!acl_find(dnsin->allow_notify, &q->addr, q->tsig_rr)) {
        if (addr2ip(q->addr, address, sizeof(address))) {
            ods_log_info("[%s] unauthorized notify for zone %s from %s: "
                "no acl matches", query_str, q->zone->name, address);
        } else {
            ods_log_info("[%s] unauthorized notify for zone %s from unknown "
                "source: no acl matches", query_str, q->zone->name);
        }
        return query_notauth(q);
    }
    ods_log_assert(q->zone->xfrd);
    /* skip header and question section */
    buffer_skip(q->buffer, BUFFER_PKT_HEADER_SIZE);
    count = buffer_pkt_qdcount(q->buffer);
    for (rrcount = 0; rrcount < count; rrcount++) {
        if (!buffer_skip_rr(q->buffer, 1)) {
            if (addr2ip(q->addr, address, sizeof(address))) {
                ods_log_info("[%s] dropped packet: zone %s received bad "
                    "notify from %s (bad question section)", query_str,
                    q->zone->name, address);
            } else {
                ods_log_info("[%s] dropped packet: zone %s received bad "
                    "notify from unknown source (bad question section)",
                    query_str, q->zone->name);
            }
            return QUERY_DISCARDED;
        }
    }
    pos = buffer_position(q->buffer);

    /* examine answer section */
    count = buffer_pkt_ancount(q->buffer);
    if (count) {
        if (!buffer_skip_dname(q->buffer) ||
            !query_parse_soa(q->buffer, &serial)) {
            if (addr2ip(q->addr, address, sizeof(address))) {
                ods_log_info("[%s] dropped packet: zone %s received bad "
                    "notify from %s (bad soa in answer section)", query_str,
                    q->zone->name, address);
            } else {
                ods_log_info("[%s] dropped packet: zone %s received bad "
                    "notify from unknown source (bad soa in answer section)",
                    query_str, q->zone->name);
            }
            return QUERY_DISCARDED;
        }

        pthread_mutex_lock(&q->zone->xfrd->serial_lock);
        if (!util_serial_gt(serial, q->zone->xfrd->serial_disk)) {
            if (addr2ip(q->addr, address, sizeof(address))) {
                ods_log_info("[%s] ignore notify from %s: already got "
                    "zone %s serial %u on disk (received %u)", query_str,
                    address, q->zone->name, q->zone->xfrd->serial_disk,
                    serial);
            } else {
                ods_log_info("[%s] ignore notify: already got zone %s "
                    "serial %u on disk (received %u)", query_str,
                    q->zone->name, q->zone->xfrd->serial_disk, serial);
            }
            pthread_mutex_unlock(&q->zone->xfrd->serial_lock);
        } else if (q->zone->xfrd->serial_notify_acquired) {
            pthread_mutex_unlock(&q->zone->xfrd->serial_lock);
            if (addr2ip(q->addr, address, sizeof(address))) {
                ods_log_info("[%s] ignore notify from %s: zone %s "
                    "transfer in progress", query_str, address,
                    q->zone->name);
            } else {
                ods_log_info("[%s] ignore notify: zone %s transfer in "
                    "progress", query_str, q->zone->name);
            }
        } else {
            q->zone->xfrd->serial_notify = serial;
            q->zone->xfrd->serial_notify_acquired = time_now();
            pthread_mutex_unlock(&q->zone->xfrd->serial_lock);
            /* forward notify to xfrd */
            if (addr2ip(q->addr, address, sizeof(address))) {
                ods_log_verbose("[%s] forward notify for zone %s from client %s",
                    query_str, q->zone->name, address);
            } else {
                ods_log_verbose("[%s] forward notify for zone %s", query_str,
                    q->zone->name);
            }
            xfrd_set_timer_now(q->zone->xfrd);
            dnshandler_fwd_notify(engine->dnshandler, buffer_begin(q->buffer),
                buffer_remaining(q->buffer));
        }
    } else { /* Empty answer section, no SOA. We still need to process
        the notify according to the RFC */
        /* forward notify to xfrd */
        if (addr2ip(q->addr, address, sizeof(address))) {
            ods_log_verbose("[%s] forward notify for zone %s from client %s",
                query_str, q->zone->name, address);
        } else {
            ods_log_verbose("[%s] forward notify for zone %s", query_str,
                q->zone->name);
        }
        xfrd_set_timer_now(q->zone->xfrd);
        dnshandler_fwd_notify(engine->dnshandler, buffer_begin(q->buffer),
            buffer_remaining(q->buffer));
    }

    /* send notify ok */
    buffer_pkt_set_qr(q->buffer);
    buffer_pkt_set_aa(q->buffer);
    buffer_pkt_set_ancount(q->buffer, 0);

    buffer_clear(q->buffer); /* lim = pos, pos = 0; */
    buffer_set_position(q->buffer, pos);
    buffer_set_limit(q->buffer, buffer_capacity(q->buffer));
    q->reserved_space = edns_rr_reserved_space(q->edns_rr);
    q->reserved_space += tsig_rr_reserved_space(q->tsig_rr);
    return QUERY_PROCESSED;
}


/**
 * IXFR.
 *
 */
static query_state
query_process_ixfr(query_type* q)
{
    uint16_t count = 0;
    ods_log_assert(q);
    ods_log_assert(q->buffer);
    ods_log_assert(buffer_pkt_qdcount(q->buffer) == 1);
    /* skip header and question section */
    buffer_skip(q->buffer, BUFFER_PKT_HEADER_SIZE);
    if (!buffer_skip_rr(q->buffer, 1)) {
        ods_log_error("[%s] dropped packet: zone %s received bad ixfr "
            "request (bad question section)", query_str, q->zone->name);
        return QUERY_DISCARDED;
    }
    /* answer section is empty */
    ods_log_assert(buffer_pkt_ancount(q->buffer) == 0);
    /* examine auth section */
    q->startpos = buffer_position(q->buffer);
    count = buffer_pkt_nscount(q->buffer);
    if (count) {
        if (!buffer_skip_dname(q->buffer) ||
            !query_parse_soa(q->buffer, &(q->serial))) {
            ods_log_error("[%s] dropped packet: zone %s received bad ixfr "
                "request (bad soa in auth section)", query_str, q->zone->name);
            return QUERY_DISCARDED;
        }
        ods_log_debug("[%s] found ixfr request zone %s serial=%u", query_str,
            q->zone->name, q->serial);
        return QUERY_PROCESSED;
    }
    ods_log_debug("[%s] ixfr request zone %s has no auth section", query_str,
        q->zone->name);
    q->serial = 0;
    return QUERY_PROCESSED;
}


/**
 * Encode RR.
 *
 */
static int
response_encode_rr(query_type* q, ldns_rr* rr, ldns_pkt_section section)
{
    uint8_t *data = NULL;
    size_t size = 0;
    ldns_status status = LDNS_STATUS_OK;
    ods_log_assert(q);
    ods_log_assert(rr);
    ods_log_assert(section);
    status = ldns_rr2wire(&data, rr, section, &size);
    if (status != LDNS_STATUS_OK) {
        ods_log_error("[%s] unable to send good response: ldns_rr2wire() "
            "failed (%s)", query_str, ldns_get_errorstr_by_id(status));
        return 0;
    }
    buffer_write(q->buffer, (const void*) data, size);
    LDNS_FREE(data);
    return 1;
}


/**
 * Encode RRset.
 *
 */
static uint16_t
response_encode_rrset(query_type* q, ldns_rr_list* rrs, ldns_rr_list* rrsigs, ldns_pkt_section section)
{
    ldns_rr* rr;
    uint16_t added = 0;
    ods_log_assert(q);
    ods_log_assert(section);

    while((rr = ldns_rr_list_pop_rr(rrs))) {
        added += response_encode_rr(q, rr, section);
    }
    if (q->edns_rr && q->edns_rr->dnssec_ok) {
        while((rr = ldns_rr_list_pop_rr(rrsigs))) {
            added += response_encode_rr(q, rr, section);
        }
    }
    /* truncation? */
    return added;
}

/**
 * Encode response.
 *
 */
static void
response_encode(query_type* q, response_type* r)
{
    ods_log_assert(q);
    ods_log_assert(r);
    uint16_t answercount;
    uint16_t authoritycount;
    uint16_t additionalcount;
    answercount = response_encode_rrset(q, r->answersection, r->answersectionsigs, LDNS_SECTION_ANSWER);
    authoritycount = response_encode_rrset(q, r->authoritysection, r->authoritysectionsigs, LDNS_SECTION_ANSWER);
    additionalcount = response_encode_rrset(q, r->additionalsection, r->additionalsectionsigs, LDNS_SECTION_ANSWER);
    buffer_pkt_set_ancount(q->buffer, answercount);
    buffer_pkt_set_nscount(q->buffer, authoritycount);
    buffer_pkt_set_arcount(q->buffer, additionalcount);
    buffer_pkt_set_qr(q->buffer);
    buffer_pkt_set_aa(q->buffer);
}

/**
 * Query response.
 *
 */
static query_state
query_response(names_view_type view, query_type* q, ldns_rr_type qtype)
{
    
    response_type r;
    if (!q || !q->zone) {
        return QUERY_DISCARDED;
    }
    r.answersection = ldns_rr_list_new();
    r.answersectionsigs = ldns_rr_list_new();
    r.authoritysection = ldns_rr_list_new();
    r.authoritysectionsigs = ldns_rr_list_new();
    r.additionalsection = ldns_rr_list_new();
    r.additionalsectionsigs =  ldns_rr_list_new();
    names_viewlookupall(view, NULL, qtype, &r.answersection, &r.answersectionsigs);
    if (r.answersection) {
        /* NS RRset goes into Authority Section */
        names_viewlookupall(view, NULL, LDNS_RR_TYPE_NS, &r.authoritysection, &r.authoritysectionsigs);
        /* not having NS RRs is not fatal  */
    } else if (qtype != LDNS_RR_TYPE_SOA) {
        names_viewlookupall(view, NULL, LDNS_RR_TYPE_SOA, &r.authoritysection, &r.authoritysectionsigs);
    } else {
        return query_servfail(q);
    }
    response_encode(q, &r);
    ldns_rr_list_deep_free(r.answersection);
    ldns_rr_list_deep_free(r.answersectionsigs);
    ldns_rr_list_deep_free(r.authoritysection);
    ldns_rr_list_deep_free(r.authoritysectionsigs);
    ldns_rr_list_deep_free(r.answersection);
    ldns_rr_list_deep_free(r.answersectionsigs);
    /* compression */
    return QUERY_PROCESSED;
}


/**
 * Prepare response.
 *
 */
void
query_prepare(query_type* q)
{
    uint16_t limit = 0;
    uint16_t flags = 0;
    ods_log_assert(q);
    ods_log_assert(q->buffer);
    limit = buffer_limit(q->buffer);
    flags = buffer_pkt_flags(q->buffer);
    flags &= 0x0100U; /* preserve the rd flag */
    flags |= 0x8000U; /* set the qr flag */
    buffer_pkt_set_flags(q->buffer, flags);
    buffer_clear(q->buffer);
    buffer_set_position(q->buffer, limit);
    buffer_set_limit(q->buffer, buffer_capacity(q->buffer));
    q->reserved_space = edns_rr_reserved_space(q->edns_rr);
    q->reserved_space += tsig_rr_reserved_space(q->tsig_rr);
}


/**
 * QUERY.
 *
 */
static query_state
query_process_query(query_type* q, ldns_rr_type qtype, engine_type* engine)
{
    query_state returnstate;
    names_view_type view;
    dnsout_type* dnsout = NULL;
    if (!q || !q->zone) {
        return QUERY_DISCARDED;
    }
    ods_log_assert(q->zone->name);
    /* sanity checks */
    if (buffer_pkt_qdcount(q->buffer) != 1 || buffer_pkt_tc(q->buffer)) {
        buffer_pkt_set_flags(q->buffer, 0);
        return query_formerr(q);
    }
    if (buffer_pkt_ancount(q->buffer) != 0 ||
        (qtype != LDNS_RR_TYPE_IXFR && buffer_pkt_nscount(q->buffer) != 0)) {
        buffer_pkt_set_flags(q->buffer, 0);
        return query_formerr(q);
    }
    /* acl */
    if (!q->zone->adoutbound || q->zone->adoutbound->type != ADAPTER_DNS) {
        ods_log_error("[%s] zone %s is not configured to have output dns "
            "adapter", query_str, q->zone->name);
        return query_refused(q);
    }
    ods_log_assert(q->zone->adoutbound->config);
    dnsout = (dnsout_type*) q->zone->adoutbound->config;
    /* acl also in use for soa and other queries */
    if (!acl_find(dnsout->provide_xfr, &q->addr, q->tsig_rr)) {
        ods_log_debug("[%s] zone %s acl query refused", query_str,
            q->zone->name);
        return query_refused(q);
    }

    query_prepare(q);
    /* ixfr? */
    if (qtype == LDNS_RR_TYPE_IXFR) {
        ods_log_assert(q->zone->name);
        ods_log_debug("[%s] incoming ixfr request serial=%u for zone %s",
            query_str, q->serial, q->zone->name);
        return ixfr(q, engine);
    }
    /* axfr? */
    if (qtype == LDNS_RR_TYPE_AXFR) {
        ods_log_assert(q->zone->name);
        ods_log_debug("[%s] incoming axfr request for zone %s",
            query_str, q->zone->name);
        return axfr(q, engine, 0);
    }
    /* (soa) query */
    if (qtype == LDNS_RR_TYPE_SOA) {
        ods_log_assert(q->zone->name);
        ods_log_debug("[%s] incoming soa request for zone %s",
            query_str, q->zone->name);
        return soa_request(q, engine);
    }
    /* other qtypes */
    view = zonelist_obtainresource(NULL, q->zone, NULL, offsetof(zone_type,outputview));
    names_viewreset(view);
    returnstate = query_response(view, q, qtype);
    zonelist_releaseresource(NULL, q->zone, NULL, offsetof(zone_type,outputview), view);
    return returnstate;
}


/**
 * UPDATE.
 *
 */
static query_state
query_process_update(query_type* q)
{
    if (!q || !q->zone) {
        return QUERY_DISCARDED;
    }
    ods_log_debug("[%s] dynamic update not implemented", query_str);
    return query_notimpl(q);
}


/**
 * Process TSIG RR.
 *
 */
static ldns_pkt_rcode
query_process_tsig(query_type* q)
{
    if (!q || !q->tsig_rr) {
        return LDNS_RCODE_SERVFAIL;
    }
    if (q->tsig_rr->status == TSIG_ERROR) {
        return LDNS_RCODE_FORMERR;
    }
    if (q->tsig_rr->status == TSIG_OK) {
        if (!tsig_rr_lookup(q->tsig_rr)) {
            ods_log_debug("[%s] tsig unknown key/algorithm", query_str);
            return LDNS_RCODE_REFUSED;
        }
        buffer_set_limit(q->buffer, q->tsig_rr->position);
        buffer_pkt_set_arcount(q->buffer, buffer_pkt_arcount(q->buffer)-1);
        tsig_rr_prepare(q->tsig_rr);
        tsig_rr_update(q->tsig_rr, q->buffer, buffer_limit(q->buffer));
        if (!tsig_rr_verify(q->tsig_rr)) {
            ods_log_debug("[%s] bad tsig signature", query_str);
            return LDNS_RCODE_NOTAUTH;
        }
    }
    return LDNS_RCODE_NOERROR;
}


/**
 * Process EDNS OPT RR.
 *
 */
static ldns_pkt_rcode
query_process_edns(query_type* q)
{
    if (!q || !q->edns_rr) {
        return LDNS_RCODE_SERVFAIL;
    }
    if (q->edns_rr->status == EDNS_ERROR) {
        /* The only error is VERSION not implemented */
        return LDNS_RCODE_FORMERR;
    }
    if (q->edns_rr->status == EDNS_OK) {
        /* Only care about UDP size larger than normal... */
        if (!q->tcp && q->edns_rr->maxlen > UDP_MAX_MESSAGE_LEN) {
            if (q->edns_rr->maxlen < EDNS_MAX_MESSAGE_LEN) {
                q->maxlen = q->edns_rr->maxlen;
            } else {
                q->maxlen = EDNS_MAX_MESSAGE_LEN;
            }
        }
        /* Strip the OPT resource record off... */
        buffer_set_position(q->buffer, q->edns_rr->position);
        buffer_set_limit(q->buffer, q->edns_rr->position);
        buffer_pkt_set_arcount(q->buffer, buffer_pkt_arcount(q->buffer) - 1);
    }
    return LDNS_RCODE_NOERROR;
}


/**
 * Find TSIG RR.
 *
 */
static int
query_find_tsig(query_type* q)
{
    size_t saved_pos = 0;
    size_t rrcount = 0;
    size_t i = 0;

    ods_log_assert(q);
    ods_log_assert(q->tsig_rr);
    ods_log_assert(q->buffer);
    if (buffer_pkt_arcount(q->buffer) == 0) {
        q->tsig_rr->status = TSIG_NOT_PRESENT;
        return 1;
    }
    saved_pos = buffer_position(q->buffer);
    rrcount = buffer_pkt_qdcount(q->buffer) + buffer_pkt_ancount(q->buffer) +
        buffer_pkt_nscount(q->buffer);
    buffer_set_position(q->buffer, BUFFER_PKT_HEADER_SIZE);
    for (i=0; i < rrcount; i++) {
        if (!buffer_skip_rr(q->buffer, i < buffer_pkt_qdcount(q->buffer))) {
             buffer_set_position(q->buffer, saved_pos);
             return 0;
        }
    }

    rrcount = buffer_pkt_arcount(q->buffer);
    ods_log_assert(rrcount != 0);
    if (!tsig_rr_parse(q->tsig_rr, q->buffer)) {
        ods_log_debug("[%s] got bad tsig", query_str);
        return 0;
    }
    if (q->tsig_rr->status != TSIG_NOT_PRESENT) {
        --rrcount;
    }
    if (rrcount) {
        if (edns_rr_parse(q->edns_rr, q->buffer)) {
            --rrcount;
        }
    }
    if (rrcount && q->tsig_rr->status == TSIG_NOT_PRESENT) {
        /* see if tsig is after the edns record */
        if (!tsig_rr_parse(q->tsig_rr, q->buffer)) {
            ods_log_debug("[%s] got bad tsig", query_str);
            return 0;
        }
        if (q->tsig_rr->status != TSIG_NOT_PRESENT) {
            --rrcount;
        }
    }
    if (rrcount > 0) {
        ods_log_debug("[%s] too many additional rrs", query_str);
        return 0;
    }
    buffer_set_position(q->buffer, saved_pos);
    return 1;
}


/**
 * Process query.
 *
 */
query_state
query_process(query_type* q, engine_type* engine)
{
    ldns_status status = LDNS_STATUS_OK;
    ldns_pkt* pkt = NULL;
    ldns_rr* rr = NULL;
    ldns_pkt_rcode rcode = LDNS_RCODE_NOERROR;
    ldns_pkt_opcode opcode = LDNS_PACKET_QUERY;
    ldns_rr_type qtype = LDNS_RR_TYPE_SOA;
    ods_log_assert(engine);
    ods_log_assert(q);
    ods_log_assert(q->buffer);
    if (buffer_limit(q->buffer) < BUFFER_PKT_HEADER_SIZE) {
        ods_log_debug("[%s] drop query: packet too small", query_str);
        return QUERY_DISCARDED; /* too small */
    }
    if (buffer_pkt_qr(q->buffer)) {
        ods_log_debug("[%s] drop query: qr bit set", query_str);
        return QUERY_DISCARDED; /* not a query */
    }
    /* parse packet */
    status = ldns_wire2pkt(&pkt, buffer_current(q->buffer),
        buffer_remaining(q->buffer));
    if (status != LDNS_STATUS_OK) {
        ods_log_debug("[%s] got bad packet: %s", query_str,
            ldns_get_errorstr_by_id(status));
        return query_formerr(q);
    }
    rr = ldns_rr_list_rr(ldns_pkt_question(pkt), 0);
    if (!rr) {
        ods_log_debug("[%s] no RRset in query section, ignoring", query_str);
        return QUERY_DISCARDED; /* no RRset in query */
    }
    pthread_mutex_lock(&engine->zonelist->zl_lock);
    /* we can just lookup the zone, because we will only handle SOA queries,
       zone transfers, updates and notifies */
    q->zone = zonelist_lookup_zone_by_dname(engine->zonelist, ldns_rr_owner(rr),
        ldns_rr_get_class(rr));
    /* don't answer for zones that are just added */
    if (q->zone && q->zone->zl_status == ZONE_ZL_ADDED) {
        ods_log_assert(q->zone->name);
        ods_log_warning("[%s] zone %s just added, don't answer for now",
            query_str, q->zone->name);
        q->zone = NULL;
    }
    pthread_mutex_unlock(&engine->zonelist->zl_lock);
    if (!q->zone) {
	char *zn = ldns_rdf2str(ldns_rr_owner(rr));
	if (zn) {
            ods_log_debug("[%s] zone %s not found", query_str, zn);
	} else {
            ods_log_debug("[%s] zone (unknown?) not found", query_str);
	}
        return query_servfail(q);
    }
    /* see if it is tsig signed */
    if (!query_find_tsig(q)) {
        return query_formerr(q);
    }
    /* else: valid tsig, or no tsig present */
    ods_log_debug("[%s] tsig %s", query_str, tsig_status2str(q->tsig_rr->status));
    /* get opcode, qtype, ixfr=serial */
    opcode = ldns_pkt_get_opcode(pkt);
    qtype = ldns_rr_get_type(rr);
    if (qtype == LDNS_RR_TYPE_IXFR) {
        ods_log_assert(q->zone->name);
        ods_log_debug("[%s] incoming ixfr request for zone %s",
            query_str, q->zone->name);
        if (query_process_ixfr(q) != QUERY_PROCESSED) {
            return query_formerr(q);
        }
    }
    /* process tsig */
    rcode = query_process_tsig(q);
    if (rcode != LDNS_RCODE_NOERROR) {
        return query_error(q, rcode);
    }
    /* process edns */
    rcode = query_process_edns(q);
    if (rcode != LDNS_RCODE_NOERROR) {
        /* We should not return FORMERR, but BADVERS (=16).
         * BADVERS is created with Ext. RCODE, followed by RCODE.
         * Ext. RCODE is set to 1, RCODE must be 0 (getting 0x10 = 16).
         * Thus RCODE = NOERROR = NSD_RC_OK. */
        return query_error(q, LDNS_RCODE_NOERROR);
    }
    /* handle incoming request */
    ldns_pkt_free(pkt);
    switch (opcode) {
        case LDNS_PACKET_NOTIFY:
            return query_process_notify(q, qtype, engine);
        case LDNS_PACKET_QUERY:
            return query_process_query(q, qtype, engine);
        case LDNS_PACKET_UPDATE:
            return query_process_update(q);
        default:
            break;
    }
    return query_notimpl(q);
}


/**
 * Check if query does not overflow.
 *
 */
static int
query_overflow(query_type* q)
{
    ods_log_assert(q);
    ods_log_assert(q->buffer);
    return buffer_position(q->buffer) > (q->maxlen - q->reserved_space);
}


/**
 * Add optional RRs to query.
 *
 */
void
query_add_optional(query_type* q, engine_type* engine)
{
    edns_data_type* edns = NULL;
    if (!q || !engine) {
        return;
    }
    /** First EDNS */
    if (q->edns_rr) {
        edns = &engine->edns;
        switch (q->edns_rr->status) {
            case EDNS_NOT_PRESENT:
                break;
            case EDNS_OK:
                ods_log_debug("[%s] add edns opt ok", query_str);
                if (q->edns_rr->dnssec_ok) {
                    edns->ok[7] = 0x80;
                } else {
                    edns->ok[7] = 0x00;
                }
                buffer_write(q->buffer, edns->ok, OPT_LEN);
                /* fill with NULLs */
                buffer_write(q->buffer, edns->rdata_none, OPT_RDATA);
                buffer_pkt_set_arcount(q->buffer,
                    buffer_pkt_arcount(q->buffer) + 1);
                break;
            case EDNS_ERROR:
                ods_log_debug("[%s] add edns opt err", query_str);
                if (q->edns_rr->dnssec_ok) {
                    edns->ok[7] = 0x80;
                } else {
                    edns->ok[7] = 0x00;
                }
                buffer_write(q->buffer, edns->error, OPT_LEN);
                buffer_write(q->buffer, edns->rdata_none, OPT_RDATA);
                buffer_pkt_set_arcount(q->buffer,
                    buffer_pkt_arcount(q->buffer) + 1);
                break;
            default:
                break;
        }
    }

    /** Then TSIG */
    if (!q->tsig_rr) {
        return;
    }
    if (q->tsig_rr->status != TSIG_NOT_PRESENT) {

         if (q->tsig_rr->status == TSIG_ERROR ||
             q->tsig_rr->error_code != LDNS_RCODE_NOERROR) {
             ods_log_debug("[%s] add tsig err", query_str);
             tsig_rr_error(q->tsig_rr);
             tsig_rr_append(q->tsig_rr, q->buffer);
             buffer_pkt_set_arcount(q->buffer,
                 buffer_pkt_arcount(q->buffer)+1);
         } else if (q->tsig_rr->status == TSIG_OK &&
             q->tsig_rr->error_code == LDNS_RCODE_NOERROR) {
             ods_log_debug("[%s] add tsig ok", query_str);
             if (q->tsig_prepare_it)
                 tsig_rr_prepare(q->tsig_rr);
             if (q->tsig_update_it)
                 tsig_rr_update(q->tsig_rr, q->buffer,
                     buffer_position(q->buffer));
             if (q->tsig_sign_it) {
                 tsig_rr_sign(q->tsig_rr);
                 tsig_rr_append(q->tsig_rr, q->buffer);
                 buffer_pkt_set_arcount(q->buffer,
                     buffer_pkt_arcount(q->buffer)+1);
             }
        }
    }
}


/**
 * Add RR to query.
 *
 */
int
query_add_rr(query_type* q, ldns_rr* rr)
{
    size_t i = 0;
    size_t tc_mark = 0;
    size_t rdlength_pos = 0;
    uint16_t rdlength = 0;

    ods_log_assert(q);
    ods_log_assert(q->buffer);
    ods_log_assert(rr);

    /* set truncation mark, in case rr does not fit */
    tc_mark = buffer_position(q->buffer);
    /* owner type class ttl */
    if (!buffer_available(q->buffer, ldns_rdf_size(ldns_rr_owner(rr)))) {
        goto query_add_rr_tc;
    }
    buffer_write_rdf(q->buffer, ldns_rr_owner(rr));
    if (!buffer_available(q->buffer, sizeof(uint16_t) + sizeof(uint16_t) +
        sizeof(uint32_t) + sizeof(rdlength))) {
        goto query_add_rr_tc;
    }
    buffer_write_u16(q->buffer, (uint16_t) ldns_rr_get_type(rr));
    buffer_write_u16(q->buffer, (uint16_t) ldns_rr_get_class(rr));
    buffer_write_u32(q->buffer, (uint32_t) ldns_rr_ttl(rr));
    /* skip rdlength */
    rdlength_pos = buffer_position(q->buffer);
    buffer_skip(q->buffer, sizeof(rdlength));
    /* write rdata */
    for (i=0; i < ldns_rr_rd_count(rr); i++) {
        if (!buffer_available(q->buffer, ldns_rdf_size(ldns_rr_rdf(rr, i)))) {
            goto query_add_rr_tc;
        }
        buffer_write_rdf(q->buffer, ldns_rr_rdf(rr, i));
    }

    if (!query_overflow(q)) {
        /* write rdlength */
        rdlength = buffer_position(q->buffer) - rdlength_pos - sizeof(rdlength);
        buffer_write_u16_at(q->buffer, rdlength_pos, rdlength);
        /* position updated by buffer_write() */
        return 1;
    }

query_add_rr_tc:
    buffer_set_position(q->buffer, tc_mark);
    ods_log_assert(!query_overflow(q));
    return 0;

}


/**
 * Cleanup query.
 *
 */
void
query_cleanup(query_type* q)
{
    if (!q) {
        return;
    }
    if (q->axfr_fd) {
        ods_fclose(q->axfr_fd);
        q->axfr_fd = NULL;
    }
    buffer_cleanup(q->buffer);
    tsig_rr_cleanup(q->tsig_rr);
    edns_rr_cleanup(q->edns_rr);
    free(q);
}
