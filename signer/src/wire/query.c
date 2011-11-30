/*
 * $Id: query.c 4958 2011-04-18 07:11:09Z matthijs $
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
 * Query.
 *
 */

#include "config.h"
#include "daemon/dnshandler.h"
#include "daemon/engine.h"
#include "shared/util.h"
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
    allocator_type* allocator = NULL;
    query_type* q = NULL;
    allocator = allocator_create(malloc, free);
    if (!allocator) {
        return NULL;
    }
    q = (query_type*) allocator_alloc(allocator, sizeof(query_type));
    if (!q) {
        allocator_cleanup(allocator);
        return NULL;
    }
    q->allocator = allocator;
    q->buffer = NULL;
    q->tsig_rr = NULL;
    q->buffer = buffer_create(allocator, PACKET_BUFFER_SIZE);
    if (!q->buffer) {
        query_cleanup(q);
        return NULL;
    }
    q->tsig_rr = tsig_rr_create(allocator);
    if (!q->tsig_rr) {
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
    q->tsig_prepare_it = 1;
    q->tsig_update_it = 1;
    q->tsig_sign_it = 1;
    q->tcp = is_tcp;
    q->tcplen = 0;
    /* qname, qtype, qclass */
    q->zone = NULL;
    /* domain, opcode, cname count, delegation, compression, temp */
    q->axfr_is_done = 0;
    q->axfr_fd = NULL;
    return;
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
 * Parse SOA RR in packet.
 * (kind of similar to xfrd_parse_soa)
 *
 */
static int
query_parse_soa(buffer_type* buffer, uint32_t* serial)
{
    ldns_rr_type type = 0;
    ldns_rr_class klass = 0;
    uint32_t tmp = 0;
    ods_log_assert(buffer);

    if (!buffer_available(buffer, 10)) {
        ods_log_error("[%s] bad notify: packet too short", query_str);
        return 0;
    }
    type = (ldns_rr_type) buffer_read_u16(buffer);
    if (type != LDNS_RR_TYPE_SOA) {
        ods_log_error("[%s] bad notify: rr in answer section is not soa (%d)",
            query_str, type);
        return 0;
    }
    klass = (ldns_rr_class) buffer_read_u16(buffer);
    tmp = buffer_read_u32(buffer);
    /* rdata length */
    if (!buffer_available(buffer, buffer_read_u16(buffer))) {
        ods_log_error("[%s] bad notify: soa missing rdlength", query_str);
        return 0;
    }
    /* MNAME */
    if (!buffer_skip_dname(buffer)) {
        ods_log_error("[%s] bad notify: soa missing mname", query_str);
        return 0;
    }
    /* RNAME */
    if (!buffer_skip_dname(buffer)) {
        ods_log_error("[%s] bad notify: soa missing rname", query_str);
        return 0;
    }
    if (serial) {
        *serial = buffer_read_u32(buffer);
    }
    return 1;
}


/**
 * NOTIFY.
 *
 */
static query_state
query_process_notify(query_type* q, ldns_rr_type qtype, void* engine)
{
    engine_type* e = (engine_type*) engine;
    dnsin_type* dnsin = NULL;
    uint16_t count = 0;
    uint16_t rrcount = 0;
    uint32_t serial = 0;
    size_t limit = 0;
    size_t curpos = 0;
    char address[128];
    if (!e || !q || !q->zone) {
        return QUERY_DISCARDED;
    }
    ods_log_assert(e->dnshandler);
    ods_log_assert(q->zone->name);
    ods_log_debug("[%s] incoming notify for zone %s", query_str,
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
        return query_refused(q);
    }
    ods_log_assert(q->zone->adinbound->config);
    dnsin = (dnsin_type*) q->zone->adinbound->config;
    if (!acl_find(dnsin->allow_notify, &q->addr, q->tsig_rr)) {
        if (addr2ip(q->addr, address, sizeof(address))) {
            ods_log_info("[%s] notify for zone %s from client %s refused: no "
                "acl matches", query_str, q->zone->name, address);
        } else {
            ods_log_info("[%s] notify for zone %s from unknown client "
                "refused: no acl matches", query_str, q->zone->name);
        }
        return query_refused(q);
    }
    limit = buffer_limit(q->buffer);
    curpos = buffer_position(q->buffer);
    ods_log_assert(q->zone->xfrd);
    /* skip header and question section */
    buffer_skip(q->buffer, BUFFER_PKT_HEADER_SIZE);
    count = buffer_pkt_qdcount(q->buffer);
    for (rrcount = 0; rrcount < count; rrcount++) {
        if (!buffer_skip_rr(q->buffer, 1)) {
            ods_log_error("[%s] dropped packet: zone %s received bad notify "
                "(bad question section)", query_str, q->zone->name);
            return QUERY_DISCARDED;
        }
    }
    /* examine answer section */
    count = buffer_pkt_ancount(q->buffer);
    if (count) {
        if (!buffer_skip_dname(q->buffer) ||
            !query_parse_soa(q->buffer, &serial)) {
            ods_log_error("[%s] dropped packet: zone %s received bad notify "
                "(bad soa in answer section)", query_str, q->zone->name);
            return QUERY_DISCARDED;
        }
        lock_basic_lock(&q->zone->xfrd->serial_lock);
        q->zone->xfrd->serial_notify = serial;
        q->zone->xfrd->serial_notify_acquired = time_now();
        if (!util_serial_gt(q->zone->xfrd->serial_notify,
            q->zone->xfrd->serial_disk)) {
            ods_log_debug("[%s] ignore notify: already got zone %s serial "
                "%u on disk", query_str, q->zone->name,
                q->zone->xfrd->serial_notify);
            lock_basic_unlock(&q->zone->xfrd->serial_lock);
            goto send_notify_ok;
        }
        lock_basic_unlock(&q->zone->xfrd->serial_lock);
    } else {
        lock_basic_lock(&q->zone->xfrd->serial_lock);
        q->zone->xfrd->serial_notify = 0;
        q->zone->xfrd->serial_notify_acquired = 0;
        lock_basic_unlock(&q->zone->xfrd->serial_lock);
    }
    /* forward notify to xfrd */
    xfrd_set_timer_now(q->zone->xfrd);
    dnshandler_fwd_notify(e->dnshandler, buffer_begin(q->buffer),
        buffer_remaining(q->buffer));

send_notify_ok:
    /* send notify ok */
    buffer_pkt_set_qr(q->buffer);
    buffer_pkt_set_aa(q->buffer);
    buffer_pkt_set_ancount(q->buffer, 0);
    buffer_clear(q->buffer);
    buffer_set_position(q->buffer, limit);
    return QUERY_PROCESSED;
}


/**
 * Add RRset to response.
 *
 */
static int
response_add_rrset(response_type* r, rrset_type* rrset,
    ldns_pkt_section section)
{
    if (!r || !rrset || !section) {
        return 0;
    }
    /* duplicates? */
    r->sections[r->rrset_count] = section;
    r->rrsets[r->rrset_count] = rrset;
    ++r->rrset_count;
    return 1;
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
response_encode_rrset(query_type* q, rrset_type* rrset,
    ldns_pkt_section section)
{
    uint16_t i = 0;
    uint16_t added = 0;
    ods_log_assert(q);
    ods_log_assert(rrset);
    ods_log_assert(section);

    for (i = 0; i < rrset->rr_count; i++) {
        added += response_encode_rr(q, rrset->rrs[i].rr, section);
    }
    for (i = 0; i < rrset->rrsig_count; i++) {
        added += response_encode_rr(q, rrset->rrsigs[i].rr, section);
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
    uint16_t counts[LDNS_SECTION_ANY];
    ldns_pkt_section s = LDNS_SECTION_QUESTION;
    size_t i = 0;
    ods_log_assert(q);
    ods_log_assert(r);
    for (s = LDNS_SECTION_ANSWER; s < LDNS_SECTION_ANY; s++) {
        counts[s] = 0;
    }
    for (s = LDNS_SECTION_ANSWER; s < LDNS_SECTION_ANY; s++) {
        for (i = 0; i < r->rrset_count; i++) {
            if (r->sections[i] == s) {
                counts[s] += response_encode_rrset(q, r->rrsets[i], s);
            }
        }
    }
    buffer_pkt_set_ancount(q->buffer, counts[LDNS_SECTION_ANSWER]);
    buffer_pkt_set_nscount(q->buffer, counts[LDNS_SECTION_AUTHORITY]);
    buffer_pkt_set_arcount(q->buffer, counts[LDNS_SECTION_ADDITIONAL]);
    return;
}


/**
 * Query response.
 *
 */
static query_state
query_response(query_type* q, ldns_rr_type qtype)
{
    rrset_type* rrset = NULL;
    response_type r;
    if (!q || !q->zone) {
        return QUERY_DISCARDED;
    }
    r.rrset_count = 0;
    lock_basic_lock(&q->zone->zone_lock);
    rrset = zone_lookup_rrset(q->zone, q->zone->apex, qtype);
    if (rrset) {
        if (!response_add_rrset(&r, rrset, LDNS_SECTION_ANSWER)) {
            lock_basic_unlock(&q->zone->zone_lock);
            return query_servfail(q);
        }
        /* NS RRset goes into Authority Section */
        rrset = zone_lookup_rrset(q->zone, q->zone->apex, LDNS_RR_TYPE_NS);
        if (rrset) {
            if (!response_add_rrset(&r, rrset, LDNS_SECTION_AUTHORITY)) {
                lock_basic_unlock(&q->zone->zone_lock);
                return query_servfail(q);
            }
        }
    } else if (qtype != LDNS_RR_TYPE_SOA) {
        rrset = zone_lookup_rrset(q->zone, q->zone->apex, LDNS_RR_TYPE_SOA);
        if (rrset) {
            if (!response_add_rrset(&r, rrset, LDNS_SECTION_AUTHORITY)) {
                lock_basic_unlock(&q->zone->zone_lock);
                return query_servfail(q);
            }
        }
    } else {
        lock_basic_unlock(&q->zone->zone_lock);
        return query_servfail(q);
    }
    lock_basic_unlock(&q->zone->zone_lock);

    response_encode(q, &r);
    /* compression */
    return QUERY_PROCESSED;
}


/**
 * QUERY.
 *
 */
static query_state
query_process_query(query_type* q, ldns_rr_type qtype, engine_type* engine)
{
    dnsout_type* dnsout = NULL;
    uint16_t limit = 0;
    uint16_t flags = 0;
    if (!q || !q->zone) {
        return QUERY_DISCARDED;
    }
    ods_log_assert(q->zone->name);
    ods_log_debug("[%s] incoming query qtype=%s for zone %s", query_str,
        rrset_type2str(qtype), q->zone->name);
    /* sanity checks */
    if (buffer_pkt_qdcount(q->buffer) != 1 || buffer_pkt_tc(q->buffer)) {
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
        return query_refused(q);
    }
    /* ixfr? */
    if (qtype == LDNS_RR_TYPE_IXFR || qtype == LDNS_RR_TYPE_AXFR) {
        ods_log_assert(q->zone->name);
        ods_log_debug("[%s] incoming ixfr request for zone %s",
            query_str, q->zone->name);
        return query_notimpl(q);
    }
    /* prepare */
    limit = buffer_limit(q->buffer);
    flags = buffer_pkt_flags(q->buffer);
    flags &= 0x0100U; /* preserve the rd flag */
    flags |= 0x8000U; /* set the qr flag */
    buffer_pkt_set_flags(q->buffer, flags);
    buffer_clear(q->buffer);
    buffer_set_position(q->buffer, limit);
    /* axfr? */
    if (qtype == LDNS_RR_TYPE_AXFR) {
        ods_log_assert(q->zone->name);
        ods_log_debug("[%s] incoming axfr request for zone %s",
            query_str, q->zone->name);
        return query_notimpl(q);
    }
    /* (soa) query */
    return query_response(q, qtype);
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
            return LDNS_RCODE_REFUSED;
        }
    }
    return LDNS_RCODE_NOERROR;
}


/**
 * Process query.
 *
 */
query_state
query_process(query_type* q, void* engine)
{
    ldns_status status = LDNS_STATUS_OK;
    ldns_pkt* pkt = NULL;
    ldns_rr* rr = NULL;
    ldns_pkt_rcode rcode = LDNS_RCODE_NOERROR;
    ldns_pkt_opcode opcode = LDNS_PACKET_QUERY;
    ldns_rr_type qtype = LDNS_RR_TYPE_SOA;
    engine_type* e = (engine_type*) engine;
    ods_log_assert(e);
    ods_log_assert(q);
    ods_log_assert(q->buffer);
    if (!e || !q || !q->buffer) {
        ods_log_error("[%s] drop query: assertion error", query_str);
        return QUERY_DISCARDED; /* should not happen */
    }
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
    lock_basic_lock(&e->zonelist->zl_lock);
    /* we can just lookup the zone, because we will only handle SOA queries,
       zone transfers, updates and notifies */
    q->zone = zonelist_lookup_zone_by_dname(e->zonelist, ldns_rr_owner(rr),
        ldns_rr_get_class(rr));
    /* don't answer for zones that are just added */
    if (q->zone && q->zone->zl_status == ZONE_ZL_ADDED) {
        q->zone = NULL;
    }
    lock_basic_unlock(&e->zonelist->zl_lock);
    if (!q->zone) {
        ods_log_debug("[%s] zone not found", query_str);
        return query_servfail(q);
    }
    /* see if it is tsig signed */
    if (!tsig_rr_find(q->tsig_rr, q->buffer)) {
        ods_log_debug("[%s] got bad tsig", query_str);
        return query_formerr(q);
    }
    /* process tsig */
    ods_log_debug("[%s] tsig %s", query_str, tsig_strerror(q->tsig_rr->status));
    rcode = query_process_tsig(q);
    if (rcode != LDNS_RCODE_NOERROR) {
        return query_error(q, rcode);
    }
    /* handle incoming request */
    opcode = ldns_pkt_get_opcode(pkt);
    qtype = ldns_rr_get_type(rr);
    ldns_pkt_free(pkt);
    switch(opcode) {
        case LDNS_PACKET_NOTIFY:
            return query_process_notify(q, qtype, engine);
        case LDNS_PACKET_QUERY:
            return query_process_query(q, qtype, engine);
        case LDNS_PACKET_UPDATE:
            return query_process_update(q);
        default:
            return query_notimpl(q);
    }
    return query_notimpl(q);
}


/**
 * Add TSIG to query.
 *
 */
void
query_add_tsig(query_type* q)
{
    if (!q || !q->tsig_rr) {
        return;
    }
    if (q->tsig_rr->status != TSIG_NOT_PRESENT) {
         if (q->tsig_rr->status == TSIG_ERROR ||
             q->tsig_rr->error_code != LDNS_RCODE_NOERROR) {
             tsig_rr_error(q->tsig_rr);
             tsig_rr_append(q->tsig_rr, q->buffer);
             buffer_pkt_set_arcount(q->buffer,
                 buffer_pkt_arcount(q->buffer)+1);
         } else if (q->tsig_rr->status == TSIG_OK &&
             q->tsig_rr->error_code == LDNS_RCODE_NOERROR) {
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
    return;
}


/**
 * Cleanup query.
 *
 */
void
query_cleanup(query_type* q)
{
    allocator_type* allocator = NULL;
    if (!q) {
        return;
    }
    allocator = q->allocator;
    buffer_cleanup(q->buffer, allocator);
    tsig_rr_cleanup(q->tsig_rr);
    allocator_deallocate(allocator, (void*)q);
    allocator_cleanup(allocator);
    return;
}
