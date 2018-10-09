/*
 * Copyright (c) 2011-2018 NLNet Labs.
 * All rights reserved.
 *
 * Taken from NSD3 and adjusted for OpenDNSSEC, NLnet Labs.
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
 * TSIG.
 *
 */

#include "config.h"
#include "compat.h"
#include "duration.h"
#include "file.h"
#include "log.h"
#include "status.h"
#include "util.h"
#include "wire/buffer.h"
#include "wire/tsig.h"
#include "wire/tsig-openssl.h"

#include <arpa/inet.h>

#define TSIG_SIGNED_TIME_FUDGE 300

static const char* tsig_str = "tsig";
/** key table */
typedef struct tsig_key_table_struct tsig_key_table_type;
struct tsig_key_table_struct {
        tsig_key_table_type* next;
        tsig_key_type* key;
};
static tsig_key_table_type* tsig_key_table = NULL;
/** algorithm table */
typedef struct tsig_algo_table_struct tsig_algo_table_type;
struct tsig_algo_table_struct {
    tsig_algo_table_type* next;
    tsig_algo_type* algorithm;
};
static tsig_algo_table_type* tsig_algo_table = NULL;
/** maximum algorithm digest size */
static size_t max_algo_digest_size = 0;


/**
 * Add key to TSIG handler.
 *
 */
void
tsig_handler_add_key(tsig_key_type* key)
{
    tsig_key_table_type* entry = NULL;
    if (!key) {
        return;
    }
    CHECKALLOC(entry = (tsig_key_table_type *) malloc(sizeof(tsig_key_table_type)));
    entry->key = key;
    entry->next = tsig_key_table;
    tsig_key_table = entry;
}


/**
 * Add algorithm to TSIG handler.
 *
 */
void
tsig_handler_add_algo(tsig_algo_type* algo)
{
    tsig_algo_table_type* entry = NULL;
    if (!algo) {
        return;
    }
    CHECKALLOC(entry = (tsig_algo_table_type *) malloc(sizeof(tsig_algo_table_type)));
    entry->algorithm = algo;
    entry->next = tsig_algo_table;
    tsig_algo_table = entry;
    if (algo->max_digest_size > max_algo_digest_size) {
        max_algo_digest_size = algo->max_digest_size;
    }
}


/**
 * Initialize TSIG handler.
 *
 */
ods_status
tsig_handler_init()
{
    tsig_key_table = NULL;
    tsig_algo_table = NULL;
#ifdef HAVE_SSL
    ods_log_debug("[%s] init openssl", tsig_str);
    return tsig_handler_openssl_init();
#else
    ods_log_debug("[%s] openssl disabled", tsig_str);
    return ODS_STATUS_OK;
#endif
}


/**
 * Clean up TSIG handler.
 *
 */
void
tsig_handler_cleanup(void)
{
    tsig_algo_table_type* aentry = NULL, *anext = NULL;
    tsig_key_table_type* kentry = NULL, *knext = NULL;
#ifdef HAVE_SSL
    tsig_handler_openssl_finalize();
#endif

    aentry = tsig_algo_table;
    while (aentry) {
        anext = aentry->next;
        ldns_rdf_deep_free(aentry->algorithm->wf_name);
        free(aentry->algorithm);
        free(aentry);
        aentry = anext;
    }

    kentry = tsig_key_table;
    while (kentry) {
        knext = kentry->next;
        ldns_rdf_deep_free(kentry->key->dname);
        free((void*)kentry->key->data);
        free((void*)kentry->key);
        free(kentry);
        kentry = knext;
    }
}


/**
 * Create new TSIG key.
 *
 */
static tsig_key_type*
tsig_key_create(tsig_type* tsig)
{
    tsig_key_type* key = NULL;
    ldns_rdf* dname = NULL;
    uint8_t* data = NULL;
    int size = 0;
    if (!tsig || !tsig->name || !tsig->secret) {
        return NULL;
    }
    CHECKALLOC(key = (tsig_key_type*) malloc(sizeof(tsig_key_type)));
    dname = ldns_dname_new_frm_str(tsig->name);
    if (!dname) {
	free(key);
        return NULL;
    }
    CHECKALLOC(data = malloc(sizeof(uint8_t) * util_b64_pton_calculate_size(strlen(tsig->secret))));
    size = b64_pton(tsig->secret, data,
        util_b64_pton_calculate_size(strlen(tsig->secret)));
    if (size < 0) {
        ods_log_error("[%s] unable to create tsig key %s: failed to parse "
            "secret", tsig_str, tsig->name);
        ldns_rdf_deep_free(dname);
        free(data);
	free(key);
        return NULL;
    }
    key->dname = dname;
    key->size = size;
    key->data = data;
    tsig_handler_add_key(key);
    return key;
}


/**
 * Create new TSIG.
 *
 */
tsig_type*
tsig_create(char* name, char* algo, char* secret)
{
    tsig_type* tsig = NULL;
    if (!name || !algo || !secret) {
        return NULL;
    }
    CHECKALLOC(tsig = (tsig_type*) malloc(sizeof(tsig_type)));
    tsig->next = NULL;
    tsig->name = strdup(name);
    tsig->algorithm = strdup(algo);
    tsig->secret = strdup(secret);
    tsig->key = tsig_key_create(tsig);
    if (!tsig->key) {
        ods_log_error("[%s] unable to create tsig: tsig_key_create() "
            "failed", tsig_str);
        tsig_cleanup(tsig);
        return NULL;
    }
    return tsig;
}


/**
 * Lookup TSIG by key name.
 *
 */
tsig_type*
tsig_lookup_by_name(tsig_type* tsig, const char* name)
{
    tsig_type* find = NULL;
    if (!tsig || !name) {
        return NULL;
    }
    find = tsig;
    while (find) {
        if (ods_strlowercmp(find->name, name) == 0) {
            return find;
        }
        find = find->next;
    }
    return NULL;
}


/**
 * Lookup TSIG algorithm by name.
 *
 */
tsig_algo_type*
tsig_lookup_algo(const char* name)
{
    tsig_algo_table_type* entry = NULL;
    for (entry = tsig_algo_table; entry; entry = entry->next) {
        if (ods_strlowercmp(name, entry->algorithm->txt_name) == 0) {
            return entry->algorithm;
        }
    }
    return NULL;
}


/**
 * Create new TSIG RR.
 *
 */
tsig_rr_type*
tsig_rr_create()
{
    tsig_rr_type* trr = NULL;
    CHECKALLOC(trr = (tsig_rr_type*) malloc(sizeof(tsig_rr_type)));
    trr->key_name = NULL;
    trr->algo_name = NULL;
    trr->mac_data = NULL;
    trr->other_data = NULL;
    tsig_rr_reset(trr, NULL, NULL);
    return trr;
}


/**
 * Reset TSIG RR.
 *
 */
void
tsig_rr_reset(tsig_rr_type* trr, tsig_algo_type* algo, tsig_key_type* key)
{
    if (!trr) {
        return;
    }
    tsig_rr_free(trr);
    trr->status = TSIG_NOT_PRESENT;
    trr->position = 0;
    trr->response_count = 0;
    trr->update_since_last_prepare = 0;
    trr->context = NULL;
    trr->algo = algo;
    trr->key = key;
    trr->prior_mac_size = 0;
    trr->prior_mac_data = NULL;
    trr->signed_time_high = 0;
    trr->signed_time_low = 0;
    trr->signed_time_fudge = 0;
    trr->mac_size = 0;
    trr->original_query_id = 0;
    trr->error_code = LDNS_RCODE_NOERROR;
    trr->other_size = 0;
}


/**
 * Parse TSIG RR.
 *
 */
int
tsig_rr_parse(tsig_rr_type* trr, buffer_type* buffer)
{
    uint16_t dname_len = 0;
    ldns_rr_type type = 0;
    ldns_rr_class klass = 0;
    uint32_t ttl = 0;
    uint16_t rdlen = 0;
    uint16_t curpos = 0;
    ods_log_assert(trr);
    ods_log_assert(buffer);
    trr->status = TSIG_NOT_PRESENT;
    trr->position = buffer_position(buffer);
    curpos = trr->position;
    if (!buffer_skip_dname(buffer)) {
        buffer_set_position(buffer, trr->position);
        ods_log_debug("[%s] parse: skip key name failed", tsig_str);
        return 0;
    }
    dname_len = buffer_position(buffer) - curpos;
    buffer_set_position(buffer, curpos);
    trr->key_name = ldns_dname_new_frm_data(dname_len,
        (const void*) buffer_current(buffer));
    if (!trr->key_name) {
        buffer_set_position(buffer, trr->position);
        ods_log_debug("[%s] parse: read key name failed", tsig_str);
        return 0;
    }
    buffer_set_position(buffer, curpos + dname_len);
    if (!buffer_available(buffer, 10)) {
        ods_log_debug("[%s] parse: not enough available", tsig_str);
        buffer_set_position(buffer, trr->position);
        return 0;
    }
    type = (ldns_rr_type) buffer_read_u16(buffer);
    klass = (ldns_rr_class) buffer_read_u16(buffer);
    if (type != LDNS_RR_TYPE_TSIG || klass != LDNS_RR_CLASS_ANY) {
        /* not present */
        ods_log_debug("[%s] parse: not TSIG or not ANY but %d:%d", tsig_str,
            klass, type);
        buffer_set_position(buffer, trr->position);
        return 1;
    }
    ttl = buffer_read_u32(buffer);
    rdlen = buffer_read_u16(buffer);
    /* default to error */
    trr->status = TSIG_ERROR;
    trr->error_code = LDNS_RCODE_FORMERR;
    if (ttl || !buffer_available(buffer, rdlen)) {
        ods_log_debug("[%s] parse: TTL!=0 or RDLEN=0", tsig_str);
        buffer_set_position(buffer, trr->position);
        return 0;
    }
    curpos = buffer_position(buffer);
    if (!buffer_skip_dname(buffer)) {
        ods_log_debug("[%s] parse: skip algo name failed", tsig_str);
        buffer_set_position(buffer, trr->position);
        return 0;
    }
    dname_len = buffer_position(buffer) - curpos;
    buffer_set_position(buffer, curpos);
    trr->algo_name = ldns_dname_new_frm_data(dname_len,
        (const void*) buffer_current(buffer));
    if (!trr->algo_name) {
        ods_log_debug("[%s] parse: read algo name failed", tsig_str);
        buffer_set_position(buffer, trr->position);
        return 0;
    }
    buffer_set_position(buffer, curpos + dname_len);
    if (!buffer_available(buffer, 10)) {
        ods_log_debug("[%s] parse: not enough available", tsig_str);
        buffer_set_position(buffer, trr->position);
        return 0;
    }
    trr->signed_time_high = buffer_read_u16(buffer);
    trr->signed_time_low = buffer_read_u32(buffer);
    trr->signed_time_fudge = buffer_read_u16(buffer);
    trr->mac_size = buffer_read_u16(buffer);
    if (!buffer_available(buffer, trr->mac_size)) {
        ods_log_debug("[%s] parse: wrong mac size", tsig_str);
        buffer_set_position(buffer, trr->position);
        trr->mac_size = 0;
        return 0;
    }
    CHECKALLOC(trr->mac_data = (uint8_t *) malloc(trr->mac_size));
    memcpy(trr->mac_data, (const void*) buffer_current(buffer), trr->mac_size);
    buffer_skip(buffer, trr->mac_size);
    if (!buffer_available(buffer, 6)) {
        ods_log_debug("[%s] parse: not enough available", tsig_str);
        buffer_set_position(buffer, trr->position);
        return 0;
    }
    trr->original_query_id = buffer_read_u16(buffer);
    trr->error_code = buffer_read_u16(buffer);
    trr->other_size = buffer_read_u16(buffer);
    if (!buffer_available(buffer, trr->other_size) || trr->other_size > 16) {
        ods_log_debug("[%s] parse: not enough available", tsig_str);
        trr->other_size = 0;
        buffer_set_position(buffer, trr->position);
        return 0;
    }
    CHECKALLOC(trr->other_data = (uint8_t *) malloc(trr->other_size));
    memcpy(trr->other_data, (const void*) buffer_current(buffer), trr->other_size);
    buffer_skip(buffer, trr->other_size);
    trr->status = TSIG_OK;
    return 1;
}


/**
 * Find TSIG RR.
 *
 */
int
tsig_rr_find(tsig_rr_type* trr, buffer_type* buffer)
{
    size_t saved_pos = 0;
    size_t rrcount = 0;
    size_t i = 0;
    int result = 0;
    ods_log_assert(trr);
    ods_log_assert(buffer);
    if (buffer_pkt_arcount(buffer) == 0) {
        trr->status = TSIG_NOT_PRESENT;
        return 1;
    }
    saved_pos = buffer_position(buffer);
    rrcount = buffer_pkt_qdcount(buffer) + buffer_pkt_ancount(buffer) +
        buffer_pkt_nscount(buffer) + buffer_pkt_arcount(buffer);
    rrcount &= 0x3FFFF; /* un-taint rrcount */
    buffer_set_position(buffer, BUFFER_PKT_HEADER_SIZE);
    for (i=0; i < rrcount - 1; i++) {
        if (!buffer_skip_rr(buffer, i < (buffer_pkt_qdcount(buffer)&0xFFFF))) {
             buffer_set_position(buffer, saved_pos);
             return 0;
        }
    }
    result = tsig_rr_parse(trr, buffer);
    buffer_set_position(buffer, saved_pos);
    return result;
}


/**
 * Lookup TSIG RR.
 *
 */
int
tsig_rr_lookup(tsig_rr_type* trr)
{
    tsig_key_table_type* kentry = NULL;
    tsig_key_type* key = NULL;
    tsig_algo_table_type* aentry = NULL;
    tsig_algo_type* algorithm = NULL;
    uint64_t current_time = 0;
    uint64_t signed_time = 0;
    ods_log_assert(trr);
    ods_log_assert(trr->status == TSIG_OK);
    ods_log_assert(!trr->algo);
    ods_log_assert(!trr->key);
    for (kentry = tsig_key_table; kentry; kentry = kentry->next) {
        if (ldns_dname_compare(trr->key_name, kentry->key->dname) == 0) {
            key = kentry->key;
            break;
        }
    }
    for (aentry = tsig_algo_table; aentry; aentry = aentry->next) {
        if (ldns_dname_compare(trr->algo_name,
            aentry->algorithm->wf_name) == 0) {
            algorithm = aentry->algorithm;
            break;
        }
    }
    if (!key || !algorithm) {
        /* algorithm or key is unknown, cannot authenticate. */
        ods_log_debug("[%s] algorithm or key missing", tsig_str);
        trr->error_code = TSIG_ERROR_BADKEY;
        return 0;
    }
    if ((trr->algo && algorithm != trr->algo) ||
        (trr->key && key != trr->key)) {
        /* algorithm or key changed during a single connection, error. */
        ods_log_debug("[%s] algorithm or key has changed", tsig_str);
        trr->error_code = TSIG_ERROR_BADKEY;
        return 0;
    }
    signed_time = ((((uint64_t) trr->signed_time_high) << 32) |
                  ((uint64_t) trr->signed_time_low));
    current_time = (uint64_t) time_now();
    if ((current_time < signed_time - trr->signed_time_fudge) ||
        (current_time > signed_time + trr->signed_time_fudge)) {
        uint16_t current_time_high;
        uint32_t current_time_low;
        trr->error_code = TSIG_ERROR_BADTIME;
        current_time_high = (uint16_t) (current_time >> 32);
        current_time_low = (uint32_t) current_time;
        trr->other_size = 6;
        CHECKALLOC(trr->other_data = (uint8_t *) malloc(sizeof(uint16_t) + sizeof(uint32_t)));
        write_uint16(trr->other_data, current_time_high);
        write_uint32(trr->other_data + 2, current_time_low);
        ods_log_debug("[%s] bad time", tsig_str);
        return 0;
    }
    trr->algo = algorithm;
    trr->key = key;
    trr->response_count = 0;
    trr->prior_mac_size = 0;
    return 1;
}


/**
 * Prepare TSIG RR.
 *
 */
void
tsig_rr_prepare(tsig_rr_type* trr)
{
    ods_log_assert(trr->algo);
    if (!trr->context) {
        trr->context = trr->algo->hmac_create();
        CHECKALLOC(trr->prior_mac_data = (uint8_t *) malloc(trr->algo->max_digest_size));
    }
    trr->algo->hmac_init(trr->context, trr->algo, trr->key);
    if (trr->prior_mac_size > 0) {
        uint16_t mac_size = htons(trr->prior_mac_size);
        trr->algo->hmac_update(trr->context, &mac_size, sizeof(mac_size));
        trr->algo->hmac_update(trr->context, trr->prior_mac_data,
            trr->prior_mac_size);
    }
    trr->update_since_last_prepare = 0;
}

/**
 * Update TSIG RR.
 *
 */
void
tsig_rr_update(tsig_rr_type* trr, buffer_type* buffer, size_t length)
{
    uint16_t original_query_id = 0;
    ods_log_assert(trr);
    ods_log_assert(trr->algo);
    ods_log_assert(trr->context);
    ods_log_assert(buffer);
    ods_log_assert(length <= buffer_limit(buffer));
    original_query_id = htons(trr->original_query_id);
    trr->algo->hmac_update(trr->context, &original_query_id,
        sizeof(original_query_id));
    trr->algo->hmac_update(trr->context,
        buffer_at(buffer, sizeof(original_query_id)),
        length - sizeof(original_query_id));
    if (buffer_pkt_qr(buffer)) {
        ++trr->response_count;
    }
    ++trr->update_since_last_prepare;
}


/**
 * Digest variables.
 *
 */
static void
tsig_rr_digest_variables(tsig_rr_type* trr, int tsig_timers_only)
{
    uint16_t klass = htons(LDNS_RR_CLASS_ANY);
    uint32_t ttl = htonl(0);
    uint16_t signed_time_high = htons(trr->signed_time_high);
    uint32_t signed_time_low = htonl(trr->signed_time_low);
    uint16_t signed_time_fudge = htons(trr->signed_time_fudge);
    uint16_t error_code = htons(trr->error_code);
    uint16_t other_size = htons(trr->other_size);
    ods_log_assert(trr->context);
    ods_log_assert(trr->algo);
    ods_log_assert(trr->key_name);
    if (!tsig_timers_only) {
        ods_log_assert(trr->key_name);
        ods_log_assert(trr->algo_name);
        trr->algo->hmac_update(trr->context, ldns_rdf_data(trr->key_name),
            ldns_rdf_size(trr->key_name));
        trr->algo->hmac_update(trr->context, &klass, sizeof(klass));
        trr->algo->hmac_update(trr->context, &ttl, sizeof(ttl));
        trr->algo->hmac_update(trr->context, ldns_rdf_data(trr->algo_name),
            ldns_rdf_size(trr->algo_name));
    }
    trr->algo->hmac_update(trr->context, &signed_time_high,
        sizeof(signed_time_high));
    trr->algo->hmac_update(trr->context, &signed_time_low,
        sizeof(signed_time_low));
    trr->algo->hmac_update(trr->context, &signed_time_fudge,
        sizeof(signed_time_fudge));
    if (!tsig_timers_only) {
        trr->algo->hmac_update(trr->context, &error_code,
            sizeof(error_code));
        trr->algo->hmac_update(trr->context, &other_size,
            sizeof(other_size));
        trr->algo->hmac_update(trr->context, trr->other_data,
            trr->other_size);
    }
}


/**
 * Sign TSIG RR.
 *
 */
void
tsig_rr_sign(tsig_rr_type* trr)
{
    uint64_t current_time = (uint64_t) time_now();
    ods_log_assert(trr);
    ods_log_assert(trr->context);
    trr->signed_time_high = (uint16_t) (current_time >> 32);
    trr->signed_time_low = (uint32_t) current_time;
    trr->signed_time_fudge = TSIG_SIGNED_TIME_FUDGE;
    tsig_rr_digest_variables(trr, trr->response_count > 1);
    trr->algo->hmac_final(trr->context, trr->prior_mac_data,
        &trr->prior_mac_size);
    trr->mac_size = trr->prior_mac_size;
    trr->mac_data = trr->prior_mac_data;
}


/**
 * Verify TSIG RR.
 *
 */
int
tsig_rr_verify(tsig_rr_type* trr)
{
    ods_log_assert(trr);
    ods_log_assert(trr->algo);
    tsig_rr_digest_variables(trr, trr->response_count > 1);
    trr->algo->hmac_final(trr->context, trr->prior_mac_data,
        &trr->prior_mac_size);
    if (trr->mac_size != trr->prior_mac_size ||
        memcmp(trr->mac_data, trr->prior_mac_data, trr->mac_size) != 0) {
        /* digest is incorrect, cannot authenticate.  */
        trr->error_code = TSIG_ERROR_BADSIG;
        return 0;
    }
    return 1;
}


/**
 * Append TSIG RR.
 *
 */
void
tsig_rr_append(tsig_rr_type* trr, buffer_type* buffer)
{
    size_t rdlength_pos = 0;
    if (!trr || !buffer) {
        return;
    }
    /* [TODO] key name compression? */
    if (trr->key_name) {
        buffer_write_rdf(buffer, trr->key_name);
    } else {
        buffer_write_u8(buffer, 0);
    }
    buffer_write_u16(buffer, (uint16_t)LDNS_RR_TYPE_TSIG);
    buffer_write_u16(buffer, (uint16_t)LDNS_RR_CLASS_ANY);
    buffer_write_u32(buffer, 0); /* TTL */
    rdlength_pos = buffer_position(buffer);
    buffer_skip(buffer, sizeof(uint16_t));
    if (trr->algo_name) {
        buffer_write_rdf(buffer, trr->algo_name);
    } else {
        buffer_write_u8(buffer, 0);
    }
    buffer_write_u16(buffer, trr->signed_time_high);
    buffer_write_u32(buffer, trr->signed_time_low);
    buffer_write_u16(buffer, trr->signed_time_fudge);
    buffer_write_u16(buffer, trr->mac_size);
    buffer_write(buffer, trr->mac_data, trr->mac_size);
    buffer_write_u16(buffer, trr->original_query_id);
    buffer_write_u16(buffer, trr->error_code);
    buffer_write_u16(buffer, trr->other_size);
    buffer_write(buffer, trr->other_data, trr->other_size);
    buffer_write_u16_at(buffer, rdlength_pos,
        buffer_position(buffer) - rdlength_pos - sizeof(uint16_t));
}


/*
 * The amount of space to reserve in the response for the TSIG data.
 *
 */
size_t
tsig_rr_reserved_space(tsig_rr_type* trr)
{
    if (!trr || trr->status == TSIG_NOT_PRESENT) {
        return 0;
    }
    return (
         (trr->key_name?ldns_rdf_size(trr->key_name):1)
         + sizeof(uint16_t) /* Type */
         + sizeof(uint16_t) /* Class */
         + sizeof(uint32_t) /* TTL */
         + sizeof(uint16_t) /* RDATA length */
         + (trr->algo_name?ldns_rdf_size(trr->algo_name):1)
         + sizeof(uint16_t) /* Signed time (high) */
         + sizeof(uint32_t) /* Signed time (low) */
         + sizeof(uint16_t) /* Signed time fudge */
         + sizeof(uint16_t) /* MAC size */
         + max_algo_digest_size /* MAC data */
         + sizeof(uint16_t) /* Original query ID */
         + sizeof(uint16_t) /* Error code */
         + sizeof(uint16_t) /* Other size */
         + trr->other_size); /* Other data */
}


/**
 * Reply with error TSIG RR.
 *
 */
void
tsig_rr_error(tsig_rr_type* trr)
{
    if (!trr) {
        return;
    }
    if (trr->mac_data) {
        memset(trr->mac_data, 0, trr->mac_size);
    }
    trr->mac_size = 0;
}


/**
 * Print TSIG status.
 *
 */
const char*
tsig_status2str(tsig_status status)
{
    switch (status) {
        case TSIG_NOT_PRESENT:
            return "NOT PRESENT";
        case TSIG_OK:
            return "OK";
        case TSIG_ERROR:
            return "ERROR";
    }
    return "UNKNOWN";
}


/**
 * Get human readable TSIG error code.
 *
 */
const char*
tsig_strerror(uint16_t error)
{
    static char message[1000];
    switch (error) {
        case 0:
            return "No Error";
            break;
        case TSIG_ERROR_BADSIG:
            return "Bad Signature";
            break;
        case TSIG_ERROR_BADKEY:
            return "Bad Key";
            break;
        case TSIG_ERROR_BADTIME:
            return "Bad Time";
            break;
        default:
            if (error < 16) {
                /* DNS rcodes */
                return (const char*) ldns_pkt_rcode2str(error);
            }
            snprintf(message, sizeof(message), "Unknown Error %d", error);
            break;
    }
    return message;
}


/**
 * Free TSIG RR.
 *
 */
void
tsig_rr_free(tsig_rr_type* trr)
{
    if (!trr) {
        return;
    }
    ldns_rdf_deep_free(trr->key_name);
    ldns_rdf_deep_free(trr->algo_name);
    free(trr->mac_data);
    free(trr->other_data);
    trr->key_name = NULL;
    trr->algo_name = NULL;
    trr->mac_data = NULL;
    trr->other_data = NULL;
}


/**
 * Cleanup TSIG RR.
 *
 */
void
tsig_rr_cleanup(tsig_rr_type* trr)
{
    if (!trr) {
        return;
    }
    tsig_rr_free(trr);
    free(trr);
}


/**
 * Clean up TSIG.
 *
 */
void
tsig_cleanup(tsig_type* tsig)
{
    if (!tsig) {
        return;
    }
    tsig_cleanup(tsig->next);
    free((void*)tsig->name);
    free((void*)tsig->algorithm);
    free((void*)tsig->secret);
    free(tsig);
}
