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

#ifndef WIRE_QUERY_H
#define WIRE_QUERY_H

#include "config.h"
#include "status.h"
#include "signer/zone.h"
#include "wire/buffer.h"
#include "wire/edns.h"
#include "wire/tsig.h"

#define UDP_MAX_MESSAGE_LEN 512
#define TCP_MAX_MESSAGE_LEN 65535
#define QUERY_RESPONSE_MAX_RRSET 10 /* should be enough */

enum query_enum {
        QUERY_PROCESSED = 0,
        QUERY_DISCARDED,
        QUERY_AXFR,
        QUERY_IXFR
};
typedef enum query_enum query_state;

/**
 * Query.
 *
 */
typedef struct query_struct query_type;
struct query_struct {
    /* Query from addres */
    struct sockaddr_storage addr;
    socklen_t addrlen;
    /* Maximum supported query size */
    size_t maxlen;
    size_t reserved_space;
    /* TSIG */
    tsig_rr_type* tsig_rr;
    /* EDNS */
    edns_rr_type* edns_rr;
    /* TCP */
    int tcp;
    uint16_t tcplen;
    buffer_type* buffer;
    /* QNAME, QTYPE, QCLASS */

    /* Zone */
    zone_type* zone;
    /* Compression */

    /* AXFR IXFR */
    FILE* axfr_fd;
    uint32_t serial;
    size_t startpos;
    /* Bits */
    unsigned axfr_is_done : 1;
    unsigned tsig_prepare_it : 1;
    unsigned tsig_update_it : 1;
    unsigned tsig_sign_it : 1;
};

/**
 * Response.
 *
 */
typedef struct response_struct response_type;
struct response_struct {
    ldns_rr_list* answersection;
    ldns_rr_list* authoritysection;
    ldns_rr_list* additionalsection;
    ldns_rr_list* answersectionsigs;
    ldns_rr_list* authoritysectionsigs;
    ldns_rr_list* additionalsectionsigs;
};

/**
 * Create query.
 * \return query_type* query
 *
 */
query_type* query_create(void);

/**
 * Prepare response.
 * \param[in] q query
 *
 */
void query_prepare(query_type* q);

/**
 * Process query.
 * \param[in] q query
 * \param[in] engine signer engine
 * \return query_state state of the query
 *
 */
query_state query_process(query_type* q, engine_type* engine);

/**
 * Reset query.
 * \param[in] q query
 * \param[in] maxlen maximum message length
 * \param[in] is_tcp 1 if tcp query
 *
 */
void query_reset(query_type* q, size_t maxlen, int is_tcp);

/**
 * Add optional RRs to query.
 * \param[in] q query
 * \param[in] engine signer engine
 *
 */
void query_add_optional(query_type* q, engine_type* engine);

/**
 * Add RR to query.
 * \param[in] q query
 * \param[in] rr RR
 * \return int 1 if ok, 0 if overflow.
 *
 */
int query_add_rr(query_type* q, ldns_rr* rr);

/**
 * Cleanup query.
 * \param[in] q query
 *
 */
void query_cleanup(query_type* q);

#endif /* WIRE_QUERY_H */
