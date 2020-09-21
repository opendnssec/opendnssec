/*
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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
 *
 */

/**
 * TSIG.
 *
 */

#ifndef WIRE_TSIG_H
#define WIRE_TSIG_H

#include "config.h"
#include "status.h"
#include "wire/buffer.h"

#include <ldns/ldns.h>

#define TSIG_ERROR_BADSIG   16
#define TSIG_ERROR_BADKEY   17
#define TSIG_ERROR_BADTIME  18

#define TSIG_HMAC_MD5       157
#define TSIG_HMAC_SHA1      158
#define TSIG_HMAC_SHA256    159

/**
 * TSIG status.
 *
 */
enum tsig_status_enum {
        TSIG_NOT_PRESENT,
        TSIG_OK,
        TSIG_ERROR
};
typedef enum tsig_status_enum tsig_status;

/**
 * TSIG lookup table.
 *
 */
typedef struct tsig_lookup_table_struct tsig_lookup_table;
struct tsig_lookup_table_struct
{
        uint8_t id;
        const char* short_name;
};

/**
 * TSIG key.
 *
 */
typedef struct tsig_key_struct tsig_key_type;
struct tsig_key_struct {
    ldns_rdf* dname;
    size_t size;
    const uint8_t* data;
};

/**
 * TSIG algorithm.
 *
 */
typedef struct tsig_algo_struct tsig_algo_type;
struct tsig_algo_struct {
    const char* txt_name;
    ldns_rdf* wf_name;
    size_t max_digest_size;
    const void* data;
    /* create a new HMAC context */
    void*(*hmac_create)(void);
    /* initialize an HMAC context */
    void(*hmac_init)(void* context, tsig_algo_type* algo,
        tsig_key_type* key);
    /* update the HMAC context */
    void(*hmac_update)(void* context, const void* data, size_t size);
    /* finalize digest */
    void(*hmac_final)(void* context, uint8_t* digest, size_t* size);
};

/**
 * TSIG configuration.
 *
 */
typedef struct tsig_struct tsig_type;
struct tsig_struct {
    tsig_type* next;
    const char* name;
    const char* algorithm;
    const char* secret;
    tsig_key_type* key;
};

/**
 * TSIG RR.
 *
 */
typedef struct tsig_rr_struct tsig_rr_type;
struct tsig_rr_struct {
    tsig_status status;
    size_t position;
    size_t response_count;
    size_t update_since_last_prepare;
    void* context;
    tsig_algo_type* algo;
    tsig_key_type* key;
    size_t prior_mac_size;
    uint8_t* prior_mac_data;

    ldns_rdf* key_name;
    ldns_rdf* algo_name;
    uint16_t signed_time_high;
    uint32_t signed_time_low;
    uint16_t signed_time_fudge;
    uint16_t mac_size;
    uint8_t* mac_data;
    uint16_t original_query_id;
    uint16_t error_code;
    uint16_t other_size;
    uint8_t* other_data;
};

/**
 * Initialize TSIG handler.
 * \param[in] allocator memory allocator
 * \return ods_status status
 *
 */
extern ods_status tsig_handler_init(void);

/**
 * Clean up TSIG handler.
 *
 */
extern void tsig_handler_cleanup(void);

/**
 * Add key to TSIG handler.
 * \param[in] key tsig key
 *
 */
extern void tsig_handler_add_key(tsig_key_type* key);

/**
 * Add algorithm to TSIG handler.
 * \param[in] algo tsig algorithm
 *
 */
extern void tsig_handler_add_algo(tsig_algo_type* algo);

/**
 * Create new TSIG.
 * \param[in] allocator memory allocator
 * \param[in] name tsig name
 * \param[in] algo tsig algorithm
 * \param[in] secret tsig secret
 * \return tsig_type* TSIG
 *
 */
extern tsig_type* tsig_create(char* name, char* algo,
    char* secret);

/**
 * Lookup TSIG by key name.
 * \param[in] tsig TSIG list
 * \param[in] naem TSIG name
 * \return tsig_type* TSIG
 *
 */
extern tsig_type* tsig_lookup_by_name(tsig_type* tsig, const char* name);

/**
 * Lookup TSIG algorithm by name.
 * \param[in] name algorithm name
 * \return tsig_algo_type* TSIG algorithm
 *
 */
extern tsig_algo_type* tsig_lookup_algo(const char* name);

/**
 * Create new TSIG RR.
 * \param[in] allocator memory allocator
 * \return tsig_rr_type* TSIG RR
 *
 */
extern tsig_rr_type* tsig_rr_create(void);

/**
 * Reset TSIG RR.
 * \param[in] trr TSIG RR
 * \param[in] algo tsig algorithm
 * \param[in] key tsig key
 *
 */
extern void tsig_rr_reset(tsig_rr_type* trr, tsig_algo_type* algo, tsig_key_type* key);

/**
 * Find TSIG RR.
 * \param[in] trr TSIG RR
 * \param[in] buffer packet buffer
 * \return int 1 if not present or present and valid, 0 otherwise.
 *
 */
extern int tsig_rr_find(tsig_rr_type* trr, buffer_type* buffer);

/**
 * Parse TSIG RR.
 * \param[in] trr TSIG RR
 * \param[in] buffer packet buffer
 * \return int 1 if not TSIG RR or TSIG RR and valid, 0 otherwise.
 *
 */
extern int tsig_rr_parse(tsig_rr_type* trr, buffer_type* buffer);

/**
 * Lookup TSIG RR.
 * \param[in] trr TSIG RR
 * \return int 1 if succeeded, 0 if unknown
 *
 */
extern int tsig_rr_lookup(tsig_rr_type* trr);

/**
 * Prepare TSIG RR.
 * \param[in] trr TSIG RR
 *
 */
extern void tsig_rr_prepare(tsig_rr_type* trr);

/**
 * Update TSIG RR.
 * \param[in] trr TSIG RR
 * \param[in] buffer packet buffer
 * \param[in] length number of octets of buffer to add to the TSIG hash,
 *                   replacing the buffer's id with the original
 *                   query idfrom TSIG.
 *
 */
extern void tsig_rr_update(tsig_rr_type* trr, buffer_type* buffer, size_t length);

/**
 * Sign TSIG RR.
 * \param[in] trr TSIG RR
 *
 */
extern void tsig_rr_sign(tsig_rr_type* trr);

/**
 * Verify TSIG RR.
 * \param[in] trr TSIG RR
 * \return int 1 if verified, 0 on error
 *
 */
extern int tsig_rr_verify(tsig_rr_type* trr);

/**
 * Append TSIG RR.
 * \param[in] trr TSIG RR
 * \param[in] buffer packet buffer
 *
 */
extern void tsig_rr_append(tsig_rr_type* trr, buffer_type* buffer);

/*
 * The amount of space to reserve in the response for the TSIG data.
 * \param[in] trr TSIG RR
 * \return size_t reserved space size
 *
 */
extern size_t tsig_rr_reserved_space(tsig_rr_type *trr);

/**
 * Reply with error TSIG RR.
 * \param[in] trr TSIG RR
 *
 */
extern void tsig_rr_error(tsig_rr_type* trr);

/**
 * Get human readable TSIG error code.
 * \param[in] status TSIG status
 * \return const char* TSIG status
 *
 */
extern const char* tsig_status2str(tsig_status status);

/**
 * Get human readable TSIG error code.
 * \param[in] error TSIG error code
 * \return const char* readable error code
 *
 */
extern const char* tsig_strerror(uint16_t error);

/**
 * Free TSIG RR.
 * \param[in] trr TSIG RR
 *
 */
extern void tsig_rr_free(tsig_rr_type* trr);

/**
 * Cleanup TSIG RR
 * \param[in] trr TSIG RR
 *
 */
extern void tsig_rr_cleanup(tsig_rr_type* trr);

/**
 * Clean up TSIG.
 * \param[in] tsig TSIG
 * \param[in] allocator memory allocator
 *
 */
extern void tsig_cleanup(tsig_type* tsig);

#endif /* WIRE_TSIG_H */
