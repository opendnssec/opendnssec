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
 * EDNS.
 *
 */

#ifndef WIRE_EDNS_H
#define WIRE_EDNS_H

#include "config.h"
#include "status.h"
#include "wire/buffer.h"

#include <ldns/ldns.h>

#define OPT_LEN 9U /* length of the NSD EDNS response record minus 2 */
#define OPT_RDATA 2 /* holds the rdata length comes after OPT_LEN */
#define DNSSEC_OK_MASK  0x8000U /* do bit mask */

#define EDNS_MAX_MESSAGE_LEN 4096

/**
 * EDNS data.
 *
 */
typedef struct edns_data_struct edns_data_type;
struct edns_data_struct {
    unsigned char ok[OPT_LEN];
    unsigned char error[OPT_LEN];
    unsigned char rdata_none[OPT_RDATA];
};

/**
 * EDNS status.
 *
 */
enum edns_status_enum {
    EDNS_NOT_PRESENT,
    EDNS_OK,
    EDNS_ERROR
};
typedef enum edns_status_enum edns_status;

/**
 * EDNS RR.
 *
 */
typedef struct edns_rr_struct edns_rr_type;
struct edns_rr_struct {
    edns_status status;
    size_t position;
    size_t maxlen;
    int dnssec_ok;
};


/**
 * Initialize EDNS.
 * \param[in] data EDNS data.
 * \param[in] max_length maximum length.
 *
 */
extern void edns_init(edns_data_type* data, uint16_t max_length);

/**
 * Create new EDNS RR.
 * \param[in] allocator memory allocator.
 * \return edns_rr_type* EDNS RR.
 *
 */
extern edns_rr_type* edns_rr_create(void);


/**
 * Reset EDNS OPT RR.
 * \param[in] err EDNS record.
 *
 */
extern void edns_rr_reset(edns_rr_type* err);

/**
 * Parse EDNS OPT RR.
 * \param[in] err EDNS record.
 * \param[in] buffer packet buffer.
 * \return int 1 if EDNS and valid, 0 otherwise.
 *
 */
extern int edns_rr_parse(edns_rr_type* err, buffer_type* buffer);

/**
 * The amount of space to reserve in the response for the EDNS data.
 * \param[in] err EDNS record.
 * \return size_t amount of space to reserve.
 *
 */
extern size_t edns_rr_reserved_space(edns_rr_type* err);

extern void edns_rr_cleanup(edns_rr_type* err);


#endif /* WIRE_EDNS_H */
