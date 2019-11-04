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

#include "config.h"
#include "compat.h"

#include "wire/buffer.h"
#include "wire/edns.h"

#include <ldns/ldns.h>

static const char* edns_str = "edns";


/**
 * Create new EDNS RR.
 *
 */
edns_rr_type*
edns_rr_create()
{
    edns_rr_type* err = NULL;
    CHECKALLOC(err = (edns_rr_type*) malloc(sizeof(edns_rr_type))) ;
    edns_rr_reset(err);
    return err;
}


/**
 * Initialize EDNS.
 *
 */
void
edns_init(edns_data_type* data, uint16_t max_length)
{
    if (!data) {
        return;
    }
    memset(data, 0, sizeof(edns_data_type));
    /* record type: OPT */
    data->ok[1] = (LDNS_RR_TYPE_OPT & 0xff00) >> 8;    /* type_hi */
    data->ok[2] = LDNS_RR_TYPE_OPT & 0x00ff;           /* type_lo */
    /* udp payload size */
    data->ok[3] = (max_length & 0xff00) >> 8;          /* size_hi */
    data->ok[4] = max_length & 0x00ff;                 /* size_lo */

    data->error[1] = (LDNS_RR_TYPE_OPT & 0xff00) >> 8; /* type_hi */
    data->error[2] = LDNS_RR_TYPE_OPT & 0x00ff;        /* type_lo */
    data->error[3] = (max_length & 0xff00) >> 8;       /* size_hi */
    data->error[4] = max_length & 0x00ff;              /* size_lo */
    data->error[5] = 1; /* Extended RCODE=BAD VERS */
}


/**
 * Reset EDNS OPT RR.
 *
 */
void
edns_rr_reset(edns_rr_type* err)
{
    if (!err) {
        return;
    }
    err->status = EDNS_NOT_PRESENT;
    err->position = 0;
    err->maxlen = 0;
    err->dnssec_ok = 0;
}


/**
 * Parse EDNS OPT RR.
 *
 */
int
edns_rr_parse(edns_rr_type* err, buffer_type* buffer)
{
    /* OPT record type... */
    uint8_t  opt_owner;
    uint16_t opt_type;
    uint16_t opt_class;
    uint8_t  opt_version;
    uint16_t opt_flags;
    uint16_t opt_rdlen;

    if (!err || !buffer) {
        ods_log_debug("[%s] parse: no edns rr or no packet buffer available",
            edns_str);
        return 0;
    }

    err->position = buffer_position(buffer);
    if (!buffer_available(buffer, (OPT_LEN + OPT_RDATA))) {
        ods_log_debug("[%s] parse: edns rr too small", edns_str);
        return 0;
    }
    opt_owner = buffer_read_u8(buffer);
    opt_type = buffer_read_u16(buffer);
    if (opt_owner != 0 || opt_type != LDNS_RR_TYPE_OPT) {
        /* Not EDNS.  */
        ods_log_debug("[%s] parse: not OPT: owner=%02x, type=%02x", edns_str,
            opt_owner, opt_type);
        buffer_set_position(buffer, err->position);
        return 0;
    }
    opt_class = buffer_read_u16(buffer);
    (void)buffer_read_u8(buffer); /* opt_extended_rcode */
    opt_version = buffer_read_u8(buffer);
    opt_flags = buffer_read_u16(buffer);
    opt_rdlen = buffer_read_u16(buffer);
    buffer_skip(buffer, opt_rdlen);

    if (opt_version != 0) {
        /* The only error is VERSION not implemented */
        ods_log_debug("[%s] parse: wrong edns version", edns_str);
        err->status = EDNS_ERROR;
        return 1;
    }
    err->status = EDNS_OK;
    err->maxlen = opt_class;
    err->dnssec_ok = opt_flags & DNSSEC_OK_MASK;
    return 1;
}


/**
 * The amount of space to reserve in the response for the EDNS data.
 *
 */
size_t
edns_rr_reserved_space(edns_rr_type* err)
{
    if (!err) {
        return 0;
    }
    return err->status == EDNS_NOT_PRESENT ? 0 : (OPT_LEN + OPT_RDATA);
}


void
edns_rr_cleanup(edns_rr_type* err)
{
    if (!err)
	return;
    free(err);
}
