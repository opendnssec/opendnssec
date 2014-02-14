/*
 * $Id: buffer.c 4958 2011-04-18 07:11:09Z matthijs $
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
 * Packet buffer.
 *
 *                                    1  1  1  1  1  1
 *      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 01 |                      ID                       |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 23 |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 45 |                    QDCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 67 |                    ANCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 89 |                    NSCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 01 |                    ARCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */


#include "config.h"
#include "shared/log.h"
#include "wire/buffer.h"

#include <string.h>

static const char* buffer_str = "buffer";

ods_lookup_table ods_rcode_str[] = {
    { LDNS_RCODE_NOERROR, "NOERROR" },
    { LDNS_RCODE_FORMERR, "FORMERR" },
    { LDNS_RCODE_SERVFAIL, "SERVFAIL" },
    { LDNS_RCODE_NXDOMAIN, "NXDOMAIN" },
    { LDNS_RCODE_NOTIMPL, "NOTIMPL" },
    { LDNS_RCODE_REFUSED, "REFUSED" },
    { LDNS_RCODE_YXDOMAIN, "YXDOMAIN" },
    { LDNS_RCODE_YXRRSET, "YXRRSET" },
    { LDNS_RCODE_NXRRSET, "NXRRSET" },
    { LDNS_RCODE_NOTAUTH, "NOTAUTH" },
    { LDNS_RCODE_NOTZONE, "NOTZONE" },
    { 0, NULL }
};


/**
 * Create a new buffer with the specified capacity.
 *
 */
buffer_type*
buffer_create(allocator_type* allocator, size_t capacity)
{
    buffer_type* buffer = NULL;
    if (!allocator || !capacity) {
        return NULL;
    }
    buffer = (buffer_type *) allocator_alloc(allocator, sizeof(buffer_type));
    if (!buffer) {
        return NULL;
    }
    buffer->data = (uint8_t*) calloc(capacity, sizeof(uint8_t));
    buffer->position = 0;
    buffer->limit = capacity;
    buffer->capacity = capacity;
    buffer->fixed = 0;
    return buffer;
}


/**
 * Create a buffer with the specified data.
 *
 */
void
buffer_create_from(buffer_type* buffer, void* data, size_t size)
{
    ods_log_assert(buffer);
    buffer->data = (uint8_t*) data;
    buffer->position = 0;
    buffer->limit = size;
    buffer->capacity = size;
    buffer->fixed = 1;
    return;
}


/**
 * Clear the buffer and make it ready for writing.
 *
 */
void
buffer_clear(buffer_type* buffer)
{
    ods_log_assert(buffer);
    buffer->position = 0;
    buffer->limit = buffer->capacity;
    return;
}


/**
 * Flip the buffer and make it ready for reading.
 *
 */
void
buffer_flip(buffer_type* buffer)
{
    ods_log_assert(buffer);
    buffer->limit = buffer->position;
    buffer->position = 0;
    return;
}


/**
 * Make the buffer ready for re-reading the data.
 *
 */
void
buffer_rewind(buffer_type* buffer)
{
    ods_log_assert(buffer);
    buffer->position = 0;
    return;
}


/**
 * Get the buffer's position.
 *
 */
size_t
buffer_position(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer->position;
}


/**
 * Set the buffer's position.
 *
 */
void
buffer_set_position(buffer_type* buffer, size_t pos)
{
    ods_log_assert(buffer);
    ods_log_assert(pos <= buffer->limit);
    buffer->position = pos;
    return;
}


/**
 * Change the buffer's position.
 *
 */
void
buffer_skip(buffer_type* buffer, ssize_t count)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer->position + count <= buffer->limit);
    buffer->position += count;
    return;
}


/**
 * Get bit.
 *
 */
static int
get_bit(uint8_t bits[], size_t index)
{
    return bits[index / 8] & (1 << (7 - index % 8));
}


/**
 * Set bit.
 *
 */
static void
set_bit(uint8_t bits[], size_t index)
{
    bits[index / 8] |= (1 << (7 - index % 8));
    return;
}


/**
 * Is pointer label>
 *
 */
static int
label_is_pointer(const uint8_t* label)
{
    ods_log_assert(label);
    return (label[0] & 0xc0) == 0xc0;
}


/**
 * Pointer label location.
 *
 */
static uint16_t
label_pointer_location(const uint8_t* label)
{
    ods_log_assert(label);
    ods_log_assert(label_is_pointer(label));
    return ((uint16_t) (label[0] & ~0xc0) << 8) | (uint16_t) label[1];
}


/**
 * Is normal label?
 *
 */
static int
label_is_normal(const uint8_t* label)
{
    ods_log_assert(label);
    return (label[0] & 0xc0) == 0;
}

/*
 * Is root label?
 *
 */
static inline int
label_is_root(const uint8_t* label)
{
    ods_log_assert(label);
    return label[0] == 0;
}


/*
 * Label length.
 *
 */
static uint8_t
label_length(const uint8_t* label)
{
    ods_log_assert(label);
    ods_log_assert(label_is_normal(label));
    return label[0];
}


/**
 * Read dname from buffer.
 *
 */
size_t
buffer_read_dname(buffer_type* buffer, uint8_t* dname, unsigned allow_pointers)
{
    int done = 0;
    uint8_t visited[(MAX_PACKET_SIZE+7)/8];
    size_t dname_length = 0;
    const uint8_t *label = NULL;
    ssize_t mark = -1;
    ods_log_assert(buffer);
    memset(visited, 0, (buffer_limit(buffer)+7)/8);

    while (!done) {
        if (!buffer_available(buffer, 1)) {
            return 0;
        }
        if (get_bit(visited, buffer_position(buffer))) {
            ods_log_error("[%s] dname loop!", buffer_str);
            return 0;
        }
        set_bit(visited, buffer_position(buffer));
        label = buffer_current(buffer);
        if (label_is_pointer(label)) {
            size_t pointer = 0;
            if (!allow_pointers) {
                return 0;
            }
            if (!buffer_available(buffer, 2)) {
                return 0;
            }
            pointer = label_pointer_location(label);
            if (pointer >= buffer_limit(buffer)) {
                return 0;
            }
            buffer_skip(buffer, 2);
            if (mark == -1) {
                mark = buffer_position(buffer);
            }
            buffer_set_position(buffer, pointer);
        } else if (label_is_normal(label)) {
            size_t length = label_length(label) + 1;
            done = label_is_root(label);
            if (!buffer_available(buffer, length)) {
                return 0;
            }
            if (dname_length + length >= MAXDOMAINLEN+1) {
                return 0;
            }
            buffer_read(buffer, dname + dname_length, length);
            dname_length += length;
        } else {
            return 0;
        }
     }
     if (mark != -1) {
        buffer_set_position(buffer, mark);
     }
     return dname_length;
}


/**
 * Change the buffer's position so that one dname is skipped.
 *
 */
int
buffer_skip_dname(buffer_type* buffer)
{
    ods_log_assert(buffer);
    while (1) {
        uint8_t label_size = 0;
        if (!buffer_available(buffer, 1)) {
            return 0;
        }
        label_size = buffer_read_u8(buffer);
        if (label_size == 0) {
            break;
        } else if ((label_size & 0xc0) != 0) {
            if (!buffer_available(buffer, 1)) {
                return 0;
            }
            buffer_skip(buffer, 1);
            break;
        } else if (!buffer_available(buffer, label_size)) {
            return 0;
        } else {
            buffer_skip(buffer, label_size);
        }
    }
    return 1;
}


/**
 * Change the buffer's position so that one RR is skipped.
 *
 */
int
buffer_skip_rr(buffer_type* buffer, unsigned qrr)
{
    if (!buffer_skip_dname(buffer)) {
        return 0;
    }
    if (qrr) {
        if (!buffer_available(buffer, 4)) {
            return 0;
        }
        buffer_skip(buffer, 4);
    } else {
        uint16_t rdata_size;
        if (!buffer_available(buffer, 10)) {
            return 0;
        }
        buffer_skip(buffer, 8);
        rdata_size = buffer_read_u16(buffer);
        if (!buffer_available(buffer, rdata_size)) {
            return 0;
        }
        buffer_skip(buffer, rdata_size);
    }
    return 1;
}


/**
 * Get the buffer's limit.
 *
 */
size_t
buffer_limit(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer->limit;
}


/**
 * Set the buffer's limit.
 *
 */
void
buffer_set_limit(buffer_type* buffer, size_t limit)
{
    ods_log_assert(buffer);
    ods_log_assert(limit <= buffer->capacity);
    buffer->limit = limit;
    if (buffer->position > buffer->limit) {
        buffer->position = buffer->limit;
    }
    return;
}


/**
 * Get the buffer's capacity.
 *
 */
size_t
buffer_capacity(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer->capacity;
}


/**
 * Return a pointer to the data at the indicated position.
 *
 */
uint8_t*
buffer_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    ods_log_assert(at <= buffer->limit);
    return buffer->data + at;
}


/**
 * Return a pointer to the data at the beginning of the buffer.
 *
 */
uint8_t*
buffer_begin(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_at(buffer, 0);
}


/**
 * Return a pointer to the data at the end of the buffer.
 *
 */
uint8_t*
buffer_end(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_at(buffer, buffer->limit);
}


/**
 * Return a pointer to the data at the buffer's current position.
 *
 */
uint8_t*
buffer_current(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_at(buffer, buffer->position);
}


/**
 * The number of bytes remaining between the at and limit.
 *
 */
static size_t
buffer_remaining_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    ods_log_assert(at <= buffer->limit);
    return buffer->limit - at;
}


/**
 * The number of bytes remaining between the buffer's position and limit.
 *
 */
size_t
buffer_remaining(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_remaining_at(buffer, buffer->position);
}


/**
 * Check if the buffer has enough bytes available at indicated position.
 *
 */
static int
buffer_available_at(buffer_type *buffer, size_t at, size_t count)
{
    ods_log_assert(buffer);
    return count <= buffer_remaining_at(buffer, at);
}


/**
 * Check if the buffer has enough bytes available.
 *
 */
int
buffer_available(buffer_type *buffer, size_t count)
{
    ods_log_assert(buffer);
    return buffer_available_at(buffer, buffer->position, count);
}


/**
 * Write to buffer at indicated position.
 *
 */
static void
buffer_write_u8_at(buffer_type* buffer, size_t at, uint8_t data)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer_available_at(buffer, at, sizeof(data)));
    buffer->data[at] = data;
    return;
}


/**
 * Write to buffer at indicated position.
 *
 */
void
buffer_write_u16_at(buffer_type* buffer, size_t at, uint16_t data)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer_available_at(buffer, at, sizeof(data)));
    write_uint16(buffer->data + at, data);
    return;
}


/**
 * Write to buffer at indicated position.
 *
 */
static void
buffer_write_u32_at(buffer_type* buffer, size_t at, uint32_t data)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer_available_at(buffer, at, sizeof(data)));
    write_uint32(buffer->data + at, data);
    return;
}


/**
 * Write to buffer.
 *
 */
void
buffer_write(buffer_type* buffer, const void* data, size_t count)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer_available(buffer, count));
    memcpy(buffer->data + buffer->position, data, count);
    buffer->position += count;
    return;
}


/**
 * Write uint8_t to buffer.
 *
 */
void
buffer_write_u8(buffer_type* buffer, uint8_t data)
{
    ods_log_assert(buffer);
    buffer_write_u8_at(buffer, buffer->position, data);
    buffer->position += sizeof(data);
    return;
}


/**
 * Write uint16_t to buffer.
 *
 */
void
buffer_write_u16(buffer_type* buffer, uint16_t data)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, buffer->position, data);
    buffer->position += sizeof(data);
    return;
}


/**
 * Write uint32_t to buffer.
 *
 */
void
buffer_write_u32(buffer_type* buffer, uint32_t data)
{
    ods_log_assert(buffer);
    buffer_write_u32_at(buffer, buffer->position, data);
    buffer->position += sizeof(data);
    return;
}


/**
 * Write rdf to buffer.
 *
 */
void
buffer_write_rdf(buffer_type* buffer, ldns_rdf* rdf)
{
    ods_log_assert(buffer);
    ods_log_assert(rdf);
    buffer_write(buffer, ldns_rdf_data(rdf), ldns_rdf_size(rdf));
    /* position updated by buffer_write() */
    return;
}


/**
 * Write rr to buffer.
 *
 */
int
buffer_write_rr(buffer_type* buffer, ldns_rr* rr)
{
    size_t i = 0;
    size_t tc_mark = 0;
    size_t rdlength_pos = 0;
    uint16_t rdlength = 0;
    ods_log_assert(buffer);
    ods_log_assert(rr);
    /* set truncation mark, in case rr does not fit */
    tc_mark = buffer_position(buffer);
    /* owner type class ttl */
    if (!buffer_available(buffer, ldns_rdf_size(ldns_rr_owner(rr)))) {
        goto buffer_tc;
    }
    buffer_write_rdf(buffer, ldns_rr_owner(rr));
    if (!buffer_available(buffer, sizeof(uint16_t) + sizeof(uint16_t) +
        sizeof(uint32_t) + sizeof(rdlength))) {
        goto buffer_tc;
    }
    buffer_write_u16(buffer, (uint16_t) ldns_rr_get_type(rr));
    buffer_write_u16(buffer, (uint16_t) ldns_rr_get_class(rr));
    buffer_write_u32(buffer, (uint32_t) ldns_rr_ttl(rr));
    /* skip rdlength */
    rdlength_pos = buffer_position(buffer);
    buffer_skip(buffer, sizeof(rdlength));
    /* write rdata */
    for (i=0; i < ldns_rr_rd_count(rr); i++) {
        if (!buffer_available(buffer, ldns_rdf_size(ldns_rr_rdf(rr, i)))) {
            goto buffer_tc;
        }
        buffer_write_rdf(buffer, ldns_rr_rdf(rr, i));
    }
    /* write rdlength */
    rdlength = buffer_position(buffer) - rdlength_pos - sizeof(rdlength);
    buffer_write_u16_at(buffer, rdlength_pos, rdlength);
    /* position updated by buffer_write() */
    return 1;

buffer_tc:
    buffer_set_position(buffer, tc_mark);
    return 0;
}


/**
 * Read uint8_t from buffer at indicated position.
 *
 */
static uint8_t
buffer_read_u8_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    ods_log_assert(at < buffer->capacity);
    return buffer->data[at];

}


/**
 * Read uint16_t from buffer at indicated position.
 *
 */
static uint16_t
buffer_read_u16_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    return read_uint16(buffer->data + at);
}


/**
 * Read uint32_t from buffer at indicated position.
 *
 */
static uint32_t
buffer_read_u32_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    return read_uint32(buffer->data + at);
}


/**
 * Read from buffer.
 *
 */
void
buffer_read(buffer_type* buffer, void* data, size_t count)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer_available(buffer, count));
    memcpy(data, buffer->data + buffer->position, count);
    buffer->position += count;
    return;
}


/**
 * Read uint8_t from buffer.
 *
 */
uint8_t
buffer_read_u8(buffer_type* buffer)
{
    uint16_t result = 0;
    ods_log_assert(buffer);
    result = buffer_read_u8_at(buffer, buffer->position);
    buffer->position += sizeof(uint8_t);
    return result;
}


/**
 * Read uint16_t from buffer.
 *
 */
uint16_t
buffer_read_u16(buffer_type* buffer)
{
    uint16_t result = 0;
    ods_log_assert(buffer);
    result = buffer_read_u16_at(buffer, buffer->position);
    buffer->position += sizeof(uint16_t);
    return result;
}


/**
 * Read uint32_t from buffer.
 *
 */
uint32_t
buffer_read_u32(buffer_type* buffer)
{
    uint32_t result = 0;
    ods_log_assert(buffer);
    result = buffer_read_u32_at(buffer, buffer->position);
    buffer->position += sizeof(uint32_t);
    return result;
}


/**
 * Get query id from buffer.
 *
 */
uint16_t
buffer_pkt_id(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 0);
}

/**
 * Get a random query id.
 *
 */
static uint16_t
random_id(void)
{
    return ldns_get_random();
}

/**
 * Set random query id in buffer.
 *
 */
void
buffer_pkt_set_random_id(buffer_type* buffer)
{
    uint16_t qid = 0;
    ods_log_assert(buffer);
    qid = random_id();
    buffer_write_u16_at(buffer, 0, qid);
    return;
}


/**
 * Get flags from buffer.
 *
 */
uint16_t
buffer_pkt_flags(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (uint16_t) buffer_read_u16_at(buffer, 2);
}


/**
 * Set flags in buffer.
 *
 */
void
buffer_pkt_set_flags(buffer_type* buffer, uint16_t flags)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 2, flags);
    return;
}


/**
 * Get QR bit from buffer.
 *
 */
int
buffer_pkt_qr(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) QR(buffer);
}


/**
 * Set QR bit in buffer.
 *
 */
void
buffer_pkt_set_qr(buffer_type* buffer)
{
    ods_log_assert(buffer);
    QR_SET(buffer);
    return;
}


/**
 * Clear QR bit in buffer.
 *
 */
void
buffer_pkt_clear_qr(buffer_type* buffer)
{
    ods_log_assert(buffer);
    QR_CLR(buffer);
    return;
}


/**
 * Get OPCODE from buffer.
 *
 */
ldns_pkt_opcode
buffer_pkt_opcode(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (ldns_pkt_opcode) OPCODE(buffer);
}


/**
 * Set OPCODE in buffer.
 *
 */
void
buffer_pkt_set_opcode(buffer_type* buffer, ldns_pkt_opcode opcode)
{
    ods_log_assert(buffer);
    OPCODE_SET(buffer, opcode);
    return;
}


/**
 * Get AA bit from buffer.
 *
 */
int
buffer_pkt_aa(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) AA(buffer);
}


/**
 * Set AA bit in buffer.
 *
 */
void
buffer_pkt_set_aa(buffer_type* buffer)
{
    ods_log_assert(buffer);
    AA_SET(buffer);
    return;
}


/**
 * Get TC bit from buffer.
 *
 */
int
buffer_pkt_tc(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) TC(buffer);
}


/**
 * Get RD bit from buffer.
 *
 */
int
buffer_pkt_rd(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) RD(buffer);
}


/**
 * Get RA bit from buffer.
 *
 */
int
buffer_pkt_ra(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) RA(buffer);
}


/**
 * Get AD bit from buffer.
 *
 */
int
buffer_pkt_ad(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) AD(buffer);
}


/**
 * Get CD bit from buffer.
 *
 */
int
buffer_pkt_cd(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) CD(buffer);
}


/**
 * Get RCODE from buffer.
 *
 */
ldns_pkt_rcode
buffer_pkt_rcode(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (ldns_pkt_rcode) RCODE(buffer);
}


/**
 * Set RCODE in buffer.
 *
 */
void
buffer_pkt_set_rcode(buffer_type* buffer, ldns_pkt_rcode rcode)
{
    ods_log_assert(buffer);
    RCODE_SET(buffer, rcode);
    return;
}


/**
 * Look up a descriptive text by each rcode.
 *
 */
const char*
buffer_rcode2str(ldns_pkt_rcode rcode)
{
    ods_lookup_table *lt;
    lt = ods_lookup_by_id(ods_rcode_str, rcode);
    if (lt) {
        return lt->name;
    }
    return NULL;
}


/**
 * Get QDCOUNT from buffer.
 *
 */
uint16_t
buffer_pkt_qdcount(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 4);
}


/**
 * Set QDCOUNT in buffer.
 *
 */
void
buffer_pkt_set_qdcount(buffer_type* buffer, uint16_t count)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 4, count);
    return;
}


/**
 * Get ANCOUNT from buffer.
 *
 */
uint16_t
buffer_pkt_ancount(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 6);
}


/**
 * Set ANCOUNT in buffer.
 *
 */
void
buffer_pkt_set_ancount(buffer_type* buffer, uint16_t count)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 6, count);
    return;
}


/**
 * Get NSCOUNT from buffer.
 *
 */
uint16_t
buffer_pkt_nscount(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 8);
}


/**
 * Set NSCOUNT in buffer.
 *
 */
void
buffer_pkt_set_nscount(buffer_type* buffer, uint16_t count)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 8, count);
    return;
}


/**
 * Get ARCOUNT from buffer.
 *
 */
uint16_t
buffer_pkt_arcount(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 10);
}


/**
 * Set ARCOUNT in buffer.
 *
 */
void
buffer_pkt_set_arcount(buffer_type* buffer, uint16_t count)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 10, count);
    return;
}


/**
 * Make a new packet.
 *
 */
static void
buffer_pkt_new(buffer_type* buffer, ldns_rdf* qname, ldns_rr_type qtype,
   ldns_rr_class qclass, ldns_pkt_opcode opcode)
{
    ods_log_assert(buffer);
    ods_log_assert(qname);
    ods_log_assert(qtype);
    ods_log_assert(qclass);
    /* The header */
    buffer_clear(buffer);
    buffer_pkt_set_random_id(buffer);
    buffer_pkt_set_opcode(buffer, opcode);
    buffer_pkt_clear_qr(buffer);
    buffer_pkt_set_rcode(buffer, LDNS_RCODE_NOERROR);
    buffer_pkt_set_qdcount(buffer, 1);
    buffer_pkt_set_ancount(buffer, 0);
    buffer_pkt_set_nscount(buffer, 0);
    buffer_pkt_set_arcount(buffer, 0);
    buffer_skip(buffer, BUFFER_PKT_HEADER_SIZE);
    /* The question record */
    buffer_write_rdf(buffer, qname);
    buffer_write_u16(buffer, qtype);
    buffer_write_u16(buffer, qclass);
    return;
}


/**
 * Make a new query.
 *
 */
void
buffer_pkt_query(buffer_type* buffer, ldns_rdf* qname, ldns_rr_type qtype,
   ldns_rr_class qclass)
{
    buffer_pkt_new(buffer, qname, qtype, qclass, LDNS_PACKET_QUERY);
    buffer_pkt_set_flags(buffer, 0);
    return;
}


/**
 * Make a new notify.
 *
 */
void
buffer_pkt_notify(buffer_type* buffer, ldns_rdf* qname, ldns_rr_class qclass)
{
    buffer_pkt_new(buffer, qname, LDNS_RR_TYPE_SOA, qclass,
        LDNS_PACKET_NOTIFY);
    return;
}


/**
 * Make a new axfr.
 *
 */
void
buffer_pkt_axfr(buffer_type* buffer, ldns_rdf* qname, ldns_rr_class qclass)
{
    buffer_pkt_new(buffer, qname, LDNS_RR_TYPE_AXFR, qclass,
        LDNS_PACKET_QUERY);
    buffer_pkt_set_qr(buffer);
    return;
}


/**
 * Print packet buffer.
 *
 */
void
buffer_pkt_print(FILE* fd, buffer_type* buffer)
{
    ldns_status status = LDNS_STATUS_OK;
    ldns_pkt* pkt = NULL;
    ods_log_assert(fd);
    ods_log_assert(buffer);
    status = ldns_wire2pkt(&pkt, buffer_begin(buffer),
        buffer_remaining(buffer));
    if (status == LDNS_STATUS_OK) {
        ods_log_assert(pkt);
        ldns_pkt_print(fd, pkt);
        ldns_pkt_free(pkt);
    } else {
        fprintf(fd, ";;\n");
        fprintf(fd, ";; Bogus packet: %s\n", ldns_get_errorstr_by_id(status));
        fprintf(fd, ";;\n");
        fprintf(fd, ";;\n");
        fprintf(fd, "\n");
    }
    return;
}


/**
 * Clean up buffer.
 *
 */
void
buffer_cleanup(buffer_type* buffer, allocator_type* allocator)
{
    if (!buffer || !allocator) {
        return;
    }
    free((void*)buffer->data);
    allocator_deallocate(allocator, (void*) buffer);
    return;
}


