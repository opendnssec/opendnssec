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
 * Packet buffer.
 *
 */

#ifndef WIRE_BUFFER_H
#define WIRE_BUFFER_H

#include "config.h"
#include "status.h"
#include "log.h"
#include "status.h"

#include <ldns/ldns.h>
#include <stdint.h>

#define BUFFER_PKT_HEADER_SIZE 12
#define MAXDOMAINLEN 255
#define MAXLABELLEN 63
#define MAX_RDLENGTH    65535
#define MAX_RR_SIZE \
        (MAXDOMAINLEN + sizeof(uint32_t) + 4*sizeof(uint16_t) + MAX_RDLENGTH)
#define MAX_PACKET_SIZE 65535
#define PACKET_BUFFER_SIZE (MAX_PACKET_SIZE + MAX_RR_SIZE)

#define QR_MASK         0x80U
#define QR_SHIFT        7
#define QR(packet)      (*buffer_at((packet), 2) & QR_MASK)
#define QR_SET(packet)  (*buffer_at((packet), 2) |= QR_MASK)
#define QR_CLR(packet)  (*buffer_at((packet), 2) &= ~QR_MASK)

#define OPCODE_MASK     0x78U
#define OPCODE_SHIFT    3
#define OPCODE(packet)  ((*buffer_at((packet), 2) & OPCODE_MASK) >> OPCODE_SHIFT)
#define OPCODE_SET(packet, opcode) \
        (*buffer_at((packet), 2) = (*buffer_at((packet), 2) & ~OPCODE_MASK) | ((opcode) << OPCODE_SHIFT))

#define AA_MASK         0x04U
#define AA_SHIFT        2
#define AA(packet)      (*buffer_at((packet), 2) & AA_MASK)
#define AA_SET(packet)  (*buffer_at((packet), 2) |= AA_MASK)
#define AA_CLR(packet)  (*buffer_at((packet), 2) &= ~AA_MASK)

#define TC_MASK         0x02U
#define TC_SHIFT        1
#define TC(packet)      (*buffer_at((packet), 2) & TC_MASK)
#define TC_SET(packet)  (*buffer_at((packet), 2) |= TC_MASK)
#define TC_CLR(packet)  (*buffer_at((packet), 2) &= ~TC_MASK)

#define RD_MASK         0x01U
#define RD_SHIFT        0
#define RD(packet)      (*buffer_at((packet), 2) & RD_MASK)
#define RD_SET(packet)  (*buffer_at((packet), 2) |= RD_MASK)
#define RD_CLR(packet)  (*buffer_at((packet), 2) &= ~RD_MASK)

#define RA_MASK         0x80U
#define RA_SHIFT        7
#define RA(packet)      (*buffer_at((packet), 3) & RA_MASK)
#define RA_SET(packet)  (*buffer_at((packet), 3) |= RA_MASK)
#define RA_CLR(packet)  (*buffer_at((packet), 3) &= ~RA_MASK)

#define AD_MASK         0x20U
#define AD_SHIFT        5
#define AD(packet)      (*buffer_at((packet), 3) & AD_MASK)
#define AD_SET(packet)  (*buffer_at((packet), 3) |= AD_MASK)
#define AD_CLR(packet)  (*buffer_at((packet), 3) &= ~AD_MASK)

#define CD_MASK         0x10U
#define CD_SHIFT        4
#define CD(packet)      (*buffer_at((packet), 3) & CD_MASK)
#define CD_SET(packet)  (*buffer_at((packet), 3) |= CD_MASK)
#define CD_CLR(packet)  (*buffer_at((packet), 3) &= ~CD_MASK)

#define RCODE_MASK      0x0fU
#define RCODE_SHIFT     0
#define RCODE(packet)   (*buffer_at((packet), 3) & RCODE_MASK)
#define RCODE_SET(packet, rcode) \
        (*buffer_at((packet), 3) = (*buffer_at((packet), 3) & ~RCODE_MASK) | (rcode))

extern ods_lookup_table ods_rcode_str[];

/**
 * Buffer.
 */
typedef struct buffer_struct buffer_type;
struct buffer_struct {
    size_t position;
    size_t limit;
    size_t capacity;
    uint8_t* data;
    unsigned fixed : 1;
};

/**
 * Create a new buffer with the specified capacity.
 * \param[in] allocator memory allocator
 * \param[in] capacity specified capacity
 * \return buffer_type* buffer
 *
 */
extern buffer_type* buffer_create(size_t capacity);

/**
 * Clear the buffer and make it ready for writing.
 * The buffer's limit is set to the capacity and the position is set to 0.
 * \param[in] buffer buffer
 *
 */
extern void buffer_clear(buffer_type* buffer);

/**
 * Flip the buffer and make it ready for reading.
 * The data that has been written to the buffer.
 * The buffer's limit is set to the current position and the position is set
 * to 0.
 * \param[in] buffer buffer
 *
 */
void buffer_flip(buffer_type* buffer);

/**
 * Get the buffer's position.
 * \param[in] buffer buffer
 * \return size_t position
 *
 */
extern size_t buffer_position(buffer_type* buffer);

/**
 * Set the buffer's position.
 * The position must be less than or equal to the buffer's limit.
 * \param[in] buffer buffer
 * \param[in] pos position
 *
 */
extern void buffer_set_position(buffer_type* buffer, size_t pos);

/**
 * Change the buffer's position.
 * The position must not be moved behind the buffer's limit or before the
 * beginning of the buffer.
 * \param[in] buffer buffer
 * \param[in] count number of bytes to skip
 *
 */
extern void buffer_skip(buffer_type* buffer, ssize_t count);

/**
 * Change the buffer's position so that one dname is skipped.
 * \param[in] buffer buffer
 * \return int 0 if dname skipping failed
 *             1 otherwise
 *
 */
extern int buffer_skip_dname(buffer_type* buffer);

/**
 * Change the buffer's position so that one RR is skipped.
 * \param[in] buffer buffer
 * \param[in] qrr 1 if we skip RRs in the question section.
 * \return int 0 if RR skipping failed
 *             1 otherwise
 *
 */
extern int buffer_skip_rr(buffer_type* buffer, unsigned qrr);

/**
 * Get the buffer's limit.
 * \param[in] buffer buffer
 * \return size_t limit
 *
 */
extern size_t buffer_limit(buffer_type* buffer);

/**
 * Set the buffer's limit. If the buffer's position is greater
 * than the new limit, the position is set to the limit.
 * \param[in] buffer buffer
 * \param[in] limit limit
 *
 */
extern void buffer_set_limit(buffer_type* buffer, size_t limit);

/**
 * Get the buffer's capacity.
 * \param[in] buffer buffer
 * \return size_t capacity
 *
 */
extern size_t buffer_capacity(buffer_type* buffer);

/**
 * Return a pointer to the data at the indicated position.
 * \param[in] buffer buffer
 * \param[in] at indicated position
 * \return uint8_t* pointer to the data at the indicated position
 *
 */
extern uint8_t* buffer_at(buffer_type* buffer, size_t at);

/**
 * Return a pointer to the data at the beginning of the buffer.
 * \param[in] buffer buffer
 * \return uint8_t* pointer to the data at the begin of the buffer
 *
 */
extern uint8_t* buffer_begin(buffer_type* buffer);

/**
 * Return a pointer to the data at the buffer's current position.
 * \param[in] buffer buffer
 * \return uint8_t* pointer to the data at the buffer's current position
 *
 */
extern uint8_t* buffer_current(buffer_type* buffer);

/**
 * The number of bytes remaining between the buffer's position and limit.
 * \param[in] buffer buffer
 * \return size_t remaining number of bytes
 *
 */
extern size_t buffer_remaining(buffer_type* buffer);

/**
 * Check if the buffer has enough bytes available.
 * \param[in] buffer buffer
 * \param[in] count number of bytes that needs to be available
 * \return int 0 if not enough bytes are available
 *             1 otherwise
 *
 */
extern int buffer_available(buffer_type* buffer, size_t count);

/**
 * Write to buffer.
 * \param[in] buffer buffer
 * \param[in] data data to write
 * \param[in] count number of bytes to write
 *
 */
extern void buffer_write(buffer_type* buffer, const void* data, size_t count);

/**
 * Write uint8_t to buffer.
 * \param[in] buffer buffer
 * \param[in] data data to write
 *
 */
extern void buffer_write_u8(buffer_type* buffer, uint8_t data);

/**
 * Write uint16_t to buffer.
 * \param[in] buffer buffer
 * \param[in] data data to write
 *
 */
extern void buffer_write_u16(buffer_type* buffer, uint16_t data);

/**
 * Write uint16_t to buffer at indicated position.
 * \param[in] buffer buffer
 * \param[in] at indicated position
 * \param[in] data data to write
 *
 */
extern void buffer_write_u16_at(buffer_type* buffer, size_t at, uint16_t data);

/**
 * Write uint32_t to buffer.
 * \param[in] buffer buffer
 * \param[in] data data to write
 *
 */
extern void buffer_write_u32(buffer_type* buffer, uint32_t data);

/**
 * Write rdf to buffer.
 * \param[in] buffer buffer
 * \param[in] rdf data to write
 *
 */
extern void buffer_write_rdf(buffer_type* buffer, ldns_rdf* rdf);

/**
 * Write rr to buffer.
 * \param[in] buffer buffer
 * \param[in] rr data to write
 * \return int 1 if rr fits, 0 otherwise
 *
 */
extern int buffer_write_rr(buffer_type* buffer, ldns_rr* rr);

/**
 * Read from buffer.
 * \param[in] buffer buffer
 * \param[in] data read data
 * \param[in] count number of bytes to read
 *
 */
extern void buffer_read(buffer_type* buffer, void* data, size_t count);

/**
 * Read uint8_t from buffer.
 * \param[in] buffer buffer
 * \return uint8_t read data
 *
 */
extern uint8_t buffer_read_u8(buffer_type* buffer);

/**
 * Read uint16_t from buffer.
 * \param[in] buffer buffer
 * \return uint16_t read data
 *
 */
extern uint16_t buffer_read_u16(buffer_type* buffer);

/**
 * Read uint32_t from buffer.
 * \param[in] buffer buffer
 * \return uint32_t read data
 *
 */
extern uint32_t buffer_read_u32(buffer_type* buffer);

/**
 * Read dname from buffer.
 * \param[in] buffer buffer
 * \param[out] dname dname
 * \param[in] allow_pointers allow pointer labels
 * \return int dname length
 *
 */
extern size_t buffer_read_dname(buffer_type* buffer, uint8_t* dname,
    unsigned allow_pointers);

/**
 * Get query id from buffer.
 * \param[in] buffer buffer
 * \return uint16_t query id
 *
 */
extern uint16_t buffer_pkt_id(buffer_type* buffer);

/**
 * Set random query id in buffer.
 * \param[in] buffer buffer
 *
 */
extern void buffer_pkt_set_random_id(buffer_type* buffer);

/**
 * Get flags from buffer.
 * \param[in] buffer buffer
 * \return uint16_t flags
 *
 */
extern uint16_t buffer_pkt_flags(buffer_type* buffer);

/**
 * Set flags in buffer.
 * \param[in] buffer buffer
 * \param[in] flags flags
 *
 */
extern void buffer_pkt_set_flags(buffer_type* buffer, uint16_t flags);

/**
 * Get QR bit from buffer.
 * \param[in] buffer buffer
 * \return int 0 if QR bit is clear
 *             1 if QR bit is set
 *
 */
extern int buffer_pkt_qr(buffer_type* buffer);

/**
 * Set QR bit in buffer.
 * \param[in] buffer buffer
 *
 */
extern void buffer_pkt_set_qr(buffer_type* buffer);

/**
 * Clear QR bit in buffer.
 * \param[in] buffer buffer
 *
 */
extern void buffer_pkt_clear_qr(buffer_type* buffer);

/**
 * Get AA bit from buffer.
 * \param[in] buffer buffer
 * \return int 0 if AA bit is clear
 *             1 if AA bit is set
 *
 */
extern int buffer_pkt_aa(buffer_type* buffer);

/**
 * Set AA bit in buffer.
 * \param[in] buffer buffer
 *
 */
extern void buffer_pkt_set_aa(buffer_type* buffer);

/**
 * Get TC bit from buffer.
 * \param[in] buffer buffer
 * \return int 0 if TC bit is clear
 *             1 if TC bit is set
 *
 */
extern int buffer_pkt_tc(buffer_type* buffer);

/**
 * Get RD bit from buffer.
 * \param[in] buffer buffer
 * \return int 0 if RD bit is clear
 *             1 if RD bit is set
 *
 */
extern int buffer_pkt_rd(buffer_type* buffer);

/**
 * Get RA bit from buffer.
 * \param[in] buffer buffer
 * \return int 0 if RA bit is clear
 *             1 if RA bit is set
 *
 */
extern int buffer_pkt_ra(buffer_type* buffer);

/**
 * Get AD bit from buffer.
 * \param[in] buffer buffer
 * \return int 0 if AD bit is clear
 *             1 if AD bit is set
 *
 */
extern int buffer_pkt_ad(buffer_type* buffer);

/**
 * Get CD bit from buffer.
 * \param[in] buffer buffer
 * \return int 0 if CD bit is clear
 *             1 if CD bit is set
 *
 */
extern int buffer_pkt_cd(buffer_type* buffer);

/**
 * Get OPCODE from buffer.
 * \param[in] buffer buffer
 * \return ldns_pkt_opcode OPCODE
 *
 */
extern ldns_pkt_opcode buffer_pkt_opcode(buffer_type* buffer);

/**
 * Set OPCODE in buffer.
 * \param[in] buffer buffer
 * \param[in] opcode OPCODE
 *
 */
extern void buffer_pkt_set_opcode(buffer_type* buffer, ldns_pkt_opcode opcode);

/**
 * Get RCODE from buffer.
 * \param[in] buffer buffer
 * \return ldns_pkt_rcode RCODE
 *
 */
extern ldns_pkt_rcode buffer_pkt_rcode(buffer_type* buffer);

/**
 * Set RCODE in buffer.
 * \param[in] buffer buffer
 * \param[in] rcode RCODE
 *
 */
extern void buffer_pkt_set_rcode(buffer_type* buffer, ldns_pkt_rcode rcode);

/**
 * Look up a descriptive text by each rcode.
 * \param[in] rcode rcode
 * \return const char* descriptive text
 *
 */
extern const char* buffer_rcode2str(ldns_pkt_rcode rcode);

/**
 * Get QDCOUNT from buffer.
 * \param[in] buffer buffer
 * \return uint16_t QDCOUNT
 *
 */
extern uint16_t buffer_pkt_qdcount(buffer_type* buffer);

/**
 * Set QDCOUNT in buffer.
 * \param[in] buffer buffer
 * \param[in] count QDCOUNT
 *
 */
extern void buffer_pkt_set_qdcount(buffer_type* buffer, uint16_t count);

/**
 * Get ANCOUNT from buffer.
 * \param[in] buffer buffer
 * \return uint16_t ANCOUNT
 *
 */
extern uint16_t buffer_pkt_ancount(buffer_type* buffer);

/**
 * Set ANCOUNT in buffer.
 * \param[in] buffer buffer
 * \param[in] count ANCOUNT
 *
 */
extern void buffer_pkt_set_ancount(buffer_type* buffer, uint16_t count);

/**
 * Get NSCOUNT from buffer.
 * \param[in] buffer buffer
 * \return uint16_t NSCOUNT
 *
 */
extern uint16_t buffer_pkt_nscount(buffer_type* buffer);

/**
 * Set NSCOUNT in buffer.
 * \param[in] buffer buffer
 * \param[in] count NSCOUNT
 *
 */
extern void buffer_pkt_set_nscount(buffer_type* buffer, uint16_t count);

/**
 * Get ARCOUNT from buffer.
 * \param[in] buffer buffer
 * \return uint16_t ARCOUNT
 *
 */
extern uint16_t buffer_pkt_arcount(buffer_type* buffer);

/**
 * Set ARCOUNT in buffer.
 * \param[in] buffer buffer
 * \param[in] count ARCOUNT
 *
 */
extern void buffer_pkt_set_arcount(buffer_type* buffer, uint16_t count);

/**
 * Make a new query.
 * \param[in] buffer buffer
 * \param[in] qname qname
 * \param[in] qtype qtype
 * \param[in] qclass qclass
 *
 */
extern void
buffer_pkt_query(buffer_type* buffer, ldns_rdf* qname, ldns_rr_type qtype,
   ldns_rr_class qclass);

/**
 * Make a new notify.
 * \param[in] buffer buffer
 * \param[in] qname qname
 * \param[in] qclass qclass
 *
 */
extern void
buffer_pkt_notify(buffer_type* buffer, ldns_rdf* qname, ldns_rr_class qclass);

/**
 * Clean up buffer.
 * \param[in] buffer buffer
 * \param[in] allocator memory allocator
 *
 */
extern void buffer_cleanup(buffer_type* buffer);

/** UTIL **/

/*
 * Copy data allowing for unaligned accesses in network byte order
 * (big endian).
 */

static inline uint16_t
read_uint16(const void *src)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
    return ntohs(* (uint16_t *) src);
#else
    uint8_t *p = (uint8_t *) src;
    return (p[0] << 8) | p[1];
#endif
}

static inline uint32_t
read_uint32(const void *src)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
    return ntohl(* (uint32_t *) src);
#else
    uint8_t *p = (uint8_t *) src;
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
#endif
}

static inline void
write_uint16(void *dst, uint16_t data)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
    * (uint16_t *) dst = htons(data);
#else
    uint8_t *p = (uint8_t *) dst;
    p[0] = (uint8_t) ((data >> 8) & 0xff);
    p[1] = (uint8_t) (data & 0xff);
#endif
}

static inline void
write_uint32(void *dst, uint32_t data)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
    * (uint32_t *) dst = htonl(data);
#else
    uint8_t *p = (uint8_t *) dst;
    p[0] = (uint8_t) ((data >> 24) & 0xff);
    p[1] = (uint8_t) ((data >> 16) & 0xff);
    p[2] = (uint8_t) ((data >> 8) & 0xff);
    p[3] = (uint8_t) (data & 0xff);
#endif
}

#endif /* WIRE_BUFFER_H */
