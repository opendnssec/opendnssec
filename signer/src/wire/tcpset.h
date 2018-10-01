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
 * TCP connections.
 *
 */

#ifndef WIRE_TCPSET_H
#define WIRE_TCPSET_H

#include "config.h"
#include <stdint.h>

typedef struct tcp_conn_struct tcp_conn_type;
typedef struct tcp_set_struct tcp_set_type;

#include "status.h"
#include "wire/buffer.h"
#include "wire/xfrd.h"

#define TCPSET_MAX 50

/**
 * tcp connection.
 *
 */
struct tcp_conn_struct {
   int fd;
   /* how many bytes have been read/written - total, incl. tcp length bytes */
   uint32_t total_bytes;
   /* msg len bytes */
   uint16_t msglen;
   /* packet buffer of connection */
   buffer_type* packet;
   /* state: reading or writing */
   unsigned is_reading : 1;
};

/*
 * Set of tcp connections.
 *
 */
struct tcp_set_struct {
    tcp_conn_type* tcp_conn[TCPSET_MAX];
    xfrd_type* tcp_waiting_first;
    xfrd_type* tcp_waiting_last;
    size_t tcp_count;
};

/**
 * Create a tcp connection.
 * \param[in] allocator memory allocator
 * \return tcp_conn_type* TCP connection.
 *
 */
tcp_conn_type* tcp_conn_create(void);

/**
 * Create a set of tcp connections.
 * \param[in] allocator memory allocator
 * \return tcp_set_type* set of tcp connection.
 *
 */
tcp_set_type* tcp_set_create(void);

/**
 * Make tcp connection ready for reading.
 * \param[in] tcp tcp connection
 *
 */
void tcp_conn_ready(tcp_conn_type* tcp);

/*
 * Read from a tcp connection.
 * On first call, make sure total_bytes = 0, msglen=0, buffer clear,
 * and the packet and fd need to be set.
 * \param[in] tcp tcp connection
 * \return int -1 on error,
 *              0 on short read,
 *              1 on completed read.
 *
 */
int tcp_conn_read(tcp_conn_type* tcp);

/*
 * Write to a tcp connection.
 * On first call, make sure total_bytes=0, msglen=limit, buffer filled,
 * and the packet and fd need to be set.
 * \param[in] tcp tcp connection
 * \return int -1 on error,
 *              0 on short write,
 *              1 on completed write.
 *
 */
int tcp_conn_write(tcp_conn_type* tcp);

/**
 * Clean up set of tcp connections.
 * \param[in] set set of tcp connections
 * \param[in] allocator memory allocator
 *
 */
void tcp_set_cleanup(tcp_set_type* set);

#endif /* WIRE_TCPSET_H */
