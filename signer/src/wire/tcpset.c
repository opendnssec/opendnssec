/*
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
 * TCP connections.
 *
 */

#include "config.h"
#include "wire/tcpset.h"

#include <string.h>

static const char* tcp_str = "tcp";


/**
 * Create a tcp connection.
 *
 */
tcp_conn_type*
tcp_conn_create(allocator_type* allocator)
{
    tcp_conn_type* tcp_conn = NULL;
    if (!allocator) {
        return NULL;
    }
    tcp_conn = (tcp_conn_type*) allocator_alloc(allocator,
        sizeof(tcp_conn_type));
    if (!tcp_conn) {
        return NULL;
    }
    memset(tcp_conn, 0, sizeof(tcp_conn_type));
    tcp_conn->packet = buffer_create(allocator, PACKET_BUFFER_SIZE);
    if (!tcp_conn->packet) {
        allocator_deallocate(allocator, (void*)tcp_conn);
        return NULL;
    }
    tcp_conn->msglen = 0;
    tcp_conn->total_bytes = 0;
    tcp_conn->fd = -1;
    return tcp_conn;
}


/**
 * Create a set of tcp connections.
 *
 */
tcp_set_type*
tcp_set_create(allocator_type* allocator)
{
    size_t i = 0;
    tcp_set_type* tcp_set = NULL;
    tcp_set = (tcp_set_type*) allocator_alloc(allocator, sizeof(tcp_set_type));
    memset(tcp_set, 0, sizeof(tcp_set_type));
    tcp_set->tcp_count = 0;
    for (i=0; i < TCPSET_MAX; i++) {
        tcp_set->tcp_conn[i] = tcp_conn_create(allocator);
    }
    tcp_set->tcp_waiting_first = NULL;
    tcp_set->tcp_waiting_last = NULL;
    return tcp_set;
}


/**
 * Make tcp connection ready for reading.
 * \param[in] tcp tcp connection
 *
 */
void
tcp_conn_ready(tcp_conn_type* tcp)
{
    ods_log_assert(tcp);
    tcp->total_bytes = 0;
    tcp->msglen = 0;
    buffer_clear(tcp->packet);
    return;
}


/*
 * Read from a tcp connection.
 *
 */
int
tcp_conn_read(tcp_conn_type* tcp)
{
    ssize_t received = 0;
    ods_log_assert(tcp);
    ods_log_assert(tcp->fd != -1);
    /* receive leading packet length bytes */
    if (tcp->total_bytes < sizeof(tcp->msglen)) {
        received = read(tcp->fd, (char*) &tcp->msglen + tcp->total_bytes,
            sizeof(tcp->msglen) - tcp->total_bytes);
        if (received == -1) {
            if (errno == EAGAIN || errno == EINTR) {
                /* read would block, try later */
                return 0;
            } else {
                if (errno != ECONNRESET) {
                    ods_log_error("[%s] error read() sz: %s", tcp_str,
                        strerror(errno));
                }
                return -1;
            }
        } else if (received == 0) {
            /* EOF */
            return -1;
        }
        tcp->total_bytes += received;
        if (tcp->total_bytes < sizeof(tcp->msglen)) {
            /* not complete yet, try later */
            return 0;
        }
        ods_log_assert(tcp->total_bytes == sizeof(tcp->msglen));
        tcp->msglen = ntohs(tcp->msglen);
        if (tcp->msglen > buffer_capacity(tcp->packet)) {
            /* packet to big, drop connection */
            ods_log_error("[%s] packet too big, dropping connection", tcp_str);
            return 0;
        }
        buffer_set_limit(tcp->packet, tcp->msglen);
    }
    ods_log_assert(buffer_remaining(tcp->packet) > 0);

    received = read(tcp->fd, buffer_current(tcp->packet),
        buffer_remaining(tcp->packet));
    if (received == -1) {
        if (errno == EAGAIN || errno == EINTR) {
            /* read would block, try later */
            return 0;
        } else {
            if (errno != ECONNRESET) {
                ods_log_error("[%s] error read(): %s", tcp_str,
                    strerror(errno));
            }
            return -1;
        }
    } else if (received == 0) {
        /* EOF */
        return -1;
    }
    tcp->total_bytes += received;
    buffer_skip(tcp->packet, received);
    if (buffer_remaining(tcp->packet) > 0) {
        /* not complete yet, wait for more */
        return 0;
    }
    /* completed */
    ods_log_assert(buffer_position(tcp->packet) == tcp->msglen);
    return 1;
}


/*
 * Write to a tcp connection.
 *
 */
int
tcp_conn_write(tcp_conn_type* tcp)
{
    ssize_t sent = 0;
    ods_log_assert(tcp);
    ods_log_assert(tcp->fd != -1);
    if (tcp->total_bytes < sizeof(tcp->msglen)) {
        uint16_t sendlen = htons(tcp->msglen);
        sent = write(tcp->fd, (const char*)&sendlen + tcp->total_bytes,
            sizeof(tcp->msglen) - tcp->total_bytes);
        if (sent == -1) {
            if (errno == EAGAIN || errno == EINTR) {
                /* write would block, try later */
                return 0;
            } else {
                return -1;
            }
        }
        tcp->total_bytes += sent;
        if (tcp->total_bytes < sizeof(tcp->msglen)) {
            /* incomplete write, resume later */
            return 0;
        }
        ods_log_assert(tcp->total_bytes == sizeof(tcp->msglen));
    }
    ods_log_assert(tcp->total_bytes < tcp->msglen + sizeof(tcp->msglen));
    sent = write(tcp->fd, buffer_current(tcp->packet),
        buffer_remaining(tcp->packet));
    if (sent == -1) {
        if (errno == EAGAIN || errno == EINTR) {
            /* write would block, try later */
            return 0;
        } else {
            return -1;
        }
    }
    buffer_skip(tcp->packet, sent);
    tcp->total_bytes += sent;
    if (tcp->total_bytes < tcp->msglen + sizeof(tcp->msglen)) {
        /* more to write when socket becomes writable again */
        return 0;
    }
    ods_log_assert(tcp->total_bytes == tcp->msglen + sizeof(tcp->msglen));
    return 1;
}


/**
 * Clean up tcp connection.
 *
 */
static void
tcp_conn_cleanup(tcp_conn_type* conn, allocator_type* allocator)
{
    if (!conn || !allocator) {
        return;
    }
    buffer_cleanup(conn->packet, allocator);
    allocator_deallocate(allocator, (void*) conn);
    return;
}

/**
 * Clean up set of tcp connections.
 *
 */
void
tcp_set_cleanup(tcp_set_type* set, allocator_type* allocator)
{
    size_t i = 0;
    if (!set || !allocator) {
        return;
    }
    for (i=0; i < TCPSET_MAX; i++) {
        tcp_conn_cleanup(set->tcp_conn[i], allocator);
    }
    allocator_deallocate(allocator, (void*) set);
    return;
}
