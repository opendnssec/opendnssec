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
 * Sockets.
 *
 */

#ifndef WIRE_SOCK_H
#define WIRE_SOCK_H

#include "config.h"
#include "status.h"
#include "wire/listener.h"
#include "wire/netio.h"
#include "wire/query.h"

/**
 * Socket.
 *
 */
typedef struct sock_struct sock_type;
struct sock_struct {
    struct addrinfo* addr;
    int s;
};

/**
 * List of sockets.
 *
 */
typedef struct socklist_struct socklist_type;
struct socklist_struct {
    sock_type tcp[MAX_INTERFACES];
    sock_type udp[MAX_INTERFACES];
};

/**
 * Data for udp handlers.
 *
 */
struct udp_data {
    engine_type* engine;
    sock_type* socket;
    query_type* query;
};

/**
 * Data for tcp accept handlers.
 *
 */
struct tcp_accept_data {
    engine_type* engine;
    sock_type* socket;
    size_t tcp_accept_handler_count;
    netio_handler_type* tcp_accept_handlers;
};

/**
 * Data for tcp handlers.
 *
 */
struct tcp_data {
    engine_type* engine;
    query_type* query;
    size_t tcp_accept_handler_count;
    netio_handler_type* tcp_accept_handlers;
    query_state qstate;
    size_t bytes_transmitted;
};

/**
 * Create sockets and listen.
 * \param[out] sockets sockets
 * \param[in] listener interfaces
 * \return ods_status status
 *
 */
ods_status sock_listen(socklist_type* sockets, listener_type* listener);

/**
 * Handle incoming udp queries.
 * \param[in] netio network I/O event handler
 * \param[in] handler event handler
 * \param[in] event_types the types of events that should be checked for
 *
 */
void sock_handle_udp(netio_type* netio, netio_handler_type* handler,
    netio_events_type event_types);

/**
 * Handle incoming tcp connections.
 * \param[in] netio network I/O event handler
 * \param[in] handler event handler
 * \param[in] event_types the types of events that should be checked for
 *
 */
void sock_handle_tcp_accept(netio_type* netio, netio_handler_type* handler,
    netio_events_type event_types);

/**
 * Handle incoming tcp queries.
 * \param[in] netio network I/O event handler
 * \param[in] handler event handler
 * \param[in] event_types the types of events that should be checked for
 *
 */
void sock_handle_tcp_read(netio_type* netio, netio_handler_type* handler,
    netio_events_type event_types);

/**
 * Handle outgoing tcp responses.
 * \param[in] netio network I/O event handler
 * \param[in] handler event handler
 * \param[in] event_types the types of events that should be checked for
 *
 */
void sock_handle_tcp_write(netio_type* netio, netio_handler_type* handler,
    netio_events_type event_types);

#endif /* WIRE_SOCK_H */
