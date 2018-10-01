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

#include "config.h"
#include "daemon/engine.h"
#include "log.h"
#include "signer/zone.h"
#include "wire/axfr.h"
#include "wire/netio.h"
#include "wire/sock.h"
#include "wire/xfrd.h"

#include <errno.h>
#include <fcntl.h>
#include <ldns/ldns.h>
#include <unistd.h>

#define SOCK_TCP_BACKLOG 5

static const char* sock_str = "socket";


/**
 * Set udp socket to non-blocking and bind.
 *
 */
static ods_status
sock_fcntl_and_bind(sock_type* sock, const char* node, const char* port,
    const char* stype, const char* fam)
{
    ods_log_assert(sock);
    ods_log_assert(port);
    ods_log_assert(stype);
    ods_log_assert(fam);
    if (fcntl(sock->s, F_SETFL, O_NONBLOCK) == -1) {
        ods_log_error("[%s] unable to set %s/%s socket '%s:%s' to "
            "non-blocking: fcntl() failed (%s)", sock_str, stype, fam,
            node?node:"localhost", port, strerror(errno));
        return ODS_STATUS_SOCK_FCNTL_NONBLOCK;
    }
    ods_log_debug("[%s] bind %s/%s socket '%s:%s': %s", sock_str, stype, fam,
        node?node:"localhost", port, strerror(errno));
    if (bind(sock->s, (struct sockaddr *) sock->addr->ai_addr,
        sock->addr->ai_addrlen) != 0) {
        ods_log_error("[%s] unable to bind %s/%s socket '%s:%s': bind() "
            "failed (%s)", sock_str, stype, fam, node?node:"localhost",
            port, strerror(errno));
        return ODS_STATUS_SOCK_BIND;
    }
    return ODS_STATUS_OK;
}


/**
 * Set socket to v6 only.
 *
 */
static ods_status
sock_v6only(sock_type* sock, const char* node, const char* port, int on,
    const char* stype)
{
    ods_log_assert(sock);
    ods_log_assert(port);
    ods_log_assert(stype);
#ifdef IPV6_V6ONLY
#if defined(IPPROTO_IPV6)
    ods_log_debug("[%s] set %s/ipv6 socket '%s:%s' v6only", sock_str,
        stype, node?node:"localhost", port);
    if (setsockopt(sock->s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
        ods_log_error("[%s] unable to set %s/ipv6 socket '%s:%s' to "
            "ipv6-only: setsockopt() failed (%s)", sock_str, stype,
            node?node:"localhost", port, strerror(errno));
        return ODS_STATUS_SOCK_SETSOCKOPT_V6ONLY;
    }
#endif
#endif /* IPV6_V6ONLY */
    return ODS_STATUS_OK;
}


/**
 * Set tcp socket to reusable.
 *
 */
static void
sock_tcp_reuseaddr(sock_type* sock, const char* node, const char* port,
    int on, const char* fam)
{
    ods_log_assert(sock);
    ods_log_assert(port);
    ods_log_assert(fam);
    if (setsockopt(sock->s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        ods_log_error("[%s] unable to set tcp/%s socket '%s:%s' to "
            "reuse-addr: setsockopt() failed (%s)", sock_str, fam,
            node?node:"localhost", port, strerror(errno));
    }
}


/**
 * Listen on tcp socket.
 *
 */
static ods_status
sock_tcp_listen(sock_type* sock, const char* node, const char* port,
    const char* fam)
{
    ods_log_assert(sock);
    ods_log_assert(port);
    ods_log_assert(fam);
    if (listen(sock->s, SOCK_TCP_BACKLOG) == -1) {
        ods_log_error("[%s] unable to listen on tcp/%s socket '%s:%s': "
            "listen() failed (%s)", sock_str, fam, node?node:"localhost",
            port, strerror(errno));
        return ODS_STATUS_SOCK_LISTEN;
    }
    return ODS_STATUS_OK;
}


/**
 * Create server udp socket.
 *
 */
static ods_status
sock_server_udp(sock_type* sock, const char* node, const char* port,
    unsigned* ip6_support)
{
    int on = 0;
    ods_status status = ODS_STATUS_OK;
    ods_log_assert(sock);
    ods_log_assert(port);
#if defined(SO_REUSEADDR) || defined(IPV6_V6ONLY)
    on = 1;
#endif
    *ip6_support = 1;
    /* socket */
    ods_log_debug("[%s] create udp socket '%s:%s': %s", sock_str,
        node?node:"localhost", port, strerror(errno));
    if ((sock->s = socket(sock->addr->ai_family, SOCK_DGRAM, 0))== -1) {
        ods_log_error("[%s] unable to create udp/ipv4 socket '%s:%s': "
            "socket() failed (%s)", sock_str, node?node:"localhost", port,
            strerror(errno));
        if (sock->addr->ai_family == AF_INET6 && errno == EAFNOSUPPORT) {
            *ip6_support = 0;
        }
        return ODS_STATUS_SOCK_SOCKET_UDP;
    }
    /* ipv4 */
    if (sock->addr->ai_family == AF_INET) {
        status = sock_fcntl_and_bind(sock, node, port, "udp", "ipv4");
    }
    /* ipv6 */
    else if (sock->addr->ai_family == AF_INET6) {
        status = sock_v6only(sock, node, port, on, "udp");
        if (status != ODS_STATUS_OK) {
            return status;
        }
        status = sock_fcntl_and_bind(sock, node, port, "udp", "ipv6");
    }
    return status;
}


/**
 * Create server tcp socket.
 *
 */
static ods_status
sock_server_tcp(sock_type* sock, const char* node, const char* port,
    unsigned* ip6_support)
{
    int on = 0;
    ods_status status = ODS_STATUS_OK;
    ods_log_assert(sock);
    ods_log_assert(port);
#if defined(SO_REUSEADDR) || defined(IPV6_V6ONLY)
    on = 1;
#endif
    *ip6_support = 1;
    /* socket */
    ods_log_debug("[%s] create tcp socket '%s:%s': %s", sock_str,
        node?node:"localhost", port, strerror(errno));
    if ((sock->s = socket(sock->addr->ai_family, SOCK_STREAM, 0))== -1) {
        ods_log_error("[%s] unable to create tcp/ipv4 socket '%s:%s': "
            "socket() failed (%s)", sock_str, node?node:"localhost", port,
            strerror(errno));
        if (sock->addr->ai_family == AF_INET6 && errno == EAFNOSUPPORT) {
            *ip6_support = 0;
        }
        return ODS_STATUS_SOCK_SOCKET_TCP;
    }
    /* ipv4 */
    if (sock->addr->ai_family == AF_INET) {
        sock_tcp_reuseaddr(sock, node, port, on, "ipv4");
        status = sock_fcntl_and_bind(sock, node, port, "tcp", "ipv4");
        if (status == ODS_STATUS_OK) {
            status = sock_tcp_listen(sock, node, port, "ipv4");
        }
    }
    /* ipv6 */
    else if (sock->addr->ai_family == AF_INET6) {
        status = sock_v6only(sock, node, port, on, "tcp");
        if (status != ODS_STATUS_OK) {
            return status;
        }
        sock_tcp_reuseaddr(sock, node, port, on, "ipv6");
        status = sock_fcntl_and_bind(sock, node, port, "tcp", "ipv6");
        if (status == ODS_STATUS_OK) {
            status = sock_tcp_listen(sock, node, port, "ipv6");
        }
    }
    return status;
}


/**
 * Create listening socket.
 *
 */
static ods_status
socket_listen(sock_type* sock, struct addrinfo hints, int socktype,
    const char* node, const char* port, unsigned* ip6_support)
{
    ods_status status = ODS_STATUS_OK;
    int r = 0;
    ods_log_assert(sock);
    ods_log_assert(port);
    *ip6_support = 1;
    hints.ai_socktype = socktype;
    /* getaddrinfo */
    if ((r = getaddrinfo(node, port, &hints, &sock->addr)) != 0 ||
        !sock->addr) {
        ods_log_error("[%s] unable to parse address '%s:%s': getaddrinfo() "
            "failed (%s %s)", sock_str, node?node:"localhost", port,
            gai_strerror(r),
#ifdef EAI_SYSTEM
            r==EAI_SYSTEM?(char*)strerror(errno):"");
#else
            "");
#endif
        if (hints.ai_family == AF_INET6 && r==EAFNOSUPPORT) {
            *ip6_support = 0;
        }
        return ODS_STATUS_SOCK_GETADDRINFO;
    }
    /* socket */
    if (socktype == SOCK_DGRAM) {
        status = sock_server_udp(sock, node, port, ip6_support);
    } else if (socktype == SOCK_STREAM) {
        status = sock_server_tcp(sock, node, port, ip6_support);
    }
    ods_log_debug("[%s] socket listening to %s:%s", sock_str,
        node?node:"localhost", port);
    return status;
}


/**
 * Create sockets and listen.
 *
 */
ods_status
sock_listen(socklist_type* sockets, listener_type* listener)
{
    ods_status status = ODS_STATUS_OK;
    struct addrinfo hints[MAX_INTERFACES];
    const char* node = NULL;
    const char* port = NULL;
    size_t i = 0;
    unsigned ip6_support = 1;

    if (!sockets || !listener) {
        return ODS_STATUS_ASSERT_ERR;
    }
    /* Initialize values */
    for (i = 0; i < MAX_INTERFACES; i++) {
        memset(&hints[i], 0, sizeof(hints[i]));
        hints[i].ai_family = AF_UNSPEC;
        hints[i].ai_flags = AI_PASSIVE;
        sockets->udp[i].s = -1;
        sockets->tcp[i].s = -1;
    }
    /* Walk interfaces */
    for (i=0; i < listener->count; i++) {
        node = NULL;
        if (strlen(listener->interfaces[i].address) > 0) {
            node = listener->interfaces[i].address;
        }
        port = DNS_PORT_STRING;
        if (listener->interfaces[i].port) {
            port = listener->interfaces[i].port;
        }
        if (node != NULL) {
            hints[i].ai_flags |= AI_NUMERICHOST;
        } else {
            hints[i].ai_family = listener->interfaces[i].family;
        }
        /* udp */
        status = socket_listen(&sockets->udp[i], hints[i], SOCK_DGRAM,
            node, port, &ip6_support);
        if (status != ODS_STATUS_OK) {
            if (!ip6_support) {
                ods_log_warning("[%s] fallback to udp/ipv4, no udp/ipv6: "
                    "not supported", sock_str);
                status = ODS_STATUS_OK;
            } else {
                return status;
            }
        }
        /* tcp */
        status = socket_listen(&sockets->tcp[i], hints[i], SOCK_STREAM,
            node, port, &ip6_support);
        if (status != ODS_STATUS_OK) {
            if (!ip6_support) {
                ods_log_warning("[%s] fallback to udp/ipv4, no udp/ipv6: "
                    "not supported", sock_str);
                status = ODS_STATUS_OK;
            } else {
                return status;
            }
        }

    }
    /* All ok */
    return ODS_STATUS_OK;
}


/**
 * Send data over udp.
 *
 */
static void
send_udp(struct udp_data* data, query_type* q)
{
    ssize_t nb;
    ods_log_deeebug("[%s] sending %d bytes over udp", sock_str,
        (int)buffer_remaining(q->buffer));
    nb = sendto(data->socket->s, buffer_begin(q->buffer),
        buffer_remaining(q->buffer), 0,
        (struct sockaddr*) &q->addr, q->addrlen);
    if (nb == -1) {
        ods_log_error("[%s] unable to send data over udp: sendto() failed "
            "(%s)", sock_str, strerror(errno));
        ods_log_debug("[%s] len=%lu", sock_str, (unsigned long)buffer_remaining(q->buffer));
    } else if ((size_t) nb != buffer_remaining(q->buffer)) {
        ods_log_error("[%s] unable to send data over udp: only sent %d of %d "
            "octets", sock_str, (int)nb,
            (int)buffer_remaining(q->buffer));
    }
}


/**
 * Handle incoming udp queries.
 *
 */
void
sock_handle_udp(netio_type* ATTR_UNUSED(netio), netio_handler_type* handler,
    netio_events_type event_types)
{
    struct udp_data* data = (struct udp_data*) handler->user_data;
    int received = 0;
    query_type* q = data->query;
    query_state qstate = QUERY_PROCESSED;

    if (!(event_types & NETIO_EVENT_READ)) {
        return;
    }
    ods_log_debug("[%s] incoming udp message", sock_str);
    query_reset(q, UDP_MAX_MESSAGE_LEN, 0);
    received = recvfrom(handler->fd, buffer_begin(q->buffer),
        buffer_remaining(q->buffer), 0, (struct sockaddr*) &q->addr,
        &q->addrlen);
    if (received < 1) {
        if (errno != EAGAIN && errno != EINTR) {
            ods_log_error("[%s] recvfrom() failed: %s", sock_str,
                strerror(errno));
        }
        return;
    }
    buffer_skip(q->buffer, received);
    buffer_flip(q->buffer);
    qstate = query_process(q, data->engine);
    if (qstate != QUERY_DISCARDED) {
        ods_log_debug("[%s] query processed qstate=%d", sock_str, qstate);
        query_add_optional(q, data->engine);
        buffer_flip(q->buffer);
        send_udp(data, q);
    }
}


/**
 * Cleanup tcp handler data.
 *
 */
static void
cleanup_tcp_handler(netio_type* netio, netio_handler_type* handler)
{
    struct tcp_data* data = (struct tcp_data*) handler->user_data;
    netio_remove_handler(netio, handler);
    close(handler->fd);
    free(handler->timeout);
    free(handler);
    query_cleanup(data->query);
    free(data);
}


/**
 * Handle incoming tcp connections.
 *
 */
void
sock_handle_tcp_accept(netio_type* netio, netio_handler_type* handler,
    netio_events_type event_types)
{
    struct tcp_accept_data* accept_data = (struct tcp_accept_data*)
        handler->user_data;
    int s = 0;
    struct tcp_data* tcp_data = NULL;
    netio_handler_type* tcp_handler = NULL;
    struct sockaddr_storage addr;
    socklen_t addrlen = 0;
    if (!(event_types & NETIO_EVENT_READ)) {
        return;
    }
    ods_log_debug("[%s] handle incoming tcp connection", sock_str);
    addrlen = sizeof(addr);
    s = accept(handler->fd, (struct sockaddr *) &addr, &addrlen);
    if (s == -1) {
        if (errno != EINTR && errno != EWOULDBLOCK) {
            ods_log_error("[%s] unable to handle incoming tcp connection: "
                "accept() failed (%s)", sock_str, strerror(errno));
        }
        return;
    }
    if (fcntl(s, F_SETFL, O_NONBLOCK) == -1) {
        ods_log_error("[%s] unable to handle incoming tcp connection: "
            "fcntl() failed: %s", sock_str, strerror(errno));
        close(s);
        return;
    }
    /* create tcp handler data */
    CHECKALLOC(tcp_data = (struct tcp_data*) malloc(sizeof(struct tcp_data)));
    tcp_data->query = query_create();
    tcp_data->engine = accept_data->engine;
    tcp_data->tcp_accept_handler_count =
        accept_data->tcp_accept_handler_count;
    tcp_data->tcp_accept_handlers = accept_data->tcp_accept_handlers;
    tcp_data->qstate = QUERY_PROCESSED;
    tcp_data->bytes_transmitted = 0;
    memcpy(&tcp_data->query->addr, &addr, addrlen);
    tcp_data->query->addrlen = addrlen;
    CHECKALLOC(tcp_handler = (netio_handler_type*) malloc(sizeof(netio_handler_type)));
    tcp_handler->fd = s;
    CHECKALLOC(tcp_handler->timeout = (struct timespec*) malloc(sizeof(struct timespec)));
    tcp_handler->timeout->tv_sec = XFRD_TCP_TIMEOUT;
    tcp_handler->timeout->tv_nsec = 0L;
    timespec_add(tcp_handler->timeout, netio_current_time(netio));
    tcp_handler->user_data = tcp_data;
    tcp_handler->event_types = NETIO_EVENT_READ | NETIO_EVENT_TIMEOUT;
    tcp_handler->event_handler = sock_handle_tcp_read;
    netio_add_handler(netio, tcp_handler);
}


/**
 * Handle incoming tcp queries.
 *
 */
void
sock_handle_tcp_read(netio_type* netio, netio_handler_type* handler,
    netio_events_type event_types)
{
    struct tcp_data* data = (struct tcp_data *) handler->user_data;
    ssize_t received = 0;
    query_state qstate = QUERY_PROCESSED;

    if (event_types & NETIO_EVENT_TIMEOUT) {
        cleanup_tcp_handler(netio, handler);
        return;
    }
    ods_log_assert(event_types & NETIO_EVENT_READ);
    ods_log_debug("[%s] incoming tcp message", sock_str);
    if (data->bytes_transmitted == 0) {
        ods_log_debug("[%s] TCP_READ: reset query", sock_str);
        query_reset(data->query, TCP_MAX_MESSAGE_LEN, 1);
    }
    /* check if we received the leading packet length bytes yet. */
    if (data->bytes_transmitted < sizeof(uint16_t)) {
        received = read(handler->fd,
            (char *) &data->query->tcplen + data->bytes_transmitted,
            sizeof(uint16_t) - data->bytes_transmitted);
         if (received == -1) {
             if (errno == EAGAIN || errno == EINTR) {
                 /* read would block, wait until more data is available. */
                 return;
             } else {
                 ods_log_error("[%s] unable to handle incoming tcp query: "
                     "read() failed (%s)", sock_str, strerror(errno));
                 cleanup_tcp_handler(netio, handler);
                 return;
             }
         } else if (received == 0) {
             cleanup_tcp_handler(netio, handler);
             return;
         }
         data->bytes_transmitted += received;
         ods_log_debug("[%s] TCP_READ: bytes transmitted %lu (received %lu)",
                sock_str, (unsigned long)data->bytes_transmitted, (unsigned long)received);
         if (data->bytes_transmitted < sizeof(uint16_t)) {
             /* not done with the tcplen yet, wait for more. */
             ods_log_debug("[%s] TCP_READ: bytes transmitted %lu, while "
                "sizeof uint16_t %lu", sock_str, (unsigned long)data->bytes_transmitted,
                (unsigned long)sizeof(uint16_t));
             return;
         }
         ods_log_assert(data->bytes_transmitted == sizeof(uint16_t));
         data->query->tcplen = ntohs(data->query->tcplen);
         /* minimum query size is: 12 + 1 + 2 + 2:
          * header size + root dname + qclass + qtype */
         if (data->query->tcplen < 17) {
             ods_log_warning("[%s] unable to handle incoming tcp query: "
                 "packet too small", sock_str);
             cleanup_tcp_handler(netio, handler);
             return;
         }
         if (data->query->tcplen > data->query->maxlen) {
             ods_log_warning("[%s] unable to handle incoming tcp query: "
                 "insufficient tcp buffer", sock_str);
             cleanup_tcp_handler(netio, handler);
             return;
         }
         buffer_set_limit(data->query->buffer, data->query->tcplen);
    }
    ods_log_assert(buffer_remaining(data->query->buffer) > 0);
    /* read the (remaining) query data.  */
    received = read(handler->fd, buffer_current(data->query->buffer),
        buffer_remaining(data->query->buffer));
    if (received == -1) {
        if (errno == EAGAIN || errno == EINTR) {
            /* read would block, wait until more data is available. */
            return;
        } else {
                 ods_log_error("[%s] unable to handle incoming tcp query: "
                     "read() failed (%s)", sock_str, strerror(errno));
                 cleanup_tcp_handler(netio, handler);
                 return;
        }
    } else if (received == 0) {
        cleanup_tcp_handler(netio, handler);
        return;
    }
    data->bytes_transmitted += received;
    ods_log_debug("[%s] TCP_READ: bytes transmitted %lu (received %lu)",
        sock_str, (unsigned long)data->bytes_transmitted, (unsigned long)received);

    buffer_skip(data->query->buffer, received);
    if (buffer_remaining(data->query->buffer) > 0) {
        /* not done with message yet, wait for more. */
        ods_log_debug("[%s] TCP_READ: remaining %lu", sock_str,
            (unsigned long)buffer_remaining(data->query->buffer));
        return;
    }
    ods_log_assert(buffer_position(data->query->buffer) ==
        data->query->tcplen);
    /* we have a complete query, process it. */
    buffer_flip(data->query->buffer);
    qstate = query_process(data->query, data->engine);
    if (qstate == QUERY_DISCARDED) {
        cleanup_tcp_handler(netio, handler);
        return;
    }
    ods_log_debug("[%s] query processed qstate=%d", sock_str, qstate);
    data->qstate = qstate;
    /* edns, tsig */
    query_add_optional(data->query, data->engine);
    /* switch to tcp write handler. */
    buffer_flip(data->query->buffer);
    data->query->tcplen = buffer_remaining(data->query->buffer);
    ods_log_debug("[%s] TCP_READ: new tcplen %u", sock_str,
        data->query->tcplen);
    data->bytes_transmitted = 0;
    handler->timeout->tv_sec = XFRD_TCP_TIMEOUT;
    handler->timeout->tv_nsec = 0L;
    timespec_add(handler->timeout, netio_current_time(netio));
    handler->event_types = NETIO_EVENT_WRITE | NETIO_EVENT_TIMEOUT;
    handler->event_handler = sock_handle_tcp_write;
}


/**
 * Handle outgoing tcp responses.
 *
 */
void
sock_handle_tcp_write(netio_type* netio, netio_handler_type* handler,
    netio_events_type event_types)
{
    struct tcp_data* data = (struct tcp_data *) handler->user_data;
    ssize_t sent = 0;
    query_type* q = data->query;

    if (event_types & NETIO_EVENT_TIMEOUT) {
        cleanup_tcp_handler(netio, handler);
        return;
    }
    ods_log_assert(event_types & NETIO_EVENT_WRITE);

    if (data->bytes_transmitted < sizeof(q->tcplen)) {
        uint16_t n_tcplen = htons(q->tcplen);
        sent = write(handler->fd,
            (const char*) &n_tcplen + data->bytes_transmitted,
            sizeof(n_tcplen) - data->bytes_transmitted);
        if (sent == -1) {
             if (errno == EAGAIN || errno == EINTR) {
                 /* write would block, wait until socket becomes writeable. */
                 return;
             } else {
                 ods_log_error("[%s] unable to handle outgoing tcp response: "
                     "write() failed (%s)", sock_str, strerror(errno));
                 cleanup_tcp_handler(netio, handler);
                 return;
             }
         } else if (sent == 0) {
             cleanup_tcp_handler(netio, handler);
             return;
         }
         data->bytes_transmitted += sent;
         ods_log_debug("[%s] TCP_WRITE: bytes transmitted %lu (sent %ld)",
                sock_str, (unsigned long)data->bytes_transmitted, (long)sent);
         if (data->bytes_transmitted < sizeof(q->tcplen)) {
             /* writing not complete, wait until socket becomes writable. */
             ods_log_debug("[%s] TCP_WRITE: bytes transmitted %lu, while "
                "sizeof tcplen %lu", sock_str, (unsigned long)data->bytes_transmitted,
                (unsigned long)sizeof(q->tcplen));
             return;
         }
         ods_log_assert(data->bytes_transmitted == sizeof(q->tcplen));
    }
    ods_log_assert(data->bytes_transmitted < q->tcplen + sizeof(q->tcplen));

    sent = write(handler->fd, buffer_current(q->buffer),
        buffer_remaining(q->buffer));
    if (sent == -1) {
        if (errno == EAGAIN || errno == EINTR) {
            /* write would block, wait until socket becomes writeable. */
            return;
        } else {
            ods_log_error("[%s] unable to handle outgoing tcp response: "
                 "write() failed (%s)", sock_str, strerror(errno));
            cleanup_tcp_handler(netio, handler);
            return;
        }
    } else if (sent == 0) {
        cleanup_tcp_handler(netio, handler);
        return;
    }

    buffer_skip(q->buffer, sent);
    data->bytes_transmitted += sent;
    if (data->bytes_transmitted < q->tcplen + sizeof(q->tcplen)) {
        /* still more data to write when socket becomes writable. */
        ods_log_debug("[%s] TCP_WRITE: bytes transmitted %lu, while tcplen "
           "%u and sizeof tcplen %lu", sock_str, (unsigned long) data->bytes_transmitted,
           q->tcplen, (unsigned long)sizeof(q->tcplen));
        return;
    }

    ods_log_debug("[%s] TCP_WRITE: bytes transmitted %lu",
        sock_str, (unsigned long)data->bytes_transmitted);
    ods_log_debug("[%s] TCP_WRITE: tcplen %u", sock_str, q->tcplen);
    ods_log_debug("[%s] TCP_WRITE: sizeof tcplen %lu", sock_str,
        (unsigned long)sizeof(q->tcplen));
    ods_log_assert(data->bytes_transmitted == q->tcplen + sizeof(q->tcplen));
    if (data->qstate == QUERY_AXFR || data->qstate == QUERY_IXFR) {
        /* continue processing AXFR and writing back results.  */
        buffer_clear(q->buffer);
        if (data->qstate == QUERY_IXFR) {
            data->qstate = ixfr(q, data->engine);
        } else {
            data->qstate = axfr(q, data->engine, 0);
        }
        if (data->qstate != QUERY_PROCESSED) {
            /* edns, tsig */
            query_add_optional(q, data->engine);
            buffer_flip(q->buffer);
            q->tcplen = buffer_remaining(q->buffer);
            data->bytes_transmitted = 0;
            handler->timeout->tv_sec = XFRD_TCP_TIMEOUT;
            handler->timeout->tv_nsec = 0L;
            timespec_add(handler->timeout, netio_current_time(netio));
            return;
        }
    }
    /* done sending, wait for the next request. */
    data->bytes_transmitted = 0;
    handler->timeout->tv_sec = XFRD_TCP_TIMEOUT;
    handler->timeout->tv_nsec = 0L;
    timespec_add(handler->timeout, netio_current_time(netio));
    handler->event_types = NETIO_EVENT_READ | NETIO_EVENT_TIMEOUT;
    handler->event_handler = sock_handle_tcp_read;
}
