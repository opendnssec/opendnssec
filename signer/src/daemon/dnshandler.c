/*
 * $Id: dnshandler.c 4518 2011-02-24 15:39:09Z matthijs $
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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
 * DNS handler.
 *
 */

#include "config.h"
#include "daemon/dnshandler.h"
#include "daemon/engine.h"
#include "shared/status.h"
#include "wire/buffer.h"

#include <errno.h>
#include <string.h>

static const char* dnsh_str = "dnshandler";

static void dnshandler_handle_xfr(netio_type* netio,
    netio_handler_type* handler, netio_events_type event_types);

/**
 * Create dns handler.
 *
 */
dnshandler_type*
dnshandler_create(allocator_type* allocator, listener_type* interfaces)
{
    dnshandler_type* dnsh = NULL;
    if (!allocator || !interfaces || interfaces->count <= 0) {
        return NULL;
    }
    dnsh = (dnshandler_type*) allocator_alloc(allocator,
        sizeof(dnshandler_type));
    if (!dnsh) {
        ods_log_error("[%s] unable to create dnshandler: "
            "allocator_alloc() failed", dnsh_str);
        return NULL;
    }
    dnsh->allocator = allocator;
    dnsh->need_to_exit = 0;
    dnsh->engine = NULL;
    dnsh->interfaces = interfaces;
    dnsh->socklist = NULL;
    dnsh->netio = NULL;
    dnsh->query = NULL;
    /* setup */
    dnsh->socklist = (socklist_type*) allocator_alloc(allocator,
        sizeof(socklist_type));
    if (!dnsh->socklist) {
        ods_log_error("[%s] unable to create socklist: "
            "allocator_alloc() failed", dnsh_str);
        dnshandler_cleanup(dnsh);
        return NULL;
    }
    dnsh->netio = netio_create(allocator);
    if (!dnsh->netio) {
        ods_log_error("[%s] unable to create dnshandler: "
            "netio_create() failed", dnsh_str);
        dnshandler_cleanup(dnsh);
        return NULL;
    }
    dnsh->query = query_create();
    if (!dnsh->query) {
        ods_log_error("[%s] unable to create dnshandler: "
            "query_create() failed", dnsh_str);
        dnshandler_cleanup(dnsh);
        return NULL;
    }
    dnsh->xfrhandler.fd = -1;
    dnsh->xfrhandler.user_data = (void*) dnsh;
    dnsh->xfrhandler.timeout = 0;
    dnsh->xfrhandler.event_types = NETIO_EVENT_READ;
    dnsh->xfrhandler.event_handler = dnshandler_handle_xfr;
    return dnsh;
}


/**
 * Start dns handler listener.
 *
 */
ods_status
dnshandler_listen(dnshandler_type* dnshandler)
{
    ods_status status = ODS_STATUS_OK;
    ods_log_assert(dnshandler);
    status = sock_listen(dnshandler->socklist, dnshandler->interfaces);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to start: sock_listen() "
            "failed (%s)", dnsh_str, ods_status2str(status));
        dnshandler->thread_id = 0;
    }
    return status;
}


/**
 * Start dns handler.
 *
 */
void
dnshandler_start(dnshandler_type* dnshandler)
{
    size_t i = 0;
    engine_type* engine = NULL;
    netio_handler_type* tcp_accept_handlers = NULL;

    ods_log_assert(dnshandler);
    ods_log_assert(dnshandler->engine);
    ods_log_debug("[%s] start", dnsh_str);
    /* udp */
    for (i=0; i < dnshandler->interfaces->count; i++) {
        struct udp_data* data = NULL;
        netio_handler_type* handler = NULL;
        data = (struct udp_data*) allocator_alloc(dnshandler->allocator,
            sizeof(struct udp_data));
        if (!data) {
            ods_log_error("[%s] unable to start: allocator_alloc() "
                "failed", dnsh_str);
            dnshandler->thread_id = 0;
            engine->need_to_exit = 1;
            break;
        }
        data->query = dnshandler->query;
        data->engine = dnshandler->engine;
        data->socket = &dnshandler->socklist->udp[i];
        handler = (netio_handler_type*) allocator_alloc(
            dnshandler->allocator, sizeof(netio_handler_type));
        if (!handler) {
            ods_log_error("[%s] unable to start: allocator_alloc() "
                "failed", dnsh_str);
            allocator_deallocate(dnshandler->allocator, (void*)data);
            dnshandler->thread_id = 0;
            engine->need_to_exit = 1;
            break;
        }
        handler->fd = dnshandler->socklist->udp[i].s;
        handler->timeout = NULL;
        handler->user_data = data;
        handler->event_types = NETIO_EVENT_READ;
        handler->event_handler = sock_handle_udp;
        ods_log_debug("[%s] add udp network handler fd %u", dnsh_str,
            (unsigned) handler->fd);
        netio_add_handler(dnshandler->netio, handler);
    }
    /* tcp */
    tcp_accept_handlers = (netio_handler_type*) allocator_alloc(
        dnshandler->allocator,
        dnshandler->interfaces->count * sizeof(netio_handler_type));
    for (i=0; i < dnshandler->interfaces->count; i++) {
        struct tcp_accept_data* data = NULL;
        netio_handler_type* handler = NULL;
        data = (struct tcp_accept_data*) allocator_alloc(
            dnshandler->allocator, sizeof(struct tcp_accept_data));
        if (!data) {
            ods_log_error("[%s] unable to start: allocator_alloc() "
                "failed", dnsh_str);
            dnshandler->thread_id = 0;
            engine->need_to_exit = 1;
            return;
        }
        data->engine = dnshandler->engine;
        data->socket = &dnshandler->socklist->udp[i];
        data->tcp_accept_handler_count = dnshandler->interfaces->count;
        data->tcp_accept_handlers = tcp_accept_handlers;
        handler = &tcp_accept_handlers[i];
        handler->fd = dnshandler->socklist->tcp[i].s;
        handler->timeout = NULL;
        handler->user_data = data;
        handler->event_types = NETIO_EVENT_READ;
        handler->event_handler = sock_handle_tcp_accept;
        ods_log_debug("[%s] add tcp network handler fd %u", dnsh_str,
            (unsigned) handler->fd);
        netio_add_handler(dnshandler->netio, handler);
    }
    /* service */
    while (dnshandler->need_to_exit == 0) {
        ods_log_deeebug("[%s] netio dispatch", dnsh_str);
        if (netio_dispatch(dnshandler->netio, NULL, NULL) == -1) {
            if (errno != EINTR) {
                ods_log_error("[%s] unable to dispatch netio: %s", dnsh_str,
                    strerror(errno));
                break;
            }
        }
    }
    /* shutdown */
    ods_log_debug("[%s] shutdown", dnsh_str);
    for (i=0; i < dnshandler->interfaces->count; i++) {
        if (dnshandler->socklist->udp[i].s != -1) {
            close(dnshandler->socklist->udp[i].s);
            freeaddrinfo((void*)dnshandler->socklist->udp[i].addr);
        }
        if (dnshandler->socklist->tcp[i].s != -1) {
            close(dnshandler->socklist->tcp[i].s);
            freeaddrinfo((void*)dnshandler->socklist->tcp[i].addr);
        }
    }
    return;
}


/**
 * Signal dns handler.
 *
 */
void
dnshandler_signal(dnshandler_type* dnshandler)
{
    if (dnshandler && dnshandler->thread_id) {
        ods_thread_kill(dnshandler->thread_id, SIGHUP);
    }
    return;
}


/**
 * Forward notify to zone transfer handler.
 *
 */
void
dnshandler_fwd_notify(dnshandler_type* dnshandler, uint8_t* pkt, size_t len)
{
    ssize_t nb = 0;
    ods_log_assert(dnshandler);
    ods_log_assert(pkt);
    nb = send(dnshandler->xfrhandler.fd, (const void*) pkt, len, 0);
    if (nb < 0) {
        ods_log_error("[%s] unable to forward notify: send() failed (%s)",
            dnsh_str, strerror(errno));
    } else {
        ods_log_debug("[%s] forwarded notify: %u bytes sent", dnsh_str, nb);
    }
    return;
}


/**
 * Handle forwarded dns packets.
 *
 */
static void
dnshandler_handle_xfr(netio_type* ATTR_UNUSED(netio),
    netio_handler_type* handler, netio_events_type event_types)
{
    dnshandler_type* dnshandler = NULL;
    uint8_t buf[MAX_PACKET_SIZE];
    ssize_t received = 0;
    if (!handler) {
        return;
    }
    dnshandler = (dnshandler_type*) handler->user_data;
    ods_log_assert(event_types & NETIO_EVENT_READ);
    ods_log_debug("[%s] read forwarded xfr packet", dnsh_str);
    received = read(dnshandler->xfrhandler.fd, &buf, MAX_PACKET_SIZE);
    if (received == -1) {
        ods_log_debug("[%s] unable to forward xfr packet: %s", dnsh_str,
            strerror(errno));
    }
    return;
}


/**
 * Cleanup dns handler.
 *
 */
void
dnshandler_cleanup(dnshandler_type* dnshandler)
{
    allocator_type* allocator = NULL;
    if (!dnshandler) {
        return;
    }
    allocator = dnshandler->allocator;
    netio_cleanup(dnshandler->netio);
    query_cleanup(dnshandler->query);
    allocator_deallocate(allocator, (void*) dnshandler->socklist);
    allocator_deallocate(allocator, (void*) dnshandler);
    return;
}
