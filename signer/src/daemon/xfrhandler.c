/*
 * Copyright (c) 2009-2018 NLNet Labs.
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
 * Zone transfer handler.
 *
 */

#include "config.h"
#include "daemon/engine.h"
#include "daemon/xfrhandler.h"
#include "duration.h"
#include "status.h"

#include <errno.h>
#include <string.h>

static const char* xfrh_str = "xfrhandler";

static void xfrhandler_handle_dns(netio_type* netio,
    netio_handler_type* handler, netio_events_type event_types);


/**
 * Create zone transfer handler.
 *
 */
xfrhandler_type*
xfrhandler_create()
{
    xfrhandler_type* xfrh = NULL;
    CHECKALLOC(xfrh = (xfrhandler_type*) malloc(sizeof(xfrhandler_type)));
    xfrh->engine = NULL;
    xfrh->packet = NULL;
    xfrh->netio = NULL;
    xfrh->tcp_set = NULL;
    xfrh->tcp_waiting_first = NULL;
    xfrh->udp_waiting_first = NULL;
    xfrh->udp_waiting_last = NULL;
    xfrh->udp_use_num = 0;
    xfrh->start_time = 0;
    xfrh->current_time = 0;
    xfrh->got_time = 0;
    xfrh->need_to_exit = 0;
    xfrh->started = 0;
    /* notify */
    xfrh->notify_waiting_first = NULL;
    xfrh->notify_waiting_last = NULL;
    xfrh->notify_udp_num = 0;
    /* setup */
    xfrh->netio = netio_create();
    xfrh->packet = buffer_create(PACKET_BUFFER_SIZE);
    xfrh->tcp_set = tcp_set_create();
    xfrh->dnshandler.fd = -1;
    xfrh->dnshandler.user_data = (void*) xfrh;
    xfrh->dnshandler.timeout = 0;
    xfrh->dnshandler.event_types = NETIO_EVENT_READ;
    xfrh->dnshandler.event_handler = xfrhandler_handle_dns;
    xfrh->dnshandler.free_handler = 0;
    return xfrh;
}


/**
 * Start zone transfer handler.
 *
 */
void
xfrhandler_start(xfrhandler_type* xfrhandler)
{
    ods_log_assert(xfrhandler);
    ods_log_assert(xfrhandler->engine);
    ods_log_debug("[%s] start", xfrh_str);
    /* setup */
    xfrhandler->start_time = time_now();
    /* handlers */
    netio_add_handler(xfrhandler->netio, &xfrhandler->dnshandler);
    /* service */
    while (xfrhandler->need_to_exit == 0) {
        /* dispatch may block for a longer period, so current is gone */
        xfrhandler->got_time = 0;
        ods_log_deeebug("[%s] netio dispatch", xfrh_str);
        if (netio_dispatch(xfrhandler->netio, NULL, NULL) == -1) {
            if (errno != EINTR) {
                ods_log_error("[%s] unable to dispatch netio: %s", xfrh_str,
                    strerror(errno));
            }
        }
    }
    /* shutdown */
    ods_log_debug("[%s] shutdown", xfrh_str);
}


/**
 * Get current time from zone transfer handler.
 *
 */
time_t
xfrhandler_time(xfrhandler_type* xfrhandler)
{
    if (!xfrhandler) {
        return 0;
    }
    if (!xfrhandler->got_time) {
        xfrhandler->current_time = time_now();
        xfrhandler->got_time = 1;
    }
    return xfrhandler->current_time;
}


/**
 * Signal zone transfer handler.
 *
 */
void
xfrhandler_signal(xfrhandler_type* xfrhandler)
{
    if (xfrhandler && xfrhandler->started) {
        janitor_thread_signal(xfrhandler->thread_id);
    }
}


/**
 * Handle forwarded dns packets.
 *
 */
static void
xfrhandler_handle_dns(netio_type* ATTR_UNUSED(netio),
    netio_handler_type* handler, netio_events_type event_types)
{
    xfrhandler_type* xfrhandler = NULL;
    uint8_t buf[MAX_PACKET_SIZE];
    ssize_t received = 0;
    if (!handler) {
        return;
    }
    xfrhandler = (xfrhandler_type*) handler->user_data;
    ods_log_assert(event_types & NETIO_EVENT_READ);
    received = read(xfrhandler->dnshandler.fd, &buf, MAX_PACKET_SIZE);
    ods_log_debug("[%s] read forwarded dns packet: %d bytes received",
        xfrh_str, (int) received);
    if (received == -1) {
        ods_log_error("[%s] unable to forward dns packet: %s", xfrh_str,
            strerror(errno));
    }
}


/**
 * Cleanup zone transfer handler.
 *
 */
void
xfrhandler_cleanup(xfrhandler_type* xfrhandler)
{
    if (!xfrhandler) {
        return;
    }
    netio_cleanup_shallow(xfrhandler->netio);
    buffer_cleanup(xfrhandler->packet);
    tcp_set_cleanup(xfrhandler->tcp_set);
    free(xfrhandler);
}
