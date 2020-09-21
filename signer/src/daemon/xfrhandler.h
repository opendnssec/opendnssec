/*
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
 * Zone transfer handler.
 *
 */

#ifndef DAEMON_XFRHANDLER_H
#define DAEMON_XFRHANDLER_H

#include "config.h"

typedef struct xfrhandler_struct xfrhandler_type;

#include "status.h"
#include "locks.h"
#include "wire/buffer.h"
#include "wire/netio.h"
#include "wire/notify.h"
#include "wire/tcpset.h"
#include "wire/xfrd.h"
#include "engine.h"

/**
 * Zone transfer handler.
 *
 */
struct xfrhandler_struct {
    /* Engine reference */
    janitor_thread_t thread_id;
    engine_type* engine;
    /* Start time */
    time_t start_time;
    time_t current_time;
    /* Network support */
    netio_type* netio;
    tcp_set_type* tcp_set;
    buffer_type* packet;
    xfrd_type* tcp_waiting_first;
    xfrd_type* udp_waiting_first;
    xfrd_type* udp_waiting_last;
    size_t udp_use_num;
    notify_type* notify_waiting_first;
    notify_type* notify_waiting_last;
    int notify_udp_num;
    netio_handler_type dnshandler;
    unsigned got_time : 1;
    unsigned need_to_exit : 1;
    unsigned started : 1;
};

/**
 * Create zone transfer handler.
 * \param[in] allocator memory allocator
 * \return xfrhandler_type* created zoned transfer handler
 *
 */
extern xfrhandler_type* xfrhandler_create(void);

/**
 * Start zone transfer handler.
 * \param[in] xfrhandler_type* zone transfer handler
 *
 */
extern void xfrhandler_start(xfrhandler_type* xfrhandler);

/**
 * Get current time from the zone transfer handler.
 * \param[in] xfrhandler_type* zone transfer handler
 * \return time_t current time
 *
 */
extern time_t xfrhandler_time(xfrhandler_type* xfrhandler);

/**
 * Signal zone transfer handler.
 * \param[in] xfrhandler_type* zone transfer handler
 *
 */
extern void xfrhandler_signal(xfrhandler_type* xfrhandler);

/**
 * Cleanup zone transfer handler.
 * \param[in] xfrhandler_type* zone transfer handler
 *
 */
extern void xfrhandler_cleanup(xfrhandler_type* xfrhandler);

#endif /* DAEMON_XFRHANDLER_H */
