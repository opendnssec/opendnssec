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
 * DNS handler.
 *
 */

#ifndef DAEMON_DNSHANDLER_H
#define DAEMON_DNSHANDLER_H

#include "config.h"
#include <stdint.h>

typedef struct dnshandler_struct dnshandler_type;

#include "status.h"
#include "locks.h"
#include "status.h"
#include "wire/listener.h"
#include "wire/netio.h"
#include "wire/query.h"
#include "wire/sock.h"

#define ODS_SE_NOTIFY_CMD "NOTIFY"
#define ODS_SE_MAX_HANDLERS 5

struct dnshandler_struct {
    janitor_thread_t thread_id;
    engine_type* engine;
    listener_type* interfaces;
    socklist_type* socklist;
    netio_type* netio;
    query_type* query;
    netio_handler_type xfrhandler;
    unsigned need_to_exit;
    unsigned started;
    netio_handler_type *tcp_accept_handlers;
};

/**
 * Create dns handler.
 * \param[in] allocator memory allocator
 * \param[in] interfaces list of interfaces
 * \return dnshandler_type* created dns handler
 *
 */
dnshandler_type* dnshandler_create(listener_type* interfaces);

/**
 * Start dns handler listener.
 * \param[in] dnshandler_type* dns handler
 * \return ods_status status
 *
 */
ods_status dnshandler_listen(dnshandler_type* dnshandler);

/**
 * Start dns handler.
 * \param[in] dnshandler_type* dns handler
 *
 */
void dnshandler_start(dnshandler_type* dnshandler);

/**
 * Signal dns handler.
 * \param[in] dnshandler_type* dns handler
 *
 */
void dnshandler_signal(dnshandler_type* dnshandler);

/**
 * Forward notify to zone transfer handler.
 * \param[in] dnshandler_type* dns handler
 * \param[in] pkt notify packet
 * \param[in] len packet length
 *
 */
void dnshandler_fwd_notify(dnshandler_type* dnshandler,
    uint8_t* pkt, size_t len);

/**
 * Cleanup dns handler.
 * \param[in] dnshandler_type* dns handler
 *
 */
void dnshandler_cleanup(dnshandler_type* dnshandler);

#endif /* DAEMON_DNSHANDLER_H */
