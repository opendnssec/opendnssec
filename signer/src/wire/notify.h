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
 * Notify sending.
 *
 */

#ifndef WIRE_NOTIFY_H
#define WIRE_NOTIFY_H

#include "config.h"
#include <ldns/ldns.h>

typedef struct notify_struct notify_type;

#include "status.h"
#include "wire/acl.h"
#include "wire/buffer.h"
#include "wire/netio.h"
#include "wire/tsig.h"
#include "daemon/xfrhandler.h"
#include "signer/zone.h"

#define NOTIFY_MAX_UDP 50
#define NOTIFY_MAX_RETRY 5
#define NOTIFY_RETRY_TIMEOUT 15

/**
 * Notify.
 *
 */
struct notify_struct {
    notify_type* waiting_next;
    ldns_rr* soa;
    tsig_rr_type* tsig_rr;
    acl_type* secondary;
    zone_type* zone;
    xfrhandler_type* xfrhandler;
    netio_handler_type handler;
    struct timespec timeout;
    uint16_t query_id;
    uint8_t retry;
    unsigned is_waiting : 1;
};

/**
 * Create notify structure.
 * \param[in] xfrhandler zone transfer handler
 * \param[in] zone zone reference
 * \return notify_type* notify structure.
 *
 */
notify_type* notify_create(xfrhandler_type* xfrhandler, zone_type* zone);

/**
 * Enable notify.
 * \param[in] notify notify structure
 * \param[in] soa current soa
 *
 */
void notify_enable(notify_type* notify, ldns_rr* soa);

/**
 * Send notify.
 * \param[in] notify notify structure
 *
 */
void notify_send(notify_type* notify);

/**
 * Cleanup notify structure.
 * \param[in] notify notify structure.
 *
 */
void notify_cleanup(notify_type* notify);

#endif /* WIRE_NOTIFY_H */
