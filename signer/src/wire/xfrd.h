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
 * Zone transfers.
 *
 */

#ifndef WIRE_XFRD_H
#define WIRE_XFRD_H

#include "config.h"
#include <stdint.h>
#include <time.h>

/**
 * Packet status.
 *
 */
enum xfrd_pkt_enum {
    XFRD_PKT_BAD, /* drop the packet/connection */
    XFRD_PKT_MORE, /* more packets to follow on tcp */
    XFRD_PKT_NOTIMPL, /* server responded with NOTIMPL or FORMATERR */
    XFRD_PKT_TC, /* try tcp connection */
    XFRD_PKT_XFR, /* server responded with transfer*/
    XFRD_PKT_NEWLEASE /* no changes, soa OK */
};
typedef enum xfrd_pkt_enum xfrd_pkt_status;

typedef struct soa_struct soa_type;

typedef struct xfrd_struct xfrd_type;

#include "locks.h"
#include "status.h"
#include "wire/acl.h"
#include "wire/buffer.h"
#include "wire/netio.h"
#include "wire/tsig.h"
#include "daemon/xfrhandler.h"

#define XFRD_MAX_ROUNDS 3 /* max number of rounds along the masters */
#define XFRD_MAX_UDP 100 /* max number of udp sockets at a time for ixfr */
#define XFRD_NO_IXFR_CACHE 172800 /* 48h before retrying ixfr after notimpl */
#define XFRD_TCP_TIMEOUT 120 /* seconds, before a tcp request times out */
#define XFRD_UDP_TIMEOUT 5 /* seconds, before a udp request times out */

/*
 * Zone transfer SOA information.
 */
struct soa_struct {
    /* owner equals zone apex */
    /* class equals zone klass */
    /* type is SOA */
    uint32_t ttl;
    /* rdata count = 7 */
    uint8_t mname[MAXDOMAINLEN + 2];
    uint8_t rname[MAXDOMAINLEN + 2];
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
};

/**
 * Zone transfer state.
 *
 */
struct xfrd_struct
{
    xfrhandler_type* xfrhandler;
    zone_type* zone;
    pthread_mutex_t serial_lock; /* mutexes soa serial management */
    pthread_mutex_t rw_lock; /* mutexes <zone>.xfrd file */

    /* transfer request handling */
    int tcp_conn;
    int round_num;
    int master_num;
    int next_master;
    acl_type* master;

    /* soa serial management */
    uint32_t serial_xfr;
    /* Last received serial via notify. Only valid if
     * serial_notify_acquired is not 0 */
    uint32_t serial_notify;
    /* current serial on inbound side */
    uint32_t serial_disk;
    time_t serial_xfr_acquired;
    /* time of last received notify that is being handled. If non-zero
     * it indicates a transfer is in progress */
    time_t serial_notify_acquired;
    time_t serial_disk_acquired;
    uint8_t serial_retransfer;
    soa_type soa;

    /* timeout and event handling */
    struct timespec timeout;
    netio_handler_type handler;

    /* packet handling */
    uint16_t query_id;
    uint32_t msg_seq_nr;
    uint32_t msg_old_serial;
    uint32_t msg_new_serial;
    size_t msg_rr_count;
    uint8_t msg_is_ixfr;
    uint8_t msg_do_retransfer;
    tsig_rr_type* tsig_rr;

    xfrd_type* tcp_waiting_next;
    xfrd_type* udp_waiting_next;
    unsigned tcp_waiting : 1;
    unsigned udp_waiting : 1;

};

/**
 * Create zone transfer structure.
 * \param[in] xfrhandler zone transfer handler
 * \param[in] zone zone reference
 * \return xfrd_type* zone transfer structure.
 *
 */
extern xfrd_type* xfrd_create(xfrhandler_type* xfrhandler, zone_type* zone);

/**
 * Set timeout for zone transfer to now.
 * \param[in] xfrd zone transfer structure.
 *
 */
void xfrd_set_timer_now(xfrd_type* xfrd);

/**
 * Set timeout for zone transfer to RETRY.
 * \param[in] xfrd zone transfer structure.
 *
 */
void xfrd_set_timer_retry(xfrd_type* xfrd);

/**
 * Set timeout for zone transfer to REFRESH.
 * \param[in] xfrd zone transfer structure.
 *
 */
void xfrd_set_timer_refresh(xfrd_type* xfrd);

/**
 * Use acl address to setup remote sockaddr struct.
 * \param[in] acl acl
 * \param[in] to remote address storage
 * \return socklen_t length of address
 *
 */
extern socklen_t xfrd_acl_sockaddr_to(acl_type* acl,
    struct sockaddr_storage* to);

/**
 * Cleanup zone transfer structure.
 * \param[in] xfrd zone transfer structure.
 * \param[in] backup backup transfer variables.
 *
 */
extern void xfrd_cleanup(xfrd_type* xfrd, int backup);

#endif /* WIRE_XFRD_H */
