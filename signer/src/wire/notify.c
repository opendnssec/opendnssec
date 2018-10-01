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

#include "config.h"
#include "adapter/addns.h"
#include "daemon/xfrhandler.h"
#include "signer/zone.h"
#include "wire/notify.h"
#include "wire/xfrd.h"

#include <sys/socket.h>

static const char* notify_str = "notify";

static void notify_handle_zone(netio_type* netio,
    netio_handler_type* handler, netio_events_type event_types);


/**
 * Get time.
 *
 */
static time_t
notify_time(notify_type* notify)
{
    ods_log_assert(notify);
    ods_log_assert(notify->xfrhandler);
    return xfrhandler_time((xfrhandler_type*) notify->xfrhandler);
}


/**
 * Set timer.
 *
 */
static void
notify_set_timer(notify_type* notify, time_t t)
{
    if (!notify || !notify->xfrhandler) {
        return;
    }
    /**
     * Randomize the time, within 90%-100% of original.
     * Not later so zones cannot expire too late.
     */
    if(t > notify_time(notify) + 10) {
        time_t extra = t - notify_time(notify);
        time_t base = extra*9/10;
#ifdef HAVE_ARC4RANDOM_UNIFORM
        t = notify_time(notify) + base +
            arc4random_uniform(extra-base);
#elif HAVE_ARC4RANDOM
        t = notify_time(notify) + base +
            arc4random()%(extra-base);
#else
        t = notify_time(notify) + base +
            random()%(extra-base);
#endif
    }
    notify->handler.timeout = &notify->timeout;
    notify->timeout.tv_sec = t;
    notify->timeout.tv_nsec = 0;
}


/**
 * Create notify structure.
 *
 */
notify_type*
notify_create(xfrhandler_type* xfrhandler, zone_type* zone)
{
    notify_type* notify = NULL;
    if (!xfrhandler || !zone) {
        return NULL;
    }
    CHECKALLOC(notify = (notify_type*) malloc(sizeof(notify_type)));
    notify->zone = zone;
    notify->xfrhandler = xfrhandler;
    notify->waiting_next = NULL;
    notify->secondary = NULL;
    notify->soa = NULL;
    notify->tsig_rr = tsig_rr_create();
    notify->retry = 0;
    notify->query_id = 0;
    notify->is_waiting = 0;
    notify->handler.fd = -1;
    notify->timeout.tv_sec = 0;
    notify->timeout.tv_nsec = 0;
    notify->handler.timeout = NULL;
    notify->handler.user_data = notify;
    notify->handler.event_types =
        NETIO_EVENT_READ|NETIO_EVENT_TIMEOUT;
    notify->handler.event_handler = notify_handle_zone;
    return notify;
}


/**
 * Setup notify.
 *
 */
static void
notify_setup(notify_type* notify)
{
    zone_type* zone = NULL;
    dnsout_type* dnsout = NULL;
    if (!notify) {
        return;
    }
    zone = (zone_type*) notify->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->adoutbound);
    ods_log_assert(zone->adoutbound->config);
    ods_log_assert(zone->adoutbound->type == ADAPTER_DNS);
    dnsout = (dnsout_type*) zone->adoutbound->config;
    notify->retry = 0;
    notify->secondary = dnsout->do_notify;
    ods_log_debug("[%s] setup notify for zone %s", notify_str, zone->name);
    notify_set_timer(notify, notify_time(notify));
}


/**
 * Disable notify.
 *
 */
static void
notify_disable(notify_type* notify)
{
    xfrhandler_type* xfrhandler = NULL;
    zone_type* zone = NULL;
    if (!notify) {
        return;
    }
    xfrhandler = (xfrhandler_type*) notify->xfrhandler;
    ods_log_assert(xfrhandler);
    zone = (zone_type*) notify->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    notify->secondary = NULL;
    notify->handler.timeout = NULL;
    if (notify->handler.fd != -1) {
        close(notify->handler.fd);
        notify->handler.fd = -1;
    }
    if (xfrhandler->notify_udp_num == NOTIFY_MAX_UDP) {
        while (xfrhandler->notify_waiting_first) {
            notify_type* wn = xfrhandler->notify_waiting_first;
            ods_log_assert(wn->is_waiting);
            wn->is_waiting = 0;
            xfrhandler->notify_waiting_first = wn->waiting_next;
            if (xfrhandler->notify_waiting_last == wn) {
                xfrhandler->notify_waiting_last = NULL;
            }
            if (wn->secondary) {
                ods_log_debug("[%s] zone %s notify off waiting list",
                    notify_str, zone->name);
                notify_setup(wn);
                return;
            }
       }
    }
    ods_log_debug("[%s] notify for zone %s disabled", notify_str, zone->name);
    xfrhandler->notify_udp_num--;
}


/**
 * Next secondary.
 *
 */
static void
notify_next(notify_type* notify)
{
    if (!notify || !notify->secondary) {
        return;
    }
    notify->secondary = notify->secondary->next;
    notify->retry = 0;
    if (!notify->secondary) {
        zone_type* zone = (zone_type*) notify->zone;
        ods_log_assert(zone);
        ods_log_assert(zone->name);
        ods_log_debug("[%s] zone %s no more secondaries, disable notify",
            notify_str, zone->name);
        notify_disable(notify);
    }
}


/**
 * Read packet from udp.
 *
 */
static int
notify_udp_read_packet(notify_type* notify)
{
    xfrhandler_type* xfrhandler = NULL;
    ssize_t received = 0;
    ods_log_assert(notify);
    xfrhandler = (xfrhandler_type*) notify->xfrhandler;
    ods_log_assert(xfrhandler);
    buffer_clear(xfrhandler->packet);
    received = recvfrom(notify->handler.fd, buffer_begin(xfrhandler->packet),
        buffer_remaining(xfrhandler->packet), 0, NULL, NULL);
    if (received == -1) {
        ods_log_error("[%s] unable to read packet: recvfrom() failed fd %d "
            "(%s)", notify_str, notify->handler.fd, strerror(errno));
        return 0;
    }
    buffer_set_limit(xfrhandler->packet, received);
    return 1;
}


/**
 * Handle notify reply.
 *
 */
static int
notify_handle_reply(notify_type* notify)
{
    xfrhandler_type* xfrhandler = NULL;
    zone_type* zone = NULL;
    ods_log_assert(notify);
    ods_log_assert(notify->secondary);
    ods_log_assert(notify->secondary->address);
    xfrhandler = (xfrhandler_type*) notify->xfrhandler;
    zone = (zone_type*) notify->zone;
    ods_log_assert(xfrhandler);
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    if (xfrhandler->packet->limit < 3 ||
        (buffer_pkt_opcode(xfrhandler->packet) != LDNS_PACKET_NOTIFY) ||
        (buffer_pkt_qr(xfrhandler->packet) == 0)) {
        ods_log_error("[%s] zone %s received bad notify reply opcode/qr from %s",
            notify_str, zone->name, notify->secondary->address);
        return 0;
    }
    if (buffer_pkt_id(xfrhandler->packet) != notify->query_id) {
        ods_log_error("[%s] zone %s received bad notify reply id from %s",
            notify_str, zone->name, notify->secondary->address);
        return 0;
    }
    /* could check tsig */
    if (buffer_pkt_rcode(xfrhandler->packet) != LDNS_RCODE_NOERROR) {
        const char* str = buffer_rcode2str(buffer_pkt_rcode(xfrhandler->packet));
        ods_log_error("[%s] zone %s received bad notify rcode %s from %s",
            notify_str, zone->name, str?str:"UNKNOWN",
            notify->secondary->address);
        if (buffer_pkt_rcode(xfrhandler->packet) != LDNS_RCODE_NOTIMPL) {
            return 1;
        }
        return 0;
    }
    ods_log_debug("[%s] zone %s secondary %s notify reply ok", notify_str,
        zone->name, notify->secondary->address);
    return 1;
}


/**
 * Send notify over udp.
 *
 */
static int
notify_send_udp(notify_type* notify, buffer_type* buffer)
{
    struct sockaddr_storage to;
    socklen_t to_len = 0;
    int fd = -1;
    int family = PF_INET;
    ssize_t nb = 0;
    ods_log_assert(buffer);
    ods_log_assert(notify);
    ods_log_assert(notify->secondary);
    ods_log_assert(notify->secondary->address);
    /* this will set the remote port to acl->port or TCP_PORT */
    to_len = xfrd_acl_sockaddr_to(notify->secondary, &to);
    /* get the address family of the remote host */
    if (notify->secondary->family == AF_INET6) {
        family = PF_INET6;
    }
    /* create socket */
    fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        ods_log_error("[%s] unable to send data over udp to %s: "
            "socket() failed (%s)", notify_str, notify->secondary->address,
            strerror(errno));
        return -1;
    }
    /* bind it */
    interface_type interface = notify->xfrhandler->engine->dnshandler->interfaces->interfaces[0];
    if (!interface.address) {
        ods_log_error("[%s] unable to get the address of interface", notify_str);
        close(fd);
        return -1;
    }
    if (acl_parse_family(interface.address) == AF_INET) {
        struct sockaddr_in addr;
        addr.sin_family = acl_parse_family(interface.address);
        addr.sin_addr = interface.addr.addr;
        addr.sin_port = 0;
        if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
            ods_log_error("[%s] unable to bind address %s: bind failed %s", notify_str, interface.address, strerror(errno));
            close(fd);
            return -1;
        }
    }
    else {
        struct sockaddr_in6 addr6;
        addr6.sin6_family = acl_parse_family(interface.address);
        addr6.sin6_addr = interface.addr.addr6;
        addr6.sin6_port = 0;
        if (bind(fd, (struct sockaddr *) &addr6, sizeof(addr6)) != 0) {
            ods_log_error("[%s] unable to bind address %s: bind() failed %s", notify_str, interface.address, strerror(errno));
            close(fd);
            return -1;
        }
    }

    /* send it (udp) */
    ods_log_deeebug("[%s] send %ld bytes over udp to %s", notify_str,
        (unsigned long)buffer_remaining(buffer), notify->secondary->address);
    nb = sendto(fd, buffer_current(buffer), buffer_remaining(buffer), 0,
        (struct sockaddr*)&to, to_len);
    if (nb == -1) {
        ods_log_error("[%s] unable to send data over udp to %s: "
            "sendto() failed (%s)", notify_str, notify->secondary->address,
            strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}


/**
 * Sign notify.
 *
 */
static void
notify_tsig_sign(notify_type* notify, buffer_type* buffer)
{
    tsig_algo_type* algo = NULL;
    if (!notify || !notify->tsig_rr || !notify->secondary ||
        !notify->secondary->tsig || !notify->secondary->tsig->key ||
        !buffer) {
        return; /* no tsig configured */
    }
    algo = tsig_lookup_algo(notify->secondary->tsig->algorithm);
    if (!algo) {
        ods_log_error("[%s] unable to sign notify: tsig unknown algorithm "
            "%s", notify_str, notify->secondary->tsig->algorithm);
        return;
    }
    ods_log_assert(algo);
    tsig_rr_reset(notify->tsig_rr, algo, notify->secondary->tsig->key);
    notify->tsig_rr->original_query_id = buffer_pkt_id(buffer);
    notify->tsig_rr->algo_name =
        ldns_rdf_clone(notify->tsig_rr->algo->wf_name);
    notify->tsig_rr->key_name = ldns_rdf_clone(notify->tsig_rr->key->dname);
    tsig_rr_prepare(notify->tsig_rr);
    tsig_rr_update(notify->tsig_rr, buffer, buffer_position(buffer));
    tsig_rr_sign(notify->tsig_rr);
    ods_log_debug("[%s] tsig append rr to notify id=%u", notify_str,
        buffer_pkt_id(buffer));
    tsig_rr_append(notify->tsig_rr, buffer);
    buffer_pkt_set_arcount(buffer, buffer_pkt_arcount(buffer)+1);
    tsig_rr_prepare(notify->tsig_rr);
}


/**
 * Send notify.
 *
 */
void
notify_send(notify_type* notify)
{
    xfrhandler_type* xfrhandler = NULL;
    zone_type* zone = NULL;
    ods_log_assert(notify);
    ods_log_assert(notify->secondary);
    ods_log_assert(notify->secondary->address);
    xfrhandler = (xfrhandler_type*) notify->xfrhandler;
    zone = (zone_type*) notify->zone;
    ods_log_assert(xfrhandler);
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    if (notify->handler.fd != -1) {
        close(notify->handler.fd);
    }
    notify->handler.fd = -1;
    notify->timeout.tv_sec = notify_time(notify) + NOTIFY_RETRY_TIMEOUT;
    buffer_pkt_notify(xfrhandler->packet, zone->apex, LDNS_RR_CLASS_IN);
    notify->query_id = buffer_pkt_id(xfrhandler->packet);
    buffer_pkt_set_aa(xfrhandler->packet);
    /* add current SOA to answer section */
    if (notify->soa) {
        if (buffer_write_rr(xfrhandler->packet, notify->soa)) {
            buffer_pkt_set_ancount(xfrhandler->packet, 1);
        }
    }
    if (notify->secondary->tsig) {
        notify_tsig_sign(notify, xfrhandler->packet);
    }
    buffer_flip(xfrhandler->packet);
    notify->handler.fd = notify_send_udp(notify, xfrhandler->packet);
    if (notify->handler.fd == -1) {
        ods_log_error("[%s] unable to send notify retry %u for zone %s to "
            "%s: notify_send_udp() failed", notify_str, notify->retry,
            zone->name, notify->secondary->address);
        return;
    }
    ods_log_verbose("[%s] notify retry %u for zone %s sent to %s", notify_str,
        notify->retry, zone->name, notify->secondary->address);
}


/**
 * Handle notify.
 *
 */
static void
notify_handle_zone(netio_type* ATTR_UNUSED(netio),
    netio_handler_type* handler, netio_events_type event_types)
{
    notify_type* notify = NULL;
    xfrhandler_type* xfrhandler = NULL;
    zone_type* zone = NULL;
    if (!handler) {
        return;
    }
    notify = (notify_type*) handler->user_data;
    ods_log_assert(notify);
    xfrhandler = (xfrhandler_type*) notify->xfrhandler;
    zone = (zone_type*) notify->zone;
    ods_log_assert(xfrhandler);
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_debug("[%s] handle notify for zone %s", notify_str, zone->name);

    if (notify->is_waiting) {
        ods_log_debug("[%s] already waiting, skipping notify for zone %s",
            notify_str, zone->name);
        ods_log_assert(notify->handler.fd == -1);
        return;
    }
    if (event_types & NETIO_EVENT_READ) {
        ods_log_debug("[%s] read notify ok for zone %s", notify_str,
            zone->name);
        ods_log_assert(notify->handler.fd != -1);
        if (notify_udp_read_packet(notify)) {
            if (notify_handle_reply(notify)) {
                notify_next(notify);
            }
        }
    } else if(event_types & NETIO_EVENT_TIMEOUT) {
        ods_log_debug("[%s] notify timeout for zone %s", notify_str,
            zone->name);
        /* timeout, try again */
    }
    /* see if notify is still enabled */
    if (notify->secondary) {
        ods_log_assert(notify->secondary->address);
        notify->retry++;
        if (notify->retry > NOTIFY_MAX_RETRY) {
            ods_log_verbose("[%s] notify max retry for zone %s, %s unreachable",
                notify_str, zone->name, notify->secondary->address);
            notify_next(notify);
        } else {
            notify_send(notify);
        }
    }
}


/**
 * Update current SOA.
 *
 */
static void
notify_update_soa(notify_type* notify, ldns_rr* soa)
{
    if (!notify) {
        return;
    }
    if (notify->soa) {
        ldns_rr_free(notify->soa);
    }
    notify->soa = soa;
}


/**
 * Enable notify.
 *
 */
void
notify_enable(notify_type* notify, ldns_rr* soa)
{
    xfrhandler_type* xfrhandler = NULL;
    zone_type* zone = NULL;
    dnsout_type* dnsout = NULL;
    if (!notify) {
        return;
    }
    xfrhandler = (xfrhandler_type*) notify->xfrhandler;
    ods_log_assert(xfrhandler);
    zone = (zone_type*) notify->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->adoutbound);
    ods_log_assert(zone->adoutbound->config);
    ods_log_assert(zone->adoutbound->type == ADAPTER_DNS);
    dnsout = (dnsout_type*) zone->adoutbound->config;
    if (!dnsout->do_notify) {
        ods_log_warning("[%s] zone %s has no notify acl", notify_str,
            zone->name);
        return; /* nothing to do */
    }
    if (notify->is_waiting || notify->handler.fd != -1) {
        ods_log_debug("[%s] zone %s already on waiting list", notify_str,
            zone->name);
       return;
    }
    notify_update_soa(notify, soa);
    if (xfrhandler->notify_udp_num < NOTIFY_MAX_UDP) {
        notify_setup(notify);
        xfrhandler->notify_udp_num++;
        ods_log_debug("[%s] zone %s notify enabled", notify_str,
            zone->name);
        return;
    }
    /* put it in waiting list */
    notify->secondary = dnsout->do_notify;
    notify->is_waiting = 1;
    notify->waiting_next = NULL;
    if (xfrhandler->notify_waiting_last) {
        xfrhandler->notify_waiting_last->waiting_next = notify;
    } else {
        xfrhandler->notify_waiting_first = notify;
    }
    xfrhandler->notify_waiting_last = notify;
    notify->handler.timeout = NULL;
    ods_log_debug("[%s] zone %s notify on waiting list", notify_str,
        zone->name);
}


/**
 * Cleanup notify structure.
 *
 */
void
notify_cleanup(notify_type* notify)
{
    if (!notify) {
        return;
    }
    if (notify->handler.fd != -1) {
        close(notify->handler.fd);
        notify->handler.fd = -1;
    }
    if (notify->soa) {
        ldns_rr_free(notify->soa);
    }
    tsig_rr_cleanup(notify->tsig_rr);
    free(notify);
}
