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
 * Zone transfers.
 *
 */

#include "config.h"
#include "daemon/engine.h"
#include "daemon/xfrhandler.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/status.h"
#include "shared/util.h"
#include "signer/backup.h"
#include "signer/domain.h"
#include "signer/zone.h"
#include "wire/tcpset.h"
#include "wire/xfrd.h"

#include <unistd.h>
#include <fcntl.h>

#define XFRD_TSIG_MAX_UNSIGNED 100

static const char* xfrd_str = "xfrd";

static void xfrd_handle_zone(netio_type* netio,
    netio_handler_type* handler, netio_events_type event_types);
static void xfrd_make_request(xfrd_type* xfrd);

static socklen_t xfrd_acl_sockaddr(acl_type* acl, unsigned int port,
    struct sockaddr_storage *sck);

static void xfrd_write_soa(xfrd_type* xfrd, buffer_type* buffer);
static int xfrd_parse_soa(xfrd_type* xfrd, buffer_type* buffer,
    unsigned rdata_only, unsigned update, uint32_t t,
    uint32_t* serial);
static ods_status xfrd_parse_rrs(xfrd_type* xfrd, buffer_type* buffer,
    uint16_t count, int* done);
static xfrd_pkt_status xfrd_parse_packet(xfrd_type* xfrd,
    buffer_type* buffer);
static xfrd_pkt_status xfrd_handle_packet(xfrd_type* xfrd,
    buffer_type* buffer);

static void xfrd_tcp_obtain(xfrd_type* xfrd, tcp_set_type* set);
static void xfrd_tcp_read(xfrd_type* xfrd, tcp_set_type* set);
static void xfrd_tcp_release(xfrd_type* xfrd, tcp_set_type* set);
static void xfrd_tcp_write(xfrd_type* xfrd, tcp_set_type* set);
static void xfrd_tcp_xfr(xfrd_type* xfrd, tcp_set_type* set);
static int xfrd_tcp_open(xfrd_type* xfrd, tcp_set_type* set);

static void xfrd_udp_obtain(xfrd_type* xfrd);
static void xfrd_udp_read(xfrd_type* xfrd);
static void xfrd_udp_release(xfrd_type* xfrd);
static int xfrd_udp_read_packet(xfrd_type* xfrd);
static int xfrd_udp_send(xfrd_type* xfrd, buffer_type* buffer);
static int xfrd_udp_send_request_ixfr(xfrd_type* xfrd);

static time_t xfrd_time(xfrd_type* xfrd);
static void xfrd_set_timer(xfrd_type* xfrd, time_t t);
static void xfrd_set_timer_time(xfrd_type* xfrd, time_t t);
static void xfrd_unset_timer(xfrd_type* xfrd);


/**
 * Recover transfer variables.
 *
 */
static uint8_t
xfrd_recover_dname(uint8_t* dname, const char* name)
{
    const uint8_t *s = (const uint8_t *) name;
    uint8_t *h;
    uint8_t *p;
    uint8_t *d = dname;
    size_t label_length;

    if (strcmp(name, ".") == 0) {
        /* Root domain.  */
        dname[0] = 0;
        return 1;
    }
    for (h = d, p = h + 1; *s; ++s, ++p) {
        if (p - dname >= MAXDOMAINLEN) {
            return 0;
        }
        switch (*s) {
            case '.':
                if (p == h + 1) {
                    /* Empty label.  */
                    return 0;
                } else {
                    label_length = p - h - 1;
                    if (label_length > MAXLABELLEN) {
                        return 0;
                    }
                    *h = label_length;
                    h = p;
                }
                break;
            case '\\':
                /* Handle escaped characters (RFC1035 5.1) */
                if (isdigit(s[1]) && isdigit(s[2]) && isdigit(s[3])) {
                    int val = (ldns_hexdigit_to_int(s[1]) * 100 +
                               ldns_hexdigit_to_int(s[2]) * 10 +
                               ldns_hexdigit_to_int(s[3]));
                    if (0 <= val && val <= 255) {
                        s += 3;
                        *p = val;
                    } else {
                        *p = *++s;
                    }
                } else if (s[1] != '\0') {
                    *p = *++s;
                }
                break;
            default:
                *p = *s;
                break;
        }
    }
    if (p != h + 1) {
        /* Terminate last label.  */
        label_length = p - h - 1;
        if (label_length > MAXLABELLEN) {
            return 0;
        }
        *h = label_length;
        h = p;
    }
    /* Add root label.  */
    *h = 0;
    return p-dname;
}


/**
 * Recover transfer variables.
 *
 */
static void
xfrd_recover(xfrd_type* xfrd)
{
    zone_type* zone = (zone_type*) xfrd->zone;
    char* file = NULL;
    FILE* fd = NULL;
    int round_num = 0;
    int master_num = 0;
    int next_master = 0;
    uint32_t timeout = 0;
    uint32_t serial_xfr = 0;
    uint32_t serial_notify = 0;
    uint32_t serial_disk = 0;
    time_t serial_xfr_acquired = 0;
    time_t serial_notify_acquired = 0;
    time_t serial_disk_acquired = 0;
    uint32_t soa_ttl = 0;
    uint32_t soa_serial = 0;
    uint32_t soa_refresh = 0;
    uint32_t soa_retry = 0;
    uint32_t soa_expire = 0;
    uint32_t soa_minimum = 0;
    const char* soa_mname = NULL;
    const char* soa_rname = NULL;

    if (zone && zone->name && zone->db &&
        zone->db->is_initialized && zone->db->have_serial) {
        file = ods_build_path(zone->name, ".xfrd-state", 0, 1);
        if (file) {
            ods_log_verbose("[%s] recover xfrd.state file %s zone %s", xfrd_str,
                file, zone->name);
            fd = ods_fopen(file, NULL, "r");
            if (fd) {
                if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC_V3)) {
                    ods_log_error("[%s] corrupted state file zone %s: read "
                        "magic (start) error", xfrd_str, zone->name);
                    goto xfrd_recover_error;
                }
                if (!backup_read_check_str(fd, ";;Zone:") |
                    !backup_read_check_str(fd, "name") |
                    !backup_read_check_str(fd, zone->name) |
                    !backup_read_check_str(fd, "ttl") |
                    !backup_read_uint32_t(fd, &soa_ttl) |
                    !backup_read_check_str(fd, "mname") |
                    !backup_read_str(fd, &soa_mname) |
                    !backup_read_check_str(fd, "rname") |
                    !backup_read_str(fd, &soa_rname) |
                    !backup_read_check_str(fd, "serial") |
                    !backup_read_uint32_t(fd, &soa_serial) |
                    !backup_read_check_str(fd, "refresh") |
                    !backup_read_uint32_t(fd, &soa_refresh) |
                    !backup_read_check_str(fd, "retry") |
                    !backup_read_uint32_t(fd, &soa_retry) |
                    !backup_read_check_str(fd, "expire") |
                    !backup_read_uint32_t(fd, &soa_expire) |
                    !backup_read_check_str(fd, "minimum") |
                    !backup_read_uint32_t(fd, &soa_minimum)) {
                    ods_log_error("[%s] corrupted state file zone %s: read "
                         ";;Zone error", xfrd_str, zone->name);
                    goto xfrd_recover_error;
                }
                if (!backup_read_check_str(fd, ";;Master:") |
                    !backup_read_check_str(fd, "num") |
                    !backup_read_int(fd, &master_num) |
                    !backup_read_check_str(fd, "next") |
                    !backup_read_int(fd, &next_master) |
                    !backup_read_check_str(fd, "round") |
                    !backup_read_int(fd, &round_num) |
                    !backup_read_check_str(fd, "timeout") |
                    !backup_read_uint32_t(fd, &timeout)) {
                    ods_log_error("[%s] corrupt state file zone %s: read "
                         ";;Master error", xfrd_str, zone->name);
                    goto xfrd_recover_error;
                }
                if (!backup_read_check_str(fd, ";;Serial:") |
                    !backup_read_check_str(fd, "xfr") |
                    !backup_read_uint32_t(fd, &serial_xfr) |
                    !backup_read_time_t(fd, &serial_xfr_acquired) |
                    !backup_read_check_str(fd, "notify") |
                    !backup_read_uint32_t(fd, &serial_notify) |
                    !backup_read_time_t(fd, &serial_notify_acquired) |
                    !backup_read_check_str(fd, "disk") |
                    !backup_read_uint32_t(fd, &serial_disk) |
                    !backup_read_time_t(fd, &serial_disk_acquired)) {
                    ods_log_error("[%s] corrupt state file zone %s: read "
                         ";;Serial error", xfrd_str, zone->name);
                    goto xfrd_recover_error;
                }
                if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC_V3)) {
                    ods_log_error("[%s] corrupt state file zone %s: read "
                        "magic (end) error", xfrd_str, zone->name);
                    goto xfrd_recover_error;
                }

                /* all ok */
                xfrd->master_num = master_num;
                xfrd->next_master = next_master;
                xfrd->round_num = round_num;
                xfrd->timeout.tv_sec = timeout;
                xfrd->timeout.tv_nsec = 0;
                xfrd->master = NULL; /* acl_find_num(...) */
                xfrd->soa.ttl = soa_ttl;
                xfrd->soa.serial = soa_serial;
                xfrd->soa.refresh = soa_refresh;
                xfrd->soa.retry = soa_retry;
                xfrd->soa.expire = soa_expire;
                xfrd->soa.minimum = soa_minimum;
                xfrd->soa.mname[0] = xfrd_recover_dname(xfrd->soa.mname+1,
                    soa_mname);
                xfrd->soa.rname[0] = xfrd_recover_dname(xfrd->soa.rname+1,
                    soa_rname);
                xfrd->serial_xfr = serial_xfr;
                xfrd->serial_xfr_acquired = serial_xfr_acquired;
                xfrd->serial_notify = serial_notify;
                xfrd->serial_notify_acquired = serial_notify_acquired;
                xfrd->serial_disk = serial_disk;
                xfrd->serial_disk_acquired = serial_disk_acquired;
                if (!timeout || serial_notify_acquired ||
                    (serial_disk_acquired &&
                    (uint32_t)xfrd_time(xfrd) - serial_disk_acquired >
                    soa_refresh)) {
                    xfrd_set_timer_refresh(xfrd);
                }
                if (serial_disk_acquired &&
                    ((uint32_t)xfrd_time(xfrd) - serial_disk_acquired >
                    soa_expire)) {
                    xfrd_set_timer_refresh(xfrd);
                }

xfrd_recover_error:
                free((void*)soa_mname);
                free((void*)soa_rname);
                ods_fclose(fd);
            }
            free(file);
        }
    } else {
        ods_log_verbose("[%s] did not recover xfrd.state file zone %s", xfrd_str,
            (zone && zone->name)?zone->name:"(null)");
    }
    return;
}


/**
 * Create zone transfer structure.
 *
 */
xfrd_type*
xfrd_create(void* xfrhandler, void* zone)
{
    xfrd_type* xfrd = NULL;
    allocator_type* allocator = NULL;
    if (!xfrhandler || !zone) {
        return NULL;
    }
    allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] unable to create zone xfr structure: "
            "allocator_create() failed", xfrd_str);
        return NULL;
    }
    xfrd = (xfrd_type*) allocator_alloc(allocator, sizeof(xfrd_type));
    if (!xfrd) {
        ods_log_error("[%s] unable to create zone xfr structure: "
            " allocator_alloc() failed", xfrd_str);
        allocator_cleanup(allocator);
        return NULL;
    }
    lock_basic_init(&xfrd->serial_lock);
    lock_basic_init(&xfrd->rw_lock);

    xfrd->allocator = allocator;
    xfrd->xfrhandler = xfrhandler;
    xfrd->zone = zone;
    xfrd->tcp_conn = -1;
    xfrd->round_num = -1;
    xfrd->master_num = 0;
    xfrd->next_master = -1;
    xfrd->master = NULL;
    lock_basic_lock(&xfrd->serial_lock);
    xfrd->serial_xfr = 0;
    xfrd->serial_disk = 0;
    xfrd->serial_notify = 0;
    xfrd->serial_xfr_acquired = 0;
    xfrd->serial_disk_acquired = 0;
    xfrd->serial_notify_acquired = 0;
    xfrd->serial_retransfer = 0;
    lock_basic_unlock(&xfrd->serial_lock);
    xfrd->query_id = 0;
    xfrd->msg_seq_nr = 0;
    xfrd->msg_rr_count = 0;
    xfrd->msg_old_serial = 0;
    xfrd->msg_new_serial = 0;
    xfrd->msg_is_ixfr = 0;
    xfrd->msg_do_retransfer = 0;
    xfrd->udp_waiting = 0;
    xfrd->udp_waiting_next = NULL;
    xfrd->tcp_waiting = 0;
    xfrd->tcp_waiting_next = NULL;
    xfrd->tsig_rr = tsig_rr_create(allocator);
    if (!xfrd->tsig_rr) {
        xfrd_cleanup(xfrd, 0);
        return NULL;
    }
    memset(&xfrd->soa, 0, sizeof(xfrd->soa));
    xfrd->soa.ttl = 0;
    xfrd->soa.mname[0] = 1;
    xfrd->soa.rname[0] = 1;
    xfrd->soa.serial = 0;
    xfrd->soa.refresh = 3600;
    xfrd->soa.retry = 300;
    xfrd->soa.expire = 604800;
    xfrd->soa.minimum = 3600;
    xfrd->handler.fd = -1;
    xfrd->handler.user_data = (void*) xfrd;
    xfrd->handler.timeout = 0;
    xfrd->handler.event_types =
        NETIO_EVENT_READ|NETIO_EVENT_TIMEOUT;
    xfrd->handler.event_handler = xfrd_handle_zone;
    xfrd_set_timer_time(xfrd, 0);
    xfrd_recover(xfrd);
    return xfrd;
}


/**
 * Get time.
 *
 */
static time_t
xfrd_time(xfrd_type* xfrd)
{
    ods_log_assert(xfrd);
    ods_log_assert(xfrd->xfrhandler);
    return xfrhandler_time((xfrhandler_type*) xfrd->xfrhandler);
}


/**
 * Set timer.
 *
 */
static void
xfrd_set_timer(xfrd_type* xfrd, time_t t)
{
    if (!xfrd || !xfrd->xfrhandler) {
        return;
    }
    /**
     * Randomize the time, within 90%-100% of original.
     * Not later so zones cannot expire too late.
     */
    if(t > xfrd_time(xfrd) + 10) {
        time_t extra = t - xfrd_time(xfrd);
        time_t base = extra*9/10;
#ifdef HAVE_ARC4RANDOM_UNIFORM
        t = xfrd_time(xfrd) + base +
            arc4random_uniform(extra-base);
#elif HAVE_ARC4RANDOM
        t = xfrd_time(xfrd) + base +
            arc4random()%(extra-base);
#else
        t = xfrd_time(xfrd) + base +
            random()%(extra-base);
#endif
    }
    xfrd->handler.timeout = &xfrd->timeout;
    xfrd->timeout.tv_sec = t;
    xfrd->timeout.tv_nsec = 0;
    return;
}


/**
 * Unset timer.
 *
 */
static void
xfrd_unset_timer(xfrd_type* xfrd)
{
    ods_log_assert(xfrd);
    xfrd->handler.timeout = NULL;
    return;
}


/**
 * Set timer timeout to time.
 *
 */
static void
xfrd_set_timer_time(xfrd_type* xfrd, time_t t)
{
    ods_log_assert(xfrd);
    xfrd_set_timer(xfrd, xfrd_time(xfrd) + t);
    return;
}


/**
 * Set timeout for zone transfer to now.
 *
 */
void
xfrd_set_timer_now(xfrd_type* xfrd)
{
    zone_type* zone = NULL;
    if (!xfrd || !xfrd->zone || !xfrd->xfrhandler) {
        return;
    }
    zone = (zone_type*) xfrd->zone;
    ods_log_debug("[%s] zone %s sets timer timeout now", xfrd_str,
        zone->name);
    xfrd_set_timer_time(xfrd, 0);
    return;
}


/**
 * Set timeout for zone transfer to RETRY.
 *
 */
void
xfrd_set_timer_retry(xfrd_type* xfrd)
{
    zone_type* zone = NULL;
    if (!xfrd || !xfrd->zone || !xfrd->xfrhandler) {
        return;
    }
    zone = (zone_type*) xfrd->zone;
    ods_log_debug("[%s] zone %s sets timer timeout retry %u", xfrd_str,
        zone->name, (unsigned) xfrd->soa.retry);
    xfrd_set_timer_time(xfrd, xfrd->soa.retry);
    return;
}


/**
 * Set timeout for zone transfer to REFRESH.
 *
 */
void
xfrd_set_timer_refresh(xfrd_type* xfrd)
{
    zone_type* zone = NULL;
    if (!xfrd || !xfrd->zone || !xfrd->xfrhandler) {
        return;
    }
    zone = (zone_type*) xfrd->zone;
    ods_log_debug("[%s] zone %s sets timer timeout refresh %u", xfrd_str,
        zone->name, (unsigned) xfrd->soa.refresh);
    xfrd_set_timer_time(xfrd, xfrd->soa.refresh);
    return;
}


/**
 * Use acl address to setup sockaddr struct.
 *
 */
static socklen_t
xfrd_acl_sockaddr(acl_type* acl, unsigned int port,
    struct sockaddr_storage *sck)
{
    ods_log_assert(acl);
    ods_log_assert(sck);
    ods_log_assert(port);
    memset(sck, 0, sizeof(struct sockaddr_storage));
    if (acl->family == AF_INET6) {
        struct sockaddr_in6* sa = (struct sockaddr_in6*)sck;
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(port);
        sa->sin6_addr = acl->addr.addr6;
        return sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in* sa = (struct sockaddr_in*)sck;
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
        sa->sin_addr = acl->addr.addr;
        return sizeof(struct sockaddr_in);
    }
    return 0;
}


/**
 * Use acl address to setup remote sockaddr struct.
 *
 */
socklen_t
xfrd_acl_sockaddr_to(acl_type* acl, struct sockaddr_storage *to)
{
    unsigned int port = 0;
    if (!acl || !to) {
        return 0;
    }
    port = acl->port ? acl->port : (unsigned) atoi(DNS_PORT_STRING);
    return xfrd_acl_sockaddr(acl, port, to);
}


/**
 * Sign transfer request.
 *
 */
static void
xfrd_tsig_sign(xfrd_type* xfrd, buffer_type* buffer)
{
    tsig_algo_type* algo = NULL;
    if (!xfrd || !xfrd->tsig_rr || !xfrd->master || !xfrd->master->tsig ||
        !xfrd->master->tsig->key || !buffer) {
        return; /* no tsig configured */
    }
    algo = tsig_lookup_algo(xfrd->master->tsig->algorithm);
    if (!algo) {
        ods_log_error("[%s] unable to sign request: tsig unknown algorithm "
            "%s", xfrd_str, xfrd->master->tsig->algorithm);
        return;
    }
    ods_log_assert(algo);
    tsig_rr_reset(xfrd->tsig_rr, algo, xfrd->master->tsig->key);
    xfrd->tsig_rr->original_query_id = buffer_pkt_id(buffer);
    xfrd->tsig_rr->algo_name = ldns_rdf_clone(xfrd->tsig_rr->algo->wf_name);
    xfrd->tsig_rr->key_name = ldns_rdf_clone(xfrd->tsig_rr->key->dname);
    log_dname(xfrd->tsig_rr->key_name, "tsig sign query with key", LOG_DEBUG);
    log_dname(xfrd->tsig_rr->algo_name, "tsig sign query with algorithm",
        LOG_DEBUG);
    tsig_rr_prepare(xfrd->tsig_rr);
    tsig_rr_update(xfrd->tsig_rr, buffer, buffer_position(buffer));
    tsig_rr_sign(xfrd->tsig_rr);
    ods_log_debug("[%s] tsig append rr to request id=%u", xfrd_str,
        buffer_pkt_id(buffer));
    tsig_rr_append(xfrd->tsig_rr, buffer);
    buffer_pkt_set_arcount(buffer, buffer_pkt_arcount(buffer)+1);
    tsig_rr_prepare(xfrd->tsig_rr);
    return;
}


/**
 * Process TSIG in transfer.
 *
 */
static int
xfrd_tsig_process(xfrd_type* xfrd, buffer_type* buffer)
{
    zone_type* zone = NULL;
    int have_tsig = 0;
    if (!xfrd || !xfrd->tsig_rr || !xfrd->master || !xfrd->master->tsig ||
        !xfrd->master->tsig->key || !buffer) {
        return 1; /* no tsig configured */
    }
    zone = (zone_type*) xfrd->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(xfrd->master->address);
    if (!tsig_rr_find(xfrd->tsig_rr, buffer)) {
        ods_log_error("[%s] unable to process tsig: xfr zone %s from %s "
            "has malformed tsig rr", xfrd_str, zone->name,
        xfrd->master->address);
        return 0;
    }
    if (xfrd->tsig_rr->status == TSIG_OK) {
        have_tsig = 1;
        if (xfrd->tsig_rr->error_code != LDNS_RCODE_NOERROR) {
            ods_log_error("[%s] zone %s, from %s has tsig error (%s)",
                xfrd_str, zone->name, xfrd->master->address,
                tsig_strerror(xfrd->tsig_rr->error_code));
        }
        /* strip the TSIG resource record off... */
        buffer_set_limit(buffer, xfrd->tsig_rr->position);
        buffer_pkt_set_arcount(buffer, buffer_pkt_arcount(buffer)-1);
    }
    /* keep running the TSIG hash */
    tsig_rr_update(xfrd->tsig_rr, buffer, buffer_limit(buffer));
    if (have_tsig) {
        if (!tsig_rr_verify(xfrd->tsig_rr)) {
            ods_log_error("[%s] unable to process tsig: xfr zone %s from %s "
                "has bad tsig signature", xfrd_str, zone->name,
                xfrd->master->address);
            return 0;
        }
        /* prepare for next tsigs */
        tsig_rr_prepare(xfrd->tsig_rr);
    } else if (xfrd->tsig_rr->update_since_last_prepare >
          XFRD_TSIG_MAX_UNSIGNED) {
          /* we allow a number of non-tsig signed packets */
          ods_log_error("[%s] unable to process tsig: xfr zone %s, from %s "
              "has too many consecutive packets without tsig", xfrd_str,
              zone->name, xfrd->master->address);
          return 0;
    }
    if (!have_tsig && xfrd->msg_seq_nr == 0) {
            ods_log_error("[%s] unable to process tsig: xfr zone %s from %s "
                "has no tsig in first packet of reply", xfrd_str,
                zone->name, xfrd->master->address);
          return 0;
    }
    /* process TSIG ok */
    return 1;
}


/**
 * Commit answer on disk.
 *
 */
static void
xfrd_commit_packet(xfrd_type* xfrd)
{
    zone_type* zone = NULL;
    char* xfrfile = NULL;
    FILE* fd = NULL;
    time_t serial_disk_acq = 0;
    ods_log_assert(xfrd);
    zone = (zone_type*) xfrd->zone;
    xfrfile = ods_build_path(zone->name, ".xfrd", 0, 1);
    if (!xfrfile) {
        ods_log_crit("[%s] unable to commit xfr zone %s: build path failed",
            xfrd_str, zone->name);
        return;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    lock_basic_lock(&zone->zone_lock);
    lock_basic_lock(&xfrd->rw_lock);
    lock_basic_lock(&xfrd->serial_lock);
    /* mark end packet */
    fd = ods_fopen(xfrfile, NULL, "a");
    free((void*)xfrfile);
    if (fd) {
        fprintf(fd, ";;ENDPACKET\n");
        ods_fclose(fd);
    } else {
        lock_basic_unlock(&xfrd->rw_lock);
        lock_basic_unlock(&zone->zone_lock);
        lock_basic_unlock(&xfrd->serial_lock);
        ods_log_crit("[%s] unable to commit xfr zone %s: ods_fopen() failed "
            "(%s)", xfrd_str, zone->name, strerror(errno));
        return;
    }
    /* update soa serial management */
    xfrd->serial_disk = xfrd->msg_new_serial;
    serial_disk_acq = xfrd->serial_disk_acquired;
    xfrd->serial_disk_acquired = xfrd_time(xfrd);
    /* ensure newer time */
    if (xfrd->serial_disk_acquired == serial_disk_acq) {
        xfrd->serial_disk_acquired++;
    }
    xfrd->soa.serial = xfrd->serial_disk;
    if (xfrd->msg_do_retransfer ||
            (util_serial_gt(xfrd->serial_disk, xfrd->serial_xfr) &&
             xfrd->serial_disk_acquired > xfrd->serial_xfr_acquired)) {
        /* reschedule task */
        int ret = 0;
        xfrhandler_type* xfrhandler = (xfrhandler_type*) xfrd->xfrhandler;
        engine_type* engine = (engine_type*) xfrhandler->engine;
        ods_log_assert(xfrhandler);
        ods_log_assert(engine);
        ods_log_debug("[%s] reschedule task for zone %s: disk serial=%u "
            "acquired=%u, memory serial=%u acquired=%u", xfrd_str,
            zone->name, xfrd->serial_disk,
            xfrd->serial_disk_acquired, xfrd->serial_xfr,
            xfrd->serial_xfr_acquired);
        ret = zone_reschedule_task(zone, engine->taskq, TASK_READ);
        if (ret != ODS_STATUS_OK) {
            ods_log_crit("[%s] unable to reschedule task for zone %s: %s",
                xfrd_str, zone->name, ods_status2str(ret));
        } else {
            engine_wakeup_workers(engine);
        }
    }
    /* reset retransfer */
    xfrd->msg_do_retransfer = 0;

    lock_basic_unlock(&xfrd->serial_lock);
    lock_basic_unlock(&xfrd->rw_lock);
    lock_basic_unlock(&zone->zone_lock);
    return;
}


/**
 * Dump answer to disk.
 *
 */
static void
xfrd_dump_packet(xfrd_type* xfrd, buffer_type* buffer)
{
    zone_type* zone = NULL;
    char* xfrfile = NULL;
    FILE* fd = NULL;
    ldns_pkt* pkt = NULL;
    ldns_status status = LDNS_STATUS_OK;
    ods_log_assert(buffer);
    ods_log_assert(xfrd);
    zone = (zone_type*) xfrd->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    status = ldns_wire2pkt(&pkt, buffer_begin(buffer), buffer_limit(buffer));
    if (status != LDNS_STATUS_OK) {
        ods_log_crit("[%s] unable to dump packet zone %s: ldns_wire2pkt() "
            "failed (%s)", xfrd_str, zone->name,
            ldns_get_errorstr_by_id(status));
        return;
    }
    ods_log_assert(pkt);
    xfrfile = ods_build_path(zone->name, ".xfrd", 0, 1);
    if (!xfrfile) {
        ods_log_crit("[%s] unable to dump packet zone %s: build path failed",
            xfrd_str, zone->name);
        return;
    }
    lock_basic_lock(&xfrd->rw_lock);
    if (xfrd->msg_do_retransfer && !xfrd->msg_seq_nr && !xfrd->msg_is_ixfr) {
        fd = ods_fopen(xfrfile, NULL, "w");
    } else {
        fd = ods_fopen(xfrfile, NULL, "a");
    }
    free((void*) xfrfile);
    if (!fd) {
        ods_log_crit("[%s] unable to dump packet zone %s: ods_fopen() failed "
            "(%s)", xfrd_str, zone->name, strerror(errno));
        lock_basic_unlock(&xfrd->rw_lock);
        return;
    }
    ods_log_assert(fd);
    if (xfrd->msg_seq_nr == 0) {
        fprintf(fd, ";;BEGINPACKET\n");
    }
    ldns_rr_list_print(fd, ldns_pkt_answer(pkt));
    ods_fclose(fd);
    lock_basic_unlock(&xfrd->rw_lock);
    ldns_pkt_free(pkt);
    return;
}


/**
 * Write SOA in packet.
 *
 */
static void
xfrd_write_soa(xfrd_type* xfrd, buffer_type* buffer)
{
    zone_type* zone = NULL;
    size_t rdlength_pos = 0;
    uint16_t rdlength = 0;
    ods_log_assert(xfrd);
    ods_log_assert(buffer);
    zone = (zone_type*) xfrd->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->apex);
    buffer_write_rdf(buffer, zone->apex);
    buffer_write_u16(buffer, (uint16_t) LDNS_RR_TYPE_SOA);
    buffer_write_u16(buffer, (uint16_t) zone->klass);
    buffer_write_u32(buffer, xfrd->soa.ttl);
    rdlength_pos = buffer_position(buffer);
    buffer_skip(buffer, sizeof(rdlength));
    buffer_write(buffer, xfrd->soa.mname+1, xfrd->soa.mname[0]);
    buffer_write(buffer, xfrd->soa.rname+1, xfrd->soa.rname[0]);
    buffer_write_u32(buffer, xfrd->soa.serial);
    buffer_write_u32(buffer, xfrd->soa.refresh);
    buffer_write_u32(buffer, xfrd->soa.retry);
    buffer_write_u32(buffer, xfrd->soa.expire);
    buffer_write_u32(buffer, xfrd->soa.minimum);
    rdlength = buffer_position(buffer) - rdlength_pos - sizeof(rdlength);
    buffer_write_u16_at(buffer, rdlength_pos, rdlength);
    return;
}


/**
 * Update SOA.
 *
 */
static void
xfrd_update_soa(xfrd_type* xfrd, buffer_type* buffer, uint32_t ttl,
    uint16_t mname_pos, uint16_t rname_pos,
    uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum)
{
    zone_type* zone = NULL;
    ods_log_assert(xfrd);
    ods_log_assert(buffer);
    zone = (zone_type*) xfrd->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->apex);
    xfrd->soa.ttl = ttl;
    xfrd->soa.refresh = refresh;
    xfrd->soa.retry = retry;
    xfrd->soa.expire = expire;
    xfrd->soa.minimum = minimum;
    buffer_set_position(buffer, mname_pos);
    if (!(xfrd->soa.mname[0] =
        buffer_read_dname(buffer, xfrd->soa.mname+1, 1))) {
        xfrd->soa.mname[0] = 1;
        xfrd->soa.mname[1] = 0;
    }
    buffer_set_position(buffer, rname_pos);
    if (!(xfrd->soa.rname[0] =
        buffer_read_dname(buffer, xfrd->soa.rname+1, 1))) {
        xfrd->soa.rname[0] = 1;
        xfrd->soa.rname[1] = 0;
    }
    return;
}


/**
 * Parse SOA RR in packet.
 *
 */
static int
xfrd_parse_soa(xfrd_type* xfrd, buffer_type* buffer, unsigned rdata_only,
    unsigned update, uint32_t t, uint32_t* soa_serial)
{
    ldns_rr_type type = LDNS_RR_TYPE_SOA;
    uint16_t mname_pos = 0;
    uint16_t rname_pos = 0;
    uint16_t pos = 0;
    uint32_t serial = 0;
    uint32_t refresh = 0;
    uint32_t retry = 0;
    uint32_t expire = 0;
    uint32_t minimum = 0;
    uint32_t ttl = t;
    ods_log_assert(xfrd);
    ods_log_assert(buffer);

    /* type class ttl */
    if (!rdata_only) {
        if (!buffer_available(buffer, 10)) {
            ods_log_debug("[%s] unable to parse soa: rr too short",
                xfrd_str);
            return 0;
        }
        type = (ldns_rr_type) buffer_read_u16(buffer);
        if (type != LDNS_RR_TYPE_SOA) {
            ods_log_debug("[%s] unable to parse soa: rrtype %u != soa",
                xfrd_str, (unsigned) type);
            return 0;
        }
        (void)buffer_read_u16(buffer); /* class */
        ttl = buffer_read_u32(buffer);
        /* rdata length */
        if (!buffer_available(buffer, buffer_read_u16(buffer))) {
            ods_log_debug("[%s] unable to parse soa: rdata too short",
                xfrd_str);
            return 0;
        }
    }
    /* MNAME */
    mname_pos = buffer_position(buffer);
    if (!buffer_skip_dname(buffer)) {
        ods_log_debug("[%s] unable to parse soa: bad mname",
            xfrd_str);
        return 0;
    }
    /* RNAME */
    rname_pos = buffer_position(buffer);
    if (!buffer_skip_dname(buffer)) {
        ods_log_debug("[%s] unable to parse soa: bad rname",
            xfrd_str);
        return 0;
    }
    serial = buffer_read_u32(buffer);
    refresh = buffer_read_u32(buffer);
    retry = buffer_read_u32(buffer);
    expire = buffer_read_u32(buffer);
    minimum = buffer_read_u32(buffer);
    pos = buffer_position(buffer);
    if (soa_serial) {
        *soa_serial = serial;
    }
    if (update) {
        xfrd_update_soa(xfrd, buffer, ttl, mname_pos, rname_pos,
            refresh, retry, expire, minimum);
    }
    buffer_set_position(buffer, pos);
    return 1;
}


/**
 * Parse RRs in packet.
 *
 */
static ods_status
xfrd_parse_rrs(xfrd_type* xfrd, buffer_type* buffer, uint16_t count,
    int* done)
{
    ldns_rr_type type = 0;
    uint16_t rrlen = 0;
    uint32_t ttl = 0;
    uint32_t serial = 0;
    uint32_t tmp_serial = 0;
    size_t i = 0;
    ods_log_assert(xfrd);
    ods_log_assert(buffer);
    ods_log_assert(done);
    for (i=0; i < count; ++i, ++xfrd->msg_rr_count) {
         if (*done) {
            return ODS_STATUS_OK;
         }
         if (!buffer_skip_dname(buffer)) {
             return ODS_STATUS_SKIPDNAME;
         }
         if (!buffer_available(buffer, 10)) {
             return ODS_STATUS_BUFAVAIL;
         }
         (void)buffer_position(buffer);
         type = (ldns_rr_type) buffer_read_u16(buffer);
         (void)buffer_read_u16(buffer); /* class */
         ttl = buffer_read_u32(buffer);
         rrlen = buffer_read_u16(buffer);
         if (!buffer_available(buffer, rrlen)) {
             return ODS_STATUS_BUFAVAIL;
         }
         if (type == LDNS_RR_TYPE_SOA) {
             if (!xfrd_parse_soa(xfrd, buffer, 1, 0, ttl, &serial)) {
                 return ODS_STATUS_PARSESOA;
             }
             if (xfrd->msg_rr_count == 1 && serial != xfrd->msg_new_serial) {
                 /* 2nd RR is SOA with different serial, this is an IXFR */
                 xfrd->msg_is_ixfr = 1;
                 lock_basic_lock(&xfrd->serial_lock);
                 if (!xfrd->serial_disk_acquired) {
                     lock_basic_unlock(&xfrd->serial_lock);
                     /* got IXFR but need AXFR */
                     return ODS_STATUS_REQAXFR;
                 }
                 if (!xfrd->msg_do_retransfer && serial != xfrd->serial_disk) {
                     lock_basic_unlock(&xfrd->serial_lock);
                     /* bad start serial in IXFR */
                     return ODS_STATUS_INSERIAL;
                 }
                 lock_basic_unlock(&xfrd->serial_lock);
                 xfrd->msg_old_serial = serial;
                 tmp_serial = serial;
             } else if (serial == xfrd->msg_new_serial) {
                 /* saw another SOA of new serial. */
                 if (xfrd->msg_is_ixfr == 1) {
                     xfrd->msg_is_ixfr = 2; /* seen middle SOA in ixfr */
                 } else {
                     *done = 1; /* final axfr/ixfr soa */
                 }
             } else if (xfrd->msg_is_ixfr) {
                 /* some additional checks */
                 if (util_serial_gt(serial, xfrd->msg_new_serial)) {
                     /* bad middle serial in IXFR (too high) */
                     return ODS_STATUS_INSERIAL;
                 }
                 if (util_serial_gt(tmp_serial, serial)) {
                     /* middle serial decreases in IXFR */
                     return ODS_STATUS_INSERIAL;
                 }
                 /* serial ok, update tmp serial */
                 tmp_serial = serial;
             }
         } else {
             buffer_skip(buffer, rrlen);
         }
    }
    return ODS_STATUS_OK;
}


/**
 * Parse packet.
 *
 */
static xfrd_pkt_status
xfrd_parse_packet(xfrd_type* xfrd, buffer_type* buffer)
{
    zone_type* zone = NULL;
    uint16_t qdcount = 0;
    uint16_t ancount = 0;
    uint16_t ancount_todo = 0;
    uint16_t rrcount = 0;
    uint32_t serial = 0;
    int done = 0;
    ods_status status = ODS_STATUS_OK;
    ods_log_assert(buffer);
    ods_log_assert(xfrd);
    ods_log_assert(xfrd->master);
    ods_log_assert(xfrd->master->address);
    zone = (zone_type*) xfrd->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    /* check packet size */
    if (!buffer_available(buffer, BUFFER_PKT_HEADER_SIZE)) {
        ods_log_error("[%s] unable to parse packet: zone %s received bad "
            "packet from %s (too small)", xfrd_str, zone->name,
            xfrd->master->address);
        return XFRD_PKT_BAD;
    }
    /* check query id */
    if (buffer_pkt_id(buffer) != xfrd->query_id) {
        ods_log_error("[%s] bad packet: zone %s received bad query id "
            "%u from %s (expected %u)", xfrd_str, zone->name,
            buffer_pkt_id(buffer), xfrd->master->address, xfrd->query_id);
        return XFRD_PKT_BAD;
    }
    /* check rcode */
    if (buffer_pkt_rcode(buffer) != LDNS_RCODE_NOERROR) {
        ods_log_error("[%s] bad packet: zone %s received error code %s from %s",
            xfrd_str, zone->name, ldns_pkt_rcode2str(buffer_pkt_rcode(buffer)),
            xfrd->master->address);
        if (buffer_pkt_rcode(buffer) == LDNS_RCODE_NOTIMPL) {
            return XFRD_PKT_NOTIMPL;
        } else if (buffer_pkt_rcode(buffer) != LDNS_RCODE_NOTAUTH) {
            return XFRD_PKT_BAD;
        }
    }
    /* check tsig */
    if (!xfrd_tsig_process(xfrd, buffer)) {
        ods_log_error("[%s] bad packet: zone %s received bad tsig "
            "from %s", xfrd_str, zone->name, xfrd->master->address);
        return XFRD_PKT_BAD;
    }
    /* skip header and question section */
    buffer_skip(buffer, BUFFER_PKT_HEADER_SIZE);
    qdcount = buffer_pkt_qdcount(buffer);
    for (rrcount = 0; rrcount < qdcount; rrcount++) {
        if (!buffer_skip_rr(buffer, 1)) {
            ods_log_error("[%s] bad packet: zone %s received bad "
                "question section from %s (bad rr)", xfrd_str, zone->name,
                xfrd->master->address);
            return XFRD_PKT_BAD;
        }
    }
    /* answer section */
    ancount = buffer_pkt_ancount(buffer);
    if (xfrd->msg_rr_count == 0 && ancount == 0) {
        if (xfrd->tcp_conn == -1 && buffer_pkt_tc(buffer)) {
            ods_log_info("[%s] zone %s received tc from %s, retry tcp",
                xfrd_str, zone->name, xfrd->master->address);
            return XFRD_PKT_TC;
        }
        ods_log_error("[%s] bad packet: zone %s received bad xfr packet "
            "from %s (nodata)", xfrd_str, zone->name, xfrd->master->address);
        return XFRD_PKT_BAD;
    }

    ancount_todo = ancount;
    if (xfrd->msg_rr_count == 0) {
        /* parse the first RR, see if it is a SOA */
        if (!buffer_skip_dname(buffer) ||
            !xfrd_parse_soa(xfrd, buffer, 0, 1, 0, &serial)) {
            ods_log_error("[%s] bad packet: zone %s received bad xfr "
                "packet from %s (bad soa)", xfrd_str, zone->name,
                xfrd->master->address);
            return XFRD_PKT_BAD;
        }
        /* check serial */
        lock_basic_lock(&xfrd->serial_lock);
        if (!xfrd->msg_do_retransfer &&
            xfrd->serial_disk_acquired && xfrd->serial_disk == serial) {
            ods_log_info("[%s] zone %s got update indicating current "
                "serial %u from %s", xfrd_str, zone->name, serial,
                 xfrd->master->address);
            xfrd->serial_disk_acquired = xfrd_time(xfrd);
            if (xfrd->serial_xfr == serial) {
                xfrd->serial_xfr_acquired = xfrd->serial_disk_acquired;
                if (!xfrd->serial_notify_acquired) {
                    /* not notified or anything, so stop asking around */
                    xfrd->round_num = -1; /* next try start a new round */
                    xfrd_set_timer_refresh(xfrd);
                    ods_log_debug("[%s] zone %s wait refresh time", xfrd_str,
                       zone->name);
                    lock_basic_unlock(&xfrd->serial_lock);
                    return XFRD_PKT_NEWLEASE;
                }
                /* try next master */
                ods_log_debug("[%s] zone %s try next master", xfrd_str,
                    zone->name);
                lock_basic_unlock(&xfrd->serial_lock);
                return XFRD_PKT_BAD;
            }
        }
        if (!xfrd->msg_do_retransfer && xfrd->serial_disk_acquired &&
            !util_serial_gt(serial, xfrd->serial_disk)) {
            ods_log_info("[%s] zone %s ignoring old serial %u from %s "
                "(have %u)", xfrd_str, zone->name, serial,
                xfrd->master->address, xfrd->serial_disk);
            lock_basic_unlock(&xfrd->serial_lock);
            return XFRD_PKT_BAD;
        }

        xfrd->msg_new_serial = serial;
        if (!xfrd->msg_do_retransfer && xfrd->serial_disk_acquired) {
            xfrd->msg_old_serial = xfrd->serial_disk;
        } else {
            xfrd->msg_old_serial = 0;
        }
        /* update notify serial if this xfr is newer */
        if (ancount > 1 && xfrd->serial_notify_acquired &&
            util_serial_gt(serial, xfrd->serial_notify)) {
            xfrd->serial_notify = serial;
        }
        lock_basic_unlock(&xfrd->serial_lock);
        xfrd->msg_rr_count = 1;
        xfrd->msg_is_ixfr = 0;
        ancount_todo = ancount - 1;
    }
    /* check tc bit */
    if (xfrd->tcp_conn == -1 && buffer_pkt_tc(buffer)) {
        ods_log_info("[%s] zone %s received tc from %s, retry tcp",
            xfrd_str, zone->name, xfrd->master->address);
        return XFRD_PKT_TC;
    }
    if (xfrd->tcp_conn == -1 && ancount < 2) {
        /* too short to be a real ixfr/axfr data transfer */
        ods_log_info("[%s] zone %s received too short udp reply from %s, "
            "retry tcp", xfrd_str, zone->name, xfrd->master->address);
        return XFRD_PKT_TC;
    }
    status = xfrd_parse_rrs(xfrd, buffer, ancount_todo, &done);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] bad packet: zone %s received bad xfr packet "
            "from %s (%s)", xfrd_str, zone->name, xfrd->master->address,
            ods_status2str(status));
        return XFRD_PKT_BAD;
    }
    if (xfrd->tcp_conn == -1 && !done) {
        ods_log_error("[%s] bad packet: zone %s received bad xfr packet "
            "(xfr over udp incomplete)", xfrd_str, zone->name,
            xfrd->master->address);
        return XFRD_PKT_BAD;
    }
    if (!done) {
        return XFRD_PKT_MORE;
    }
    return XFRD_PKT_XFR;
}


/**
 * Handle packet.
 *
 */
static xfrd_pkt_status
xfrd_handle_packet(xfrd_type* xfrd, buffer_type* buffer)
{
    xfrd_pkt_status res = XFRD_PKT_BAD;
    zone_type* zone = NULL;
    ods_log_assert(xfrd);
    ods_log_assert(xfrd->master);
    ods_log_assert(xfrd->master->address);
    zone = (zone_type*) xfrd->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    res = xfrd_parse_packet(xfrd, buffer);
    ods_log_debug("[%s] zone %s xfr packet parsed (res %d)", xfrd_str,
        zone->name, res);

    switch (res) {
        case XFRD_PKT_MORE:
        case XFRD_PKT_XFR:
            /* continue with commit */
            break;
        case XFRD_PKT_NEWLEASE:
        case XFRD_PKT_TC:
            return res;
            break;
        case XFRD_PKT_NOTIMPL:
        case XFRD_PKT_BAD:
        default:
            /* rollback */
            if (xfrd->msg_seq_nr > 0) {
                buffer_clear(buffer);
                ods_log_info("[%s] zone %s xfr rollback", xfrd_str,
                    zone->name);
                buffer_flip(buffer);
            }
            return res;
            break;
    }
    /* dump reply on disk to diff file */
    xfrd_dump_packet(xfrd, buffer);
    /* more? */
    xfrd->msg_seq_nr++;
    if (res == XFRD_PKT_MORE) {
        /* wait for more */
        return XFRD_PKT_MORE;
    }
    /* done */
    buffer_clear(buffer);
    buffer_flip(buffer);
    /* commit packet */
    xfrd_commit_packet(xfrd);
    /* next time */
    lock_basic_lock(&xfrd->serial_lock);

    ods_log_info("[%s] zone %s transfer done [notify acquired %u, serial on "
        "disk %u, notify serial %u]", xfrd_str, zone->name,
        xfrd->serial_notify_acquired, xfrd->serial_disk,
        xfrd->serial_notify);

    if (xfrd->serial_notify_acquired &&
        !util_serial_gt(xfrd->serial_notify, xfrd->serial_disk)) {
        ods_log_verbose("[%s] zone %s reset notify acquired", xfrd_str,
            zone->name);
        xfrd->serial_notify_acquired = 0;
    }
    if (!xfrd->serial_notify_acquired) {
        ods_log_debug("[%s] zone %s xfr done", xfrd_str, zone->name);
        xfrd->round_num = -1; /* next try start anew */
        xfrd_set_timer_refresh(xfrd);
        lock_basic_unlock(&xfrd->serial_lock);
        return XFRD_PKT_XFR;
    }
    lock_basic_unlock(&xfrd->serial_lock);
    /* try to get an even newer serial */
    ods_log_info("[%s] zone %s try get newer serial", xfrd_str, zone->name);
    return XFRD_PKT_BAD;
}


/** TCP **/


/**
 * Write to tcp.
 *
 */
static void
xfrd_tcp_write(xfrd_type* xfrd, tcp_set_type* set)
{
    zone_type* zone = NULL;
    tcp_conn_type* tcp = NULL;
    int ret = 0;
    int error = 0;
    socklen_t len = 0;

    ods_log_assert(set);
    ods_log_assert(xfrd);
    ods_log_assert(xfrd->tcp_conn != -1);
    zone = (zone_type*) xfrd->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    tcp = set->tcp_conn[xfrd->tcp_conn];
    if (tcp->total_bytes == 0) {
        /* check for pending error from nonblocking connect */
        /* from Stevens, unix network programming, vol1, 3rd ed, p450 */
        len = sizeof(error);
        if (getsockopt(tcp->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            error = errno; /* on solaris errno is error */
        }
        if (error == EINPROGRESS || error == EWOULDBLOCK) {
            ods_log_debug("[%s] zone %s zero write, write again later (%s)",
                xfrd_str, zone->name, strerror(error));
            return; /* try again later */
        }
        if (error != 0) {
            ods_log_error("[%s] zone %s cannot tcp connect to %s: %s",
                xfrd_str, zone->name, xfrd->master->address, strerror(errno));
            xfrd_set_timer_now(xfrd);
            xfrd_tcp_release(xfrd, set);
            return;
        }
    }
    ret = tcp_conn_write(tcp);
    if(ret == -1) {
        ods_log_error("[%s] zone %s cannot tcp write to %s: %s",
            xfrd_str, zone->name, xfrd->master->address, strerror(errno));
        xfrd_set_timer_now(xfrd);
        xfrd_tcp_release(xfrd, set);
        return;
    }
    if (ret == 0) {
        ods_log_debug("[%s] zone %s zero write, write again later",
            xfrd_str, zone->name);
        return; /* write again later */
    }
    /* done writing, get ready for reading */
    ods_log_debug("[%s] zone %s done writing, get ready for reading",
        xfrd_str, zone->name);
    tcp->is_reading = 1;
    tcp_conn_ready(tcp);
    xfrd->handler.event_types = NETIO_EVENT_READ|NETIO_EVENT_TIMEOUT;
    xfrd_tcp_read(xfrd, set);
    return;
}


/**
 * Open tcp connection.
 *
 */
static int
xfrd_tcp_open(xfrd_type* xfrd, tcp_set_type* set)
{
    int fd, family, conn;
    struct sockaddr_storage to;
    socklen_t to_len;
    zone_type* zone = NULL;

    ods_log_assert(set);
    ods_log_assert(xfrd);
    ods_log_assert(xfrd->tcp_conn != -1);
    ods_log_assert(xfrd->master);
    ods_log_assert(xfrd->master->address);
    zone = (zone_type*) xfrd->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_debug("[%s] zone %s open tcp connection to %s", xfrd_str,
        zone->name, xfrd->master->address);
    set->tcp_conn[xfrd->tcp_conn]->is_reading = 0;
    set->tcp_conn[xfrd->tcp_conn]->total_bytes = 0;
    set->tcp_conn[xfrd->tcp_conn]->msglen = 0;
    if (xfrd->master->family == AF_INET6) {
        family = PF_INET6;
    } else {
        family = PF_INET;
    }
    fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    set->tcp_conn[xfrd->tcp_conn]->fd = fd;
    if (fd == -1) {
        ods_log_error("[%s] zone %s cannot create tcp socket to %s: %s",
            xfrd_str, zone->name, xfrd->master->address, strerror(errno));
        xfrd_set_timer_now(xfrd);
        xfrd_tcp_release(xfrd, set);
        return 0;
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        ods_log_error("[%s] zone %s cannot fcntl tcp socket to %s: %s",
            xfrd_str, zone->name, xfrd->master->address, strerror(errno));
        xfrd_set_timer_now(xfrd);
        xfrd_tcp_release(xfrd, set);
        return 0;
    }
    to_len = xfrd_acl_sockaddr_to(xfrd->master, &to);
    /* bind it? */

    conn = connect(fd, (struct sockaddr*)&to, to_len);
    if (conn == -1 && errno != EINPROGRESS) {
        ods_log_error("[%s] zone %s cannot connect tcp socket to %s: %s",
            xfrd_str, zone->name, xfrd->master->address, strerror(errno));
        xfrd_set_timer_now(xfrd);
        xfrd_tcp_release(xfrd, set);
        return 0;
    }
    xfrd->handler.fd = fd;
    xfrd->handler.event_types = NETIO_EVENT_WRITE|NETIO_EVENT_TIMEOUT;
    xfrd_set_timer(xfrd, xfrd_time(xfrd) + XFRD_TCP_TIMEOUT);
    return 1;
}


/**
 * Obtain tcp.
 *
 */
static void
xfrd_tcp_obtain(xfrd_type* xfrd, tcp_set_type* set)
{
    xfrhandler_type* xfrhandler;
    int i = 0;

    ods_log_assert(set);
    ods_log_assert(xfrd);
    ods_log_assert(xfrd->tcp_conn == -1);
    ods_log_assert(xfrd->tcp_waiting == 0);
    if (set->tcp_count < TCPSET_MAX) {
        ods_log_assert(!set->tcp_waiting_first);
        set->tcp_count ++;
        /* find a free tcp_buffer */
        for (i=0; i < TCPSET_MAX; i++) {
            if (set->tcp_conn[i]->fd == -1) {
                xfrd->tcp_conn = i;
                break;
            }
        }
        ods_log_assert(xfrd->tcp_conn != -1);
        xfrd->tcp_waiting = 0;
        /* stop udp use (if any) */
        if (xfrd->handler.fd != -1) {
            xfrd_udp_release(xfrd);
        }
        if (!xfrd_tcp_open(xfrd, set)) {
            return;
        }
        xfrd_tcp_xfr(xfrd, set);
        return;
    }
    /* wait, at end of line */
    ods_log_verbose("[%s] max number of tcp connections (%d) reached",
        xfrd_str, TCPSET_MAX);
    xfrd->tcp_waiting = 1;
    xfrd_unset_timer(xfrd);

    /* add it to the waiting queue */
    xfrhandler = (xfrhandler_type*) xfrd->xfrhandler;
    xfrd->tcp_waiting_next = xfrhandler->tcp_waiting_first;
    xfrhandler->tcp_waiting_first = xfrd;
}


/**
 * Start xfr.
 *
 */
static void
xfrd_tcp_xfr(xfrd_type* xfrd, tcp_set_type* set)
{
    tcp_conn_type* tcp = NULL;
    zone_type* zone = NULL;

    ods_log_assert(set);
    ods_log_assert(xfrd);
    zone = (zone_type*) xfrd->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(xfrd->tcp_conn != -1);
    ods_log_assert(xfrd->tcp_waiting == 0);
    ods_log_assert(xfrd->master);
    ods_log_assert(xfrd->master->address);
    /* start AXFR or IXFR for the zone */
    tcp = set->tcp_conn[xfrd->tcp_conn];

    if (xfrd->msg_do_retransfer || xfrd->serial_xfr_acquired <= 0 ||
        xfrd->master->ixfr_disabled) {
        ods_log_info("[%s] zone %s request axfr to %s", xfrd_str,
            zone->name, xfrd->master->address);
        buffer_pkt_query(tcp->packet, zone->apex, LDNS_RR_TYPE_AXFR,
            zone->klass);
    } else {
        ods_log_info("[%s] zone %s request tcp/ixfr=%u to %s", xfrd_str,
            zone->name, xfrd->soa.serial, xfrd->master->address);
        buffer_pkt_query(tcp->packet, zone->apex, LDNS_RR_TYPE_IXFR,
            zone->klass);
        buffer_pkt_set_nscount(tcp->packet, 1);
        xfrd_write_soa(xfrd, tcp->packet);
    }
    /* make packet */
    xfrd->query_id = buffer_pkt_id(tcp->packet);
    xfrd->msg_seq_nr = 0;
    xfrd->msg_rr_count = 0;
    xfrd->msg_old_serial = 0;
    xfrd->msg_new_serial = 0;
    xfrd->msg_is_ixfr = 0;
    xfrd_tsig_sign(xfrd, tcp->packet);
    buffer_flip(tcp->packet);
    tcp->msglen = buffer_limit(tcp->packet);
    ods_log_verbose("[%s] zone %s sending tcp query id=%d", xfrd_str,
        zone->name, xfrd->query_id);
    /* wait for select to complete connect before write */
    return;
}


/**
 * Read from tcp.
 *
 */
static void
xfrd_tcp_read(xfrd_type* xfrd, tcp_set_type* set)
{
    tcp_conn_type* tcp = NULL;
    int ret = 0;

    ods_log_assert(set);
    ods_log_assert(xfrd);
    ods_log_assert(xfrd->tcp_conn != -1);
    tcp = set->tcp_conn[xfrd->tcp_conn];
    ret = tcp_conn_read(tcp);
    if (ret == -1) {
        xfrd_set_timer_now(xfrd);
        xfrd_tcp_release(xfrd, set);
        return;
    }
    if (ret == 0) {
        return;
    }
    /* completed msg */
    buffer_flip(tcp->packet);
    ret = xfrd_handle_packet(xfrd, tcp->packet);
    switch (ret) {
        case XFRD_PKT_MORE:
            tcp_conn_ready(tcp);
            break;
        case XFRD_PKT_XFR:
        case XFRD_PKT_NEWLEASE:
            ods_log_verbose("[%s] tcp read %s: release connection", xfrd_str,
                XFRD_PKT_XFR?"xfr":"newlease");
            xfrd_tcp_release(xfrd, set);
            ods_log_assert(xfrd->round_num == -1);
            break;
        case XFRD_PKT_NOTIMPL:
            xfrd->master->ixfr_disabled = time_now();
            ods_log_verbose("[%s] disable ixfr requests for %s from now (%u)",
                xfrd_str, xfrd->master->address, xfrd->master->ixfr_disabled);
            /* break; */
        case XFRD_PKT_BAD:
        default:
            ods_log_debug("[%s] tcp read %s: release connection", xfrd_str,
                ret==XFRD_PKT_BAD?"bad":"notimpl");
            xfrd_tcp_release(xfrd, set);
            xfrd_make_request(xfrd);
            break;
    }
    return;
}


/**
 * Release tcp.
 *
 */
static void
xfrd_tcp_release(xfrd_type* xfrd, tcp_set_type* set)
{
    xfrhandler_type* xfrhandler;
    int conn = 0;
    zone_type* zone = NULL;

    ods_log_assert(set);
    ods_log_assert(xfrd);
    ods_log_assert(xfrd->master);
    ods_log_assert(xfrd->master->address);
    ods_log_assert(xfrd->tcp_conn != -1);
    ods_log_assert(xfrd->tcp_waiting == 0);
    zone = (zone_type*) xfrd->zone;
    ods_log_debug("[%s] zone %s release tcp connection to %s", xfrd_str,
        zone->name, xfrd->master->address);
    conn = xfrd->tcp_conn;
    xfrd->tcp_conn = -1;
    xfrd->tcp_waiting = 0;
    xfrd->handler.fd = -1;
    xfrd->handler.event_types = NETIO_EVENT_READ|NETIO_EVENT_TIMEOUT;

    if (set->tcp_conn[conn]->fd != -1) {
        close(set->tcp_conn[conn]->fd);
    }
    set->tcp_conn[conn]->fd = -1;
    set->tcp_count --;
    /* now see if there are any waiting connections */
    xfrhandler = (xfrhandler_type*) xfrd->xfrhandler;
    while (xfrhandler->tcp_waiting_first) {
        int i;
        xfrd_type* waiting_xfrd = xfrhandler->tcp_waiting_first;
        xfrhandler->tcp_waiting_first = waiting_xfrd->tcp_waiting_next;
        waiting_xfrd->tcp_waiting_next = NULL;

        set->tcp_count ++;
        /* find a free tcp_buffer */
        for (i=0; i < TCPSET_MAX; i++) {
            if (set->tcp_conn[i]->fd == -1) {
                waiting_xfrd->tcp_conn = i;
                break;
            }
        }
        waiting_xfrd->tcp_waiting = 0;
        /* stop udp use (if any) */
        if (waiting_xfrd->handler.fd != -1) {
            xfrd_udp_release(waiting_xfrd);
        }
        if (!xfrd_tcp_open(waiting_xfrd, set)) {
            return;
        }
        xfrd_tcp_xfr(waiting_xfrd, set);

        if (set->tcp_count >= TCPSET_MAX) break;
    }
}


/** UDP **/


/**
 * Send packet over udp.
 *
 */
static int
xfrd_udp_send(xfrd_type* xfrd, buffer_type* buffer)
{
    struct sockaddr_storage to;
    socklen_t to_len = 0;
    int fd = -1;
    int family = PF_INET;
    ssize_t nb = -1;
    ods_log_assert(buffer);
    ods_log_assert(xfrd);
    ods_log_assert(xfrd->master);
    ods_log_assert(xfrd->master->address);
    /* this will set the remote port to acl->port or TCP_PORT */
    to_len = xfrd_acl_sockaddr_to(xfrd->master, &to);
    /* get the address family of the remote host */
    if (xfrd->master->family == AF_INET6) {
        family = PF_INET6;
    }
    /* create socket */
    fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        ods_log_error("[%s] unable to send data over udp to %s: "
            "socket() failed (%s)", xfrd_str, xfrd->master->address,
            strerror(errno));
        return -1;
    }
    /* bind it? */

    /* send it (udp) */
    ods_log_deeebug("[%s] send %d bytes over udp to %s", xfrd_str,
        buffer_remaining(buffer), xfrd->master->address);
    nb = sendto(fd, buffer_current(buffer), buffer_remaining(buffer), 0,
        (struct sockaddr*)&to, to_len);
    if (nb == -1) {
        ods_log_error("[%s] unable to send data over udp to %s: "
            "sendto() failed (%s)", xfrd_str, xfrd->master->address,
            strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}


/**
 * Send IXFR request.
 *
 */
static int
xfrd_udp_send_request_ixfr(xfrd_type* xfrd)
{
    int fd;
    xfrhandler_type* xfrhandler = NULL;
    zone_type* zone = NULL;
    ods_log_assert(xfrd);
    ods_log_assert(xfrd->master);
    ods_log_assert(xfrd->master->address);
    zone = (zone_type*) xfrd->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    if (xfrd->tcp_conn != -1) {
        /* tcp is using the handler.fd */
        ods_log_error("[%s] unable to transfer zone %s: tried to send "
            "udp while tcp obtained", xfrd_str, zone->name);
        return -1;
    }
    /* make packet */
    xfrhandler = (xfrhandler_type*) xfrd->xfrhandler;
    ods_log_assert(xfrhandler);
    buffer_pkt_query(xfrhandler->packet, zone->apex, LDNS_RR_TYPE_IXFR,
        zone->klass);
    xfrd->query_id = buffer_pkt_id(xfrhandler->packet);
    xfrd->msg_seq_nr = 0;
    xfrd->msg_rr_count = 0;
    xfrd->msg_old_serial = 0;
    xfrd->msg_new_serial = 0;
    xfrd->msg_is_ixfr = 0;
    buffer_pkt_set_nscount(xfrhandler->packet, 1);
    xfrd_write_soa(xfrd, xfrhandler->packet);
    xfrd_tsig_sign(xfrd, xfrhandler->packet);
    buffer_flip(xfrhandler->packet);
    xfrd_set_timer(xfrd, xfrd_time(xfrd) + XFRD_UDP_TIMEOUT);
    ods_log_info("[%s] zone %s request udp/ixfr=%u to %s", xfrd_str,
        zone->name, xfrd->soa.serial, xfrd->master->address);
    if((fd = xfrd_udp_send(xfrd, xfrhandler->packet)) == -1) {
        return -1;
    }
    return fd;
}

/**
 * Obtain udp.
 *
 */
static void
xfrd_udp_obtain(xfrd_type* xfrd)
{
    xfrhandler_type* xfrhandler = NULL;
    ods_log_assert(xfrd);
    ods_log_assert(xfrd->xfrhandler);
    ods_log_assert(xfrd->udp_waiting == 0);
    xfrhandler = (void*) xfrd->xfrhandler;
    if (xfrd->tcp_conn != -1) {
        /* no tcp and udp at the same time */
        xfrd_tcp_release(xfrd, xfrhandler->tcp_set);
    }
    if (xfrhandler->udp_use_num < XFRD_MAX_UDP) {
            xfrhandler->udp_use_num++;
            xfrd->handler.fd = xfrd_udp_send_request_ixfr(xfrd);
            if (xfrd->handler.fd == -1) {
                    xfrhandler->udp_use_num--;
            }
            return;
    }
    /* queue the zone as last */
    xfrd->udp_waiting = 1;
    xfrd->udp_waiting_next = NULL;
    if (!xfrhandler->udp_waiting_first) {
        xfrhandler->udp_waiting_first = xfrd;
    }
    if (xfrhandler->udp_waiting_last) {
        xfrhandler->udp_waiting_last->udp_waiting_next = xfrd;
    }
    xfrhandler->udp_waiting_last = xfrd;
    xfrd_unset_timer(xfrd);
    return;
}


/**
 * Read packet from udp.
 *
 */
static int
xfrd_udp_read_packet(xfrd_type* xfrd)
{
    xfrhandler_type* xfrhandler = NULL;
    ssize_t received = 0;
    ods_log_assert(xfrd);
    xfrhandler = (xfrhandler_type*) xfrd->xfrhandler;
    ods_log_assert(xfrhandler);
    /* read the data */
    buffer_clear(xfrhandler->packet);
    received = recvfrom(xfrd->handler.fd, buffer_begin(xfrhandler->packet),
        buffer_remaining(xfrhandler->packet), 0, NULL, NULL);
    if (received == -1) {
        ods_log_error("[%s] unable to read packet: recvfrom() failed fd %d "
            "(%s)", xfrd_str, xfrd->handler.fd, strerror(errno));
        return 0;
    }
    buffer_set_limit(xfrhandler->packet, received);
    return 1;
}


/**
 * Read from udp.
 *
 */
static void
xfrd_udp_read(xfrd_type* xfrd)
{
    xfrhandler_type* xfrhandler = NULL;
    zone_type* zone = NULL;
    xfrd_pkt_status res = XFRD_PKT_BAD;
    ods_log_assert(xfrd);
    zone = (zone_type*) xfrd->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_debug("[%s] zone %s read data from udp", xfrd_str,
        zone->name);
    if (!xfrd_udp_read_packet(xfrd)) {
        ods_log_error("[%s] unable to read data from udp zone %s: "
            "xfrd_udp_read_packet() failed", xfrd_str, zone->name);
        xfrd_udp_release(xfrd);
        return;
    }
    xfrhandler = (xfrhandler_type*) xfrd->xfrhandler;
    ods_log_assert(xfrhandler);
    res = xfrd_handle_packet(xfrd, xfrhandler->packet);
    switch (res) {
        case XFRD_PKT_TC:
            ods_log_verbose("[%s] truncation from %s",
                xfrd_str, xfrd->master->address);
            xfrd_udp_release(xfrd);
            xfrd_set_timer(xfrd, xfrd_time(xfrd) + XFRD_TCP_TIMEOUT);
            xfrd_tcp_obtain(xfrd, xfrhandler->tcp_set);
            break;
        case XFRD_PKT_XFR:
        case XFRD_PKT_NEWLEASE:
            ods_log_verbose("[%s] xfr/newlease from %s",
                xfrd_str, xfrd->master->address);
            /* nothing more to do */
            ods_log_assert(xfrd->round_num == -1);
            xfrd_udp_release(xfrd);
            break;
        case XFRD_PKT_NOTIMPL:
            xfrd->master->ixfr_disabled = time_now();
            ods_log_verbose("[%s] disable ixfr requests for %s from now (%u)",
                xfrd_str, xfrd->master->address, xfrd->master->ixfr_disabled);
            /* break; */
        case XFRD_PKT_BAD:
        default:
            ods_log_debug("[%s] bad ixfr packet from %s",
                xfrd_str, xfrd->master->address);
            xfrd_udp_release(xfrd);
            xfrd_make_request(xfrd);
            break;
    }
    return;
}


/**
 * Release udp.
 *
 */
static void
xfrd_udp_release(xfrd_type* xfrd)
{
    xfrhandler_type* xfrhandler = NULL;

    ods_log_assert(xfrd);
    ods_log_assert(xfrd->udp_waiting == 0);
    if(xfrd->handler.fd != -1)
        close(xfrd->handler.fd);
    xfrd->handler.fd = -1;
    xfrhandler = (xfrhandler_type*) xfrd->xfrhandler;
    ods_log_assert(xfrhandler);
    /* see if there are waiting zones */
    if (xfrhandler->udp_use_num == XFRD_MAX_UDP) {
        while (xfrhandler->udp_waiting_first) {
            /* snip off waiting list */
            xfrd_type* wf = xfrhandler->udp_waiting_first;
            ods_log_assert(wf->udp_waiting);
            wf->udp_waiting = 0;
            xfrhandler->udp_waiting_first = wf->udp_waiting_next;
            if (xfrhandler->udp_waiting_last == wf) {
                xfrhandler->udp_waiting_last = NULL;
            }
            /* see if this zone needs udp connection */
            if (wf->tcp_conn == -1) {
                wf->handler.fd = xfrd_udp_send_request_ixfr(wf);
                if (wf->handler.fd != -1) {
                    return;
                }
            }
        }
    }
    /* no waiting zones */
    if (xfrhandler->udp_use_num > 0) {
        xfrhandler->udp_use_num --;
    }
    return;
}


/**
 * Make a zone transfer request.
 *
 */
static void
xfrd_make_request(xfrd_type* xfrd)
{
    zone_type* zone = NULL;
    dnsin_type* dnsin = NULL;
    if (!xfrd || !xfrd->xfrhandler) {
        return;
    }
    zone = (zone_type*) xfrd->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->adinbound);
    ods_log_assert(zone->adinbound->type == ADAPTER_DNS);
    ods_log_assert(zone->adinbound->config);

    dnsin = (dnsin_type*) zone->adinbound->config;
    if (xfrd->next_master != -1) {
        /* we are told to use this next master */
        xfrd->master_num = xfrd->next_master;
        xfrd->master = NULL; /* acl_find_num(...) */
        /* if there is no next master, fallback to use the first one */
        if (!xfrd->master) {
            xfrd->master = dnsin->request_xfr;
            xfrd->master_num = 0;
        }
        /* fallback to cycle master */
        xfrd->next_master = -1;
        xfrd->round_num = 0; /* fresh set of retries after notify */
    } else {
        /* cycle master */
        if (xfrd->round_num != -1 && xfrd->master &&
            xfrd->master->next) {
            /* try the next master */
            xfrd->master = xfrd->master->next;
            xfrd->master_num++;
        } else {
            /* start a new round */
            xfrd->master = dnsin->request_xfr;
            xfrd->master_num = 0;
            xfrd->round_num++;
        }
        if (xfrd->round_num >= XFRD_MAX_ROUNDS) {
            /* tried all servers that many times, wait */
            xfrd->round_num = -1;
            xfrd_set_timer_retry(xfrd);
            ods_log_verbose("[%s] zone %s make request wait retry",
                xfrd_str, zone->name);
            return;
        }
    }
    if (!xfrd->master) {
        ods_log_debug("[%s] unable to make request for zone %s: no master",
            xfrd_str, zone->name);
        xfrd->round_num = -1;
        xfrd_set_timer_retry(xfrd);
        return;
    }
    /* cache ixfr_disabled only for XFRD_NO_IXFR_CACHE time */
    if (xfrd->master->ixfr_disabled &&
        (xfrd->master->ixfr_disabled + XFRD_NO_IXFR_CACHE) <=
         xfrd_time(xfrd)) {
        ods_log_verbose("[%s] clear negative caching ixfr disabled for "
            "master %s", xfrd_str, xfrd->master->address);
        ods_log_debug("[%s] clear negative caching calc: %u + %u <= %u",
            xfrd_str, xfrd->master->ixfr_disabled, XFRD_NO_IXFR_CACHE,
            xfrd_time(xfrd));
        xfrd->master->ixfr_disabled = 0;
    }
    /* perform xfr request */
    if (xfrd->serial_xfr_acquired && !xfrd->master->ixfr_disabled &&
        !xfrd->serial_retransfer) {
        xfrd_set_timer(xfrd, xfrd_time(xfrd) + XFRD_UDP_TIMEOUT);

        ods_log_verbose("[%s] zone %s make request [udp round %d master %s:%u]",
            xfrd_str, zone->name, xfrd->round_num, xfrd->master->address,
	    xfrd->master->port);
        xfrd_udp_obtain(xfrd);
    } else if (!xfrd->serial_xfr_acquired || xfrd->master->ixfr_disabled ||
        xfrd->serial_retransfer) {
        xfrhandler_type* xfrhandler = (xfrhandler_type*) xfrd->xfrhandler;
        ods_log_assert(xfrhandler);
        if (xfrd->serial_retransfer) {
            xfrd->msg_do_retransfer = 1;
            xfrd->serial_retransfer = 0;
        }
        xfrd_set_timer(xfrd, xfrd_time(xfrd) + XFRD_TCP_TIMEOUT);

        ods_log_verbose("[%s] zone %s make request [tcp round %d master %s:%u]",
            xfrd_str, zone->name, xfrd->round_num, xfrd->master->address,
	    xfrd->master->port);
        xfrd_tcp_obtain(xfrd, xfrhandler->tcp_set);
    }
    return;
}


/**
 * Handle zone transfer.
 *
 */
static void
xfrd_handle_zone(netio_type* ATTR_UNUSED(netio),
    netio_handler_type* handler, netio_events_type event_types)
{
    xfrd_type* xfrd = NULL;
    zone_type* zone = NULL;

    if (!handler) {
        return;
    }
    xfrd = (xfrd_type*) handler->user_data;
    ods_log_assert(xfrd);
    zone = (zone_type*) xfrd->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->name);

    if (xfrd->tcp_conn != -1) {
        /* busy in tcp transaction */
        xfrhandler_type* xfrhandler = (xfrhandler_type*) xfrd->xfrhandler;
        ods_log_assert(xfrhandler);
        if (event_types & NETIO_EVENT_READ) {
           ods_log_deeebug("[%s] zone %s event tcp read", xfrd_str, zone->name);
           xfrd_set_timer(xfrd, xfrd_time(xfrd) + XFRD_TCP_TIMEOUT);
           xfrd_tcp_read(xfrd, xfrhandler->tcp_set);
           return;
        } else if (event_types & NETIO_EVENT_WRITE) {
           ods_log_deeebug("[%s] zone %s event tcp write", xfrd_str,
               zone->name);
           xfrd_set_timer(xfrd, xfrd_time(xfrd) + XFRD_TCP_TIMEOUT);
           xfrd_tcp_write(xfrd, xfrhandler->tcp_set);
           return;
        } else if (event_types & NETIO_EVENT_TIMEOUT) {
           /* tcp connection timed out. Stop it. */
           ods_log_deeebug("[%s] zone %s event tcp timeout", xfrd_str,
               zone->name);
           xfrd_tcp_release(xfrd, xfrhandler->tcp_set);
           /* continue to retry; as if a timeout happened */
           event_types = NETIO_EVENT_TIMEOUT;
        }
    }

    if (event_types & NETIO_EVENT_READ) {
        /* busy in udp transaction */
        ods_log_deeebug("[%s] zone %s event udp read", xfrd_str,
            zone->name);
        xfrd_set_timer_now(xfrd);
        xfrd_udp_read(xfrd);
        return;
    }

    /* timeout */
    ods_log_deeebug("[%s] zone %s timeout", xfrd_str, zone->name);
    if (handler->fd != -1) {
        ods_log_assert(xfrd->tcp_conn == -1);
        xfrd_udp_release(xfrd);
    }
    if (xfrd->tcp_waiting) {
        ods_log_deeebug("[%s] zone %s skips retry: tcp connections full",
            xfrd_str, zone->name);
        xfrd_unset_timer(xfrd);
        return;
    }
    if (xfrd->udp_waiting) {
        ods_log_deeebug("[%s] zone %s skips retry: udp connections full",
            xfrd_str, zone->name);
        xfrd_unset_timer(xfrd);
        return;
    }
    /* make a new request */
    xfrd_make_request(xfrd);
    return;
}


/**
 * Backup xfrd domain names.
 *
 */
static void
xfrd_backup_dname(FILE* out, uint8_t* dname)
{
    uint8_t* d= dname+1;
    uint8_t len = *d++;
    uint8_t i;
    if (dname[0]<=1) {
        fprintf(out, ".");
        return;
    }
    while (len) {
        ods_log_assert(d - (dname+1) <= dname[0]);
        for (i=0; i<len; i++) {
            uint8_t ch = *d++;
            if (isalnum(ch) || ch == '-' || ch == '_') {
                fprintf(out, "%c", ch);
            } else if (ch == '.' || ch == '\\') {
                fprintf(out, "\\%c", ch);
            } else {
                fprintf(out, "\\%03u", (unsigned int)ch);
            }
        }
        fprintf(out, ".");
        len = *d++;
    }
    return;
}


/**
 * Backup xfrd variables.
 *
 */
static void
xfrd_backup(xfrd_type* xfrd)
{
    zone_type* zone = (zone_type*) xfrd->zone;
    char* file = NULL;
    int timeout = 0;
    FILE* fd = NULL;
    if (zone && zone->name) {
        file = ods_build_path(zone->name, ".xfrd-state", 0, 1);
        if (file) {
            fd = ods_fopen(file, NULL, "w");
            if (fd) {
                if (xfrd->handler.timeout) {
                    timeout = xfrd->timeout.tv_sec;
                }
                fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC_V3);
                fprintf(fd, ";;Zone: name %s ttl %u mname ",
                    zone->name,
                    (unsigned) xfrd->soa.ttl);
                xfrd_backup_dname(fd, xfrd->soa.mname),
                fprintf(fd, " rname ");
                xfrd_backup_dname(fd, xfrd->soa.rname),
                fprintf(fd, " serial %u refresh %u retry %u expire %u "
                    "minimum %u\n",
                    (unsigned) xfrd->soa.serial,
                    (unsigned) xfrd->soa.refresh,
                    (unsigned) xfrd->soa.retry,
                    (unsigned) xfrd->soa.expire,
                    (unsigned) xfrd->soa.minimum);
                fprintf(fd, ";;Master: num %d next %d round %d timeout %d\n",
                    xfrd->master_num,
                    xfrd->next_master,
                    xfrd->round_num,
                    timeout);
                fprintf(fd, ";;Serial: xfr %u %u notify %u %u disk %u %u\n",
                    (unsigned) xfrd->serial_xfr,
                    (unsigned) xfrd->serial_xfr_acquired,
                    (unsigned) xfrd->serial_notify,
                    (unsigned) xfrd->serial_notify_acquired,
                    (unsigned) xfrd->serial_disk,
                    (unsigned) xfrd->serial_disk_acquired);
                fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC_V3);
                ods_fclose(fd);
            }
            free(file);
        }
    }
    return;
}


/**
 * Unlink xfrd file.
 *
 */
static void
xfrd_unlink(xfrd_type* xfrd)
{
    zone_type* zone = (zone_type*) xfrd->zone;
    char* file = NULL;
    if (zone && zone->name) {
        ods_log_info("[%s] unlink zone %s xfrd state", xfrd_str, zone->name);
        file = ods_build_path(zone->name, ".xfrd-state", 0, 1);
        if (file) {
            (void)unlink(file);
            free(file);
        }
    }
    return;
}


/**
 * Cleanup zone transfer structure.
 *
 */
void
xfrd_cleanup(xfrd_type* xfrd, int backup)
{
    allocator_type* allocator = NULL;
    lock_basic_type serial_lock;
    lock_basic_type rw_lock;
    if (!xfrd) {
        return;
    }
    /* backup */
    if (backup) {
        xfrd_backup(xfrd);
    } else {
        xfrd_unlink(xfrd);
    }

    allocator = xfrd->allocator;
    serial_lock = xfrd->serial_lock;
    rw_lock = xfrd->rw_lock;
    tsig_rr_cleanup(xfrd->tsig_rr);
    allocator_deallocate(allocator, (void*) xfrd);
    allocator_cleanup(allocator);
    lock_basic_destroy(&serial_lock);
    lock_basic_destroy(&rw_lock);
    return;
}
