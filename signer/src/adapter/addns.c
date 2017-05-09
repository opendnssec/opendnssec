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
 * DNS Adapters.
 *
 */

#include "config.h"
#include "adapter/adapi.h"
#include "adapter/adapter.h"
#include "adapter/addns.h"
#include "adapter/adutil.h"
#include "parser/addnsparser.h"
#include "parser/confparser.h"
#include "duration.h"
#include "file.h"
#include "log.h"
#include "status.h"
#include "util.h"
#include "signer/zone.h"
#include "wire/notify.h"
#include "wire/xfrd.h"

#include <ldns/ldns.h>
#include <stdio.h>
#include <stdlib.h>

static const char* adapter_str = "adapter";
static ods_status addns_read_pkt(FILE* fd, zone_type* zone);
static ods_status addns_read_file(FILE* fd, zone_type* zone);


/**
 * Read the next RR from zone file.
 *
 */
ldns_rr*
addns_read_rr(FILE* fd, char* line, ldns_rdf** orig, ldns_rdf** prev,
    uint32_t* ttl, ldns_status* status, unsigned int* l)
{
    ldns_rr* rr = NULL;
    int len = 0;
    uint32_t new_ttl = 0;

addns_read_line:
    if (ttl) {
        new_ttl = *ttl;
    }
    len = adutil_readline_frm_file(fd, line, l, 1);
    adutil_rtrim_line(line, &len);
    if (len >= 0) {
        switch (line[0]) {
            /* no directives */

            /* comments, empty lines */
            case ';':
            case '\n':
                if (ods_strcmp(";;ENDPACKET", line) == 0) {
                    /* end of pkt */
                    *status = LDNS_STATUS_OK;
                    return NULL;
                }
                if (ods_strcmp(";;BEGINPACKET", line) == 0) {
                    /* begin packet but previous not ended, rollback */
                    *status = LDNS_STATUS_OK;
                    return NULL;
                }
                goto addns_read_line; /* perhaps next line is rr */
                break;
            /* let's hope its a RR */
            default:
                if (adutil_whitespace_line(line, len)) {
                    goto addns_read_line; /* perhaps next line is rr */
                    break;
                }
                *status = ldns_rr_new_frm_str(&rr, line, new_ttl, *orig, prev);
                if (*status == LDNS_STATUS_OK) {
                    return rr;
                } else if (*status == LDNS_STATUS_SYNTAX_EMPTY) {
                    if (rr) {
                        ldns_rr_free(rr);
                        rr = NULL;
                    }
                    *status = LDNS_STATUS_OK;
                    goto addns_read_line; /* perhaps next line is rr */
                    break;
                } else {
                    ods_log_error("[%s] error parsing RR at line %i (%s): %s",
                        adapter_str, l&&*l?*l:0,
                        ldns_get_errorstr_by_id(*status), line);
                    while (len >= 0) {
                        len = adutil_readline_frm_file(fd, line, l, 0);
                    }
                    if (rr) {
                        ldns_rr_free(rr);
                        rr = NULL;
                    }
                    return NULL;
                }
                break;
        }
    }
    /* -1, EOF */
    *status = LDNS_STATUS_OK;
    return NULL;
}


/**
 * Read pkt from file.
 *
 */
static ods_status
addns_read_pkt(FILE* fd, zone_type* zone)
{
    ldns_rr* rr = NULL;
    long startpos = 0;
    long fpos = 0;
    int len = 0;
    uint32_t new_serial = 0;
    uint32_t old_serial = 0;
    uint32_t tmp_serial = 0;
    ldns_rdf* prev = NULL;
    ldns_rdf* orig = NULL;
    ldns_rdf* dname = NULL;
    uint32_t ttl = 0;
    size_t rr_count = 0;
    ods_status result = ODS_STATUS_OK;
    ldns_status status = LDNS_STATUS_OK;
    char line[SE_ADFILE_MAXLINE];
    unsigned is_axfr = 0;
    unsigned del_mode = 0;
    unsigned soa_seen = 0;
    unsigned line_update_interval = 100000;
    unsigned line_update = line_update_interval;
    unsigned l = 0;
    char* xfrd;
    char* fin;
    char* fout;

    ods_log_assert(fd);
    ods_log_assert(zone);
    ods_log_assert(zone->name);


    fpos = ftell(fd);
    len = adutil_readline_frm_file(fd, line, &l, 1);
    if (len < 0) {
        /* -1 EOF */
        return ODS_STATUS_EOF;
    }
    adutil_rtrim_line(line, &len);
    if (ods_strcmp(";;BEGINPACKET", line) != 0) {
        ods_log_error("[%s] bogus xfrd file zone %s, missing ;;BEGINPACKET (was %s)",
            adapter_str, zone->name, line);
        return ODS_STATUS_ERR;
    }
    startpos = fpos;
    fpos = ftell(fd);

begin_pkt:
    rr_count = 0;
    is_axfr = 0;
    del_mode = 0;
    soa_seen = 0;
    /* $ORIGIN <zone name> */
    dname = adapi_get_origin(zone);
    if (!dname) {
        ods_log_error("[%s] error getting default value for $ORIGIN",
            adapter_str);
        return ODS_STATUS_ERR;
    }
    orig = ldns_rdf_clone(dname);
    if (!orig) {
        ods_log_error("[%s] error setting default value for $ORIGIN",
            adapter_str);
        return ODS_STATUS_ERR;
    }
    /* $TTL <default ttl> */
    ttl = adapi_get_ttl(zone);

    /* read RRs */
    while ((rr = addns_read_rr(fd, line, &orig, &prev, &ttl, &status, &l))
        != NULL) {
        /* update file position */
        fpos = ftell(fd);
        /* check status */
        if (status != LDNS_STATUS_OK) {
            ods_log_error("[%s] error reading RR at line %i (%s): %s",
                adapter_str, l, ldns_get_errorstr_by_id(status), line);
            result = ODS_STATUS_ERR;
            break;
        }
        /* debug update */
        if (l > line_update) {
            ods_log_debug("[%s] ...at line %i: %s", adapter_str, l, line);
            line_update += line_update_interval;
        }
        /* first RR: check if SOA and correct zone & serialno */
        if (rr_count == 0) {
            rr_count++;
            if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA) {
                ods_log_error("[%s] bad xfr, first rr is not soa",
                    adapter_str);
                ldns_rr_free(rr);
                rr = NULL;
                result = ODS_STATUS_ERR;
                break;
            }
            soa_seen++;
            if (ldns_dname_compare(ldns_rr_owner(rr), zone->apex)) {
                ods_log_error("[%s] bad xfr, soa dname not equal to zone "
                    "dname %s", adapter_str, zone->name);
                ldns_rr_free(rr);
                rr = NULL;
                result = ODS_STATUS_ERR;
                break;
            }

            tmp_serial =
                ldns_rdf2native_int32(ldns_rr_rdf(rr, SE_SOA_RDATA_SERIAL));
            old_serial = adapi_get_serial(zone);

/**
 * Do we need to make this check? It is already done by xfrd.
 * By not doing this check, retransfers will be taken into account.
 *

            if (!util_serial_gt(tmp_serial, old_serial) &&
                zone->db->is_initialized) {
                ods_log_info("[%s] zone %s is already up to date, have "
                    "serial %u, got serial %u", adapter_str, zone->name,
                    old_serial, tmp_serial);
                new_serial = tmp_serial;
                ldns_rr_free(rr);
                rr = NULL;
                result = ODS_STATUS_UPTODATE;
                while (len >= 0) {
                    len = adutil_readline_frm_file(fd, line, &l, 1);
                    if (len && ods_strcmp(";;ENDPACKET", line) == 0) {
                        startpos = 0;
                        break;
                    }
                }
                break;
            }

 *
 **/

            ldns_rr_free(rr);
            rr = NULL;
            result = ODS_STATUS_OK;
            continue;
        }
        /* second RR: if not soa, this is an AXFR */
        if (rr_count == 1) {
            if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA) {
                ods_log_verbose("[%s] detected axfr serial=%u for zone %s",
                    adapter_str, tmp_serial, zone->name);
                new_serial = tmp_serial;
                is_axfr = 1;
                del_mode = 0;
            } else {
                ods_log_verbose("[%s] detected ixfr serial=%u for zone %s",
                    adapter_str, tmp_serial, zone->name);

                if (!util_serial_gt(tmp_serial, old_serial) &&
                    zone->db->is_initialized) {
                    ods_log_error("[%s] bad ixfr for zone %s, bad start serial %lu",
                        adapter_str, zone->name, (unsigned long)tmp_serial);
                    result = ODS_STATUS_ERR;
                }

                new_serial = tmp_serial;
                tmp_serial =
                  ldns_rdf2native_int32(ldns_rr_rdf(rr, SE_SOA_RDATA_SERIAL));
                ldns_rr_free(rr);
                rr = NULL;
                rr_count++;
                if (tmp_serial < new_serial) {
                    del_mode = 1;
                    result = ODS_STATUS_OK;
                    continue;
                } else {
                    ods_log_error("[%s] bad ixfr for zone %s, bad soa serial %lu",
                        adapter_str, zone->name, (unsigned long) tmp_serial);
                    result = ODS_STATUS_ERR;
                    break;
                }
            }
        }
        /* soa means swap */
        rr_count++;
        if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_SOA) {
            if (!is_axfr) {
                tmp_serial =
                  ldns_rdf2native_int32(ldns_rr_rdf(rr, SE_SOA_RDATA_SERIAL));
                if (tmp_serial <= new_serial) {
                    if (tmp_serial == new_serial) {
                        soa_seen++;
                    }
                    del_mode = !del_mode;
                    ldns_rr_free(rr);
                    rr = NULL;
                    result = ODS_STATUS_OK;
                    continue;
                } else {
                    ods_log_assert(tmp_serial > new_serial);
                    ods_log_error("[%s] bad xfr for zone %s, bad soa serial",
                        adapter_str, zone->name);
                    ldns_rr_free(rr);
                    rr = NULL;
                    result = ODS_STATUS_ERR;
                    break;
                }
            } else {
               /* for axfr */
               soa_seen++;
            }
        }
        /* [add to/remove from] the zone */
        if (!is_axfr && del_mode) {
            ods_log_deeebug("[%s] delete RR #%lu at line %i: %s",
                adapter_str, (unsigned long)rr_count, l, line);
            result = adapi_del_rr(zone, rr, 0);
            ldns_rr_free(rr);
            rr = NULL;
        } else {
            ods_log_deeebug("[%s] add RR #%lu at line %i: %s",
                adapter_str, (unsigned long)rr_count, l, line);
            result = adapi_add_rr(zone, rr, 0);
        }
        if (result == ODS_STATUS_UNCHANGED) {
            ods_log_debug("[%s] skipping RR at line %i (%s): %s",
                adapter_str, l, del_mode?"not found":"duplicate", line);
            ldns_rr_free(rr);
            rr = NULL;
            result = ODS_STATUS_OK;
            continue;
        } else if (result != ODS_STATUS_OK) {
            ods_log_error("[%s] error %s RR at line %i: %s",
                adapter_str, del_mode?"deleting":"adding", l, line);
            ldns_rr_free(rr);
            rr = NULL;
            break;
        }
    }
    /* and done */
    if (orig) {
        ldns_rdf_deep_free(orig);
        orig = NULL;
    }
    if (prev) {
        ldns_rdf_deep_free(prev);
        prev = NULL;
    }
    /* check again */
    if (ods_strcmp(";;ENDPACKET", line) == 0) {
        ods_log_verbose("[%s] xfr zone %s on disk complete, commit to db",
            adapter_str, zone->name);
            startpos = 0;
    } else {
        ods_log_warning("[%s] xfr zone %s on disk incomplete, rollback",
            adapter_str, zone->name);
        namedb_rollback(zone, zone->db, 1);
        if (ods_strcmp(";;BEGINPACKET", line) == 0) {
            result = ODS_STATUS_OK;
            startpos = fpos;
            goto begin_pkt;
        } else {
            result = ODS_STATUS_XFRINCOMPLETE;
        }
    }
    /* otherwise EOF */
    if (result == ODS_STATUS_OK && status != LDNS_STATUS_OK) {
        ods_log_error("[%s] error reading RR at line %i (%s): %s",
            adapter_str, l, ldns_get_errorstr_by_id(status), line);
        result = ODS_STATUS_ERR;
    }
    /* check the number of SOAs seen */
    if (result == ODS_STATUS_OK) {
        if ((is_axfr && soa_seen != 2) || (!is_axfr && soa_seen != 3)) {
            ods_log_error("[%s] bad %s, wrong number of SOAs (%u)",
                adapter_str, is_axfr?"axfr":"ixfr", soa_seen);
            result = ODS_STATUS_ERR;
        }
    }
    /* input zone ok, set inbound serial and apply differences */
    if (result == ODS_STATUS_OK) {
        adapi_set_serial(zone, new_serial);
        if (is_axfr) {
            adapi_trans_full(zone, 1);
        } else {
            adapi_trans_diff(zone, 1);
        }
    }
    if (result == ODS_STATUS_UPTODATE) {
        /* do a transaction for DNSKEY and NSEC3PARAM */
        adapi_trans_diff(zone, 1);
        result = ODS_STATUS_OK;
    }
    if (result == ODS_STATUS_XFRINCOMPLETE) {
        /** we have to restore the incomplete zone transfer:
          * xfrd = (xfrd.tmp + startpos) . (xfrd)
          */
        xfrd = ods_build_path(zone->name, ".xfrd", 0, 1);
        fin = ods_build_path(zone->name, ".xfrd.tmp", 0, 1);
        fout = ods_build_path(zone->name, ".xfrd.bak", 0, 1);
        if (!xfrd || !fin || !fout) {
            return ODS_STATUS_MALLOC_ERR;
        }
        ods_log_debug("[%s] restore xfrd zone %s xfrd %s fin %s fout %s",
            adapter_str, zone->name, xfrd, fin, fout);
        result = ods_file_copy(fin, fout, startpos, 0);
        if (result != ODS_STATUS_OK) {
            ods_log_crit("[%s] unable to restore incomple xfr zone %s: %s",
                adapter_str, zone->name, ods_status2str(result));
        } else {
            pthread_mutex_lock(&zone->xfrd->rw_lock);
            if (ods_file_lastmodified(xfrd)) {
                result = ods_file_copy(xfrd, fout, 0, 1);
                if (result != ODS_STATUS_OK) {
                    ods_log_crit("[%s] unable to restore xfrd zone %s: %s",
                        adapter_str, zone->name, ods_status2str(result));
                } else if (rename(fout, xfrd) != 0) {
                    result = ODS_STATUS_RENAME_ERR;
                    ods_log_crit("[%s] unable to restore xfrd zone %s: %s",
                        adapter_str, zone->name, ods_status2str(result));
                }
            } else if (rename(fout, xfrd) != 0) {
                result = ODS_STATUS_RENAME_ERR;
                ods_log_crit("[%s] unable to restore xfrd zone %s: %s",
                    adapter_str, zone->name, ods_status2str(result));

            }
            pthread_mutex_unlock(&zone->xfrd->rw_lock);
        }
        free((void*) xfrd);
        free((void*) fin);
        free((void*) fout);
        result = ODS_STATUS_XFRINCOMPLETE;
    }
    return result;
}


/**
 * Read pkt from file.
 *
 */
static ods_status
addns_read_file(FILE* fd, zone_type* zone)
{
    ods_status status = ODS_STATUS_OK;

    while (status == ODS_STATUS_OK) {
        status = addns_read_pkt(fd, zone);
        if (status == ODS_STATUS_OK) {
            pthread_mutex_lock(&zone->xfrd->serial_lock);
            zone->xfrd->serial_xfr = adapi_get_serial(zone);
            zone->xfrd->serial_xfr_acquired = zone->xfrd->serial_disk_acquired;
            pthread_mutex_unlock(&zone->xfrd->serial_lock);
        }
    }
    if (status == ODS_STATUS_EOF) {
        status = ODS_STATUS_OK;
    }
    return status;
}


/**
 * Create DNS input adapter.
 *
 */
dnsin_type*
dnsin_create(void)
{
    dnsin_type* addns = NULL;
    CHECKALLOC(addns = (dnsin_type*) malloc(sizeof(dnsin_type)));
    addns->request_xfr = NULL;
    addns->allow_notify = NULL;
    addns->tsig = NULL;
    return addns;
}


/**
 * Create DNS output adapter.
 *
 */
dnsout_type*
dnsout_create(void)
{
    dnsout_type* addns = NULL;
    CHECKALLOC(addns = (dnsout_type*) malloc(sizeof(dnsout_type)));
    addns->provide_xfr = NULL;
    addns->do_notify = NULL;
    addns->tsig = NULL;
    return addns;
}


/**
 * Read DNS input adapter.
 *
 */
static ods_status
dnsin_read(dnsin_type* addns, const char* filename)
{
    const char* rngfile = ODS_SE_RNGDIR "/addns.rng";
    ods_status status = ODS_STATUS_OK;
    FILE* fd = NULL;
    if (!filename || !addns) {
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_debug("[%s] read dnsin file %s", adapter_str, filename);
    status = parse_file_check(filename, rngfile);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read dnsin: parse error in "
            "file %s (%s)", adapter_str, filename, ods_status2str(status));
        return status;
    }
    fd = ods_fopen(filename, NULL, "r");
    if (fd) {
        addns->tsig = parse_addns_tsig(filename);
        addns->request_xfr = parse_addns_request_xfr(filename, addns->tsig);
        addns->allow_notify = parse_addns_allow_notify(filename, addns->tsig);
        ods_fclose(fd);
        return ODS_STATUS_OK;
    }
    ods_log_error("[%s] unable to read dnsout: failed to open file %s",
        adapter_str, filename);
    return ODS_STATUS_ERR;
}


/**
 * Update DNS input adapter.
 *
 */
ods_status
dnsin_update(dnsin_type** addns, const char* filename, time_t* last_mod)
{
    dnsin_type* new_addns = NULL;
    time_t st_mtime = 0;
    ods_status status = ODS_STATUS_OK;

    if (!filename || !addns || !last_mod) {
        return ODS_STATUS_UNCHANGED;
    }
    /* read the new signer configuration */
    status = dnsin_read(*addns, filename);
    if (status == ODS_STATUS_OK) {
        *last_mod = st_mtime;
    } else {
        ods_log_error("[%s] unable to update dnsin: dnsin_read(%s) "
            "failed (%s)", adapter_str, filename, ods_status2str(status));
    }
    return status;
}

/**
 * Read DNS output adapter.
 *
 */
static ods_status
dnsout_read(dnsout_type* addns, const char* filename)
{
    const char* rngfile = ODS_SE_RNGDIR "/addns.rng";
    ods_status status = ODS_STATUS_OK;
    FILE* fd = NULL;
    if (!filename || !addns) {
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_debug("[%s] read dnsout file %s", adapter_str, filename);
    status = parse_file_check(filename, rngfile);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read dnsout: parse error in "
            "file %s (%s)", adapter_str, filename, ods_status2str(status));
        return status;
    }
    fd = ods_fopen(filename, NULL, "r");
    if (fd) {
        addns->tsig = parse_addns_tsig(filename);
        addns->provide_xfr = parse_addns_provide_xfr(filename, addns->tsig);
        addns->do_notify = parse_addns_do_notify(filename, addns->tsig);
        ods_fclose(fd);
        return ODS_STATUS_OK;
    }
    ods_log_error("[%s] unable to read dnsout: failed to open file %s",
        adapter_str, filename);
    return ODS_STATUS_ERR;
}


/**
 * Update DNS output adapter.
 *
 */
ods_status
dnsout_update(dnsout_type** addns, const char* filename, time_t* last_mod)
{
    time_t st_mtime = 0;
    ods_status status = ODS_STATUS_OK;

    if (!filename || !addns || !last_mod) {
        return ODS_STATUS_UNCHANGED;
    }
    /* read the new signer configuration */
    status = dnsout_read(*addns, filename);
    if (status == ODS_STATUS_OK) {
        *last_mod = st_mtime;
    } else {
        ods_log_error("[%s] unable to update dnsout: dnsout_read(%s) "
            "failed (%s)", adapter_str, filename, ods_status2str(status));
        /* Don't do this cleanup. Signer will crash on exit and will
         * access the wrong memory runtime. Leak is only once per badly
         * configured adapter. */
        /* dnsout_cleanup(*addns); */
    }
    return status;
}


/**
 * Send notifies.
 *
 */
static void
dnsout_send_notify(void* zone)
{
    zone_type* z = (zone_type*) zone;
    rrset_type* rrset = NULL;
    ldns_rr* soa = NULL;
    if (!z->notify) {
        ods_log_error("[%s] unable to send notify for zone %s: no notify "
           "handler", adapter_str, z->name);
        return;
    }
    ods_log_assert(z->adoutbound);
    ods_log_assert(z->adoutbound->config);
    ods_log_assert(z->adoutbound->type == ADAPTER_DNS);
    ods_log_assert(z->db);
    ods_log_assert(z->name);
    ods_log_debug("[%s] enable notify for zone %s serial %u", adapter_str,
        z->name, z->db->intserial);
    rrset = zone_lookup_rrset(z, z->apex, LDNS_RR_TYPE_SOA);
    ods_log_assert(rrset);
    soa = ldns_rr_clone(rrset->rrs[0].rr);
    notify_enable(z->notify, soa);
}


/**
 * Read zone from DNS Input Adapter.
 *
 */
ods_status
addns_read(void* zone)
{
    zone_type* z = (zone_type*) zone;
    ods_status status = ODS_STATUS_OK;
    char* xfrfile = NULL;
    char* file = NULL;
    FILE* fd = NULL;
    ods_log_assert(z);
    ods_log_assert(z->name);
    ods_log_assert(z->xfrd);
    ods_log_assert(z->db);
    ods_log_assert(z->adinbound);
    ods_log_assert(z->adinbound->type == ADAPTER_DNS);

    pthread_mutex_lock(&z->xfrd->rw_lock);
    pthread_mutex_lock(&z->xfrd->serial_lock);
    /* did we already store a new zone transfer on disk? */
    if (!z->xfrd->serial_disk_acquired ||
        z->xfrd->serial_disk_acquired <= z->xfrd->serial_xfr_acquired) {
        if (!z->xfrd->serial_disk_acquired) {
            pthread_mutex_unlock(&z->xfrd->serial_lock);
            pthread_mutex_unlock(&z->xfrd->rw_lock);
            return ODS_STATUS_XFR_NOT_READY;
        }
        pthread_mutex_unlock(&z->xfrd->serial_lock);
        pthread_mutex_unlock(&z->xfrd->rw_lock);
        /* do a transaction for DNSKEY and NSEC3PARAM */
        adapi_trans_diff(z, 0);
        ods_log_verbose("[%s] no new xfr ready for zone %s", adapter_str,
            z->name);
        return ODS_STATUS_UNCHANGED;
    }
    /* copy zone transfers */
    xfrfile = ods_build_path(z->name, ".xfrd", 0, 1);
    file = ods_build_path(z->name, ".xfrd.tmp", 0, 1);
    if (!xfrfile || !file) {
        free(xfrfile);
        free(file);
        pthread_mutex_unlock(&z->xfrd->serial_lock);
        pthread_mutex_unlock(&z->xfrd->rw_lock);
        ods_log_error("[%s] unable to build paths to xfrd files", adapter_str);
        return ODS_STATUS_MALLOC_ERR;
    }
    if (rename(xfrfile, file) != 0) {
        pthread_mutex_unlock(&z->xfrd->serial_lock);
        pthread_mutex_unlock(&z->xfrd->rw_lock);
        ods_log_error("[%s] unable to rename file %s to %s: %s", adapter_str,
           xfrfile, file, strerror(errno));
        free((void*) xfrfile);
        free((void*) file);
        return ODS_STATUS_RENAME_ERR;
    }
    pthread_mutex_unlock(&z->xfrd->serial_lock);
    /* open copy of zone transfers to read */
    fd = ods_fopen(file, NULL, "r");
    free((void*) xfrfile);
    if (!fd) {
        pthread_mutex_unlock(&z->xfrd->rw_lock);
        free((void*) file);
        return ODS_STATUS_FOPEN_ERR;
    }
    pthread_mutex_unlock(&z->xfrd->rw_lock);

    status = addns_read_file(fd, z);
    if (status == ODS_STATUS_OK) {
        /* clean up copy of zone transfer */
        if (unlink((const char*) file) != 0) {
            ods_log_error("[%s] unable to unlink zone transfer copy file %s: "
                " %s", adapter_str, file, strerror(errno));
            /* should be no issue */
        }
    }
    free((void*) file);
    ods_fclose(fd);
    return status;
}


/**
 * Write to DNS Output Adapter.
 *
 */
ods_status
addns_write(void* zone)
{
    FILE* fd = NULL;
    char* atmpfile = NULL;
    char* axfrfile = NULL;
    char* itmpfile = NULL;
    char* ixfrfile = NULL;
    zone_type* z = (zone_type*) zone;
    int ret = 0;
    ods_status status = ODS_STATUS_OK;
    ods_log_assert(z);
    ods_log_assert(z->name);
    ods_log_assert(z->adoutbound);
    ods_log_assert(z->adoutbound->type == ADAPTER_DNS);

    atmpfile = ods_build_path(z->name, ".axfr.tmp", 0, 1);
    if (!atmpfile) {
        return ODS_STATUS_MALLOC_ERR;
    }
    fd = ods_fopen(atmpfile, NULL, "w");
    if (!fd) {
        free((void*) atmpfile);
        return ODS_STATUS_FOPEN_ERR;
    }
    status = adapi_printaxfr(fd, z);
    ods_fclose(fd);
    if (status != ODS_STATUS_OK) {
        free((void*) atmpfile);
        return status;
    }

    if (status == ODS_STATUS_OK) {
        if (z->adoutbound->error) {
            ods_log_error("[%s] unable to write zone %s axfr: one or "
                "more RR print failed", adapter_str, z->name);
            /* clear error */
            z->adoutbound->error = 0;
            free((void*) atmpfile);
            free((void*) itmpfile);
            return ODS_STATUS_FWRITE_ERR;
        }
    }

    /* lock and move */
    axfrfile = ods_build_path(z->name, ".axfr", 0, 1);
    if (!axfrfile) {
        free((void*) atmpfile);
        free((void*) itmpfile);
        return ODS_STATUS_MALLOC_ERR;
    }

    pthread_mutex_lock(&z->xfr_lock);
    ret = rename(atmpfile, axfrfile);
    if (ret != 0) {
        ods_log_error("[%s] unable to rename file %s to %s: %s", adapter_str,
            atmpfile, axfrfile, strerror(errno));
        pthread_mutex_unlock(&z->xfr_lock);
        free((void*) atmpfile);
        free((void*) axfrfile);
        free((void*) itmpfile);
        return ODS_STATUS_RENAME_ERR;
    }
    free((void*) axfrfile);
    free((void*) atmpfile);
    axfrfile = NULL;
    atmpfile = NULL;

    free((void*) itmpfile);
    pthread_mutex_unlock(&z->xfr_lock);

    dnsout_send_notify(zone);
    return ODS_STATUS_OK;
}


/**
 * Clean up DNS input adapter.
 *
 */
void
dnsin_cleanup(dnsin_type* addns)
{
    if (!addns) {
        return;
    }
    acl_cleanup(addns->request_xfr);
    acl_cleanup(addns->allow_notify);
    tsig_cleanup(addns->tsig);
    free(addns);
}


/**
 * Clean up DNS output adapter.
 *
 */
void
dnsout_cleanup(dnsout_type* addns)
{
    if (!addns) {
        return;
    }
    acl_cleanup(addns->provide_xfr);
    acl_cleanup(addns->do_notify);
    tsig_cleanup(addns->tsig);
    free(addns);
}
