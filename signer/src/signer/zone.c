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
 * Zone.
 *
 */

#include "adapter/adapter.h"
#include "file.h"
#include "hsm.h"
#include "locks.h"
#include "log.h"
#include "status.h"
#include "util.h"
#include "signer/zone.h"
#include "wire/netio.h"
#include "compat.h"
#include "daemon/signertasks.h"

#include <ldns/ldns.h>

static const char* zone_str = "zone";


/**
 * Create a new zone.
 *
 */
zone_type*
zone_create(char* name, ldns_rr_class klass)
{
    zone_type* zone = NULL;
    int err;

    if (!name || !klass) {
        return NULL;
    }
    CHECKALLOC(zone = (zone_type*) calloc(1, sizeof(zone_type)));
    /* [start] PS 9218653: Drop trailing dot in domain name */
    if (strlen(name) > 1 && name[strlen(name)-1] == '.') {
        name[strlen(name)-1] = '\0';
    }
    /* [end] PS 9218653 */

    if (pthread_mutex_init(&zone->zone_lock, NULL)) {
        free(zone);
        return NULL;
    }
    if (pthread_mutex_init(&zone->xfr_lock, NULL)) {
        (void)pthread_mutex_destroy(&zone->zone_lock);
        free(zone);
        return NULL;
    }

    zone->name = strdup(name);
    if (!zone->name) {
        ods_log_error("[%s] unable to create zone %s: allocator_strdup() "
            "failed", zone_str, name);
        zone_cleanup(zone);
        return NULL;
    }
    zone->klass = klass;
    zone->default_ttl = 3600; /* TODO: configure --default-ttl option? */
    zone->apex = ldns_dname_new_frm_str(name);
    /* check zone->apex? */
    zone->notify_command = NULL;
    zone->notify_ns = NULL;
    zone->notify_args = NULL;
    zone->policy_name = NULL;
    zone->signconf_filename = NULL;
    zone->adinbound = NULL;
    zone->adoutbound = NULL;
    zone->zl_status = ZONE_ZL_OK;
    zone->xfrd = NULL;
    zone->notify = NULL;
    zone->zoneconfigvalid = 0;
    zone->signconf = signconf_create();
    if (!zone->signconf) {
        ods_log_error("[%s] unable to create zone %s: signconf_create() "
            "failed", zone_str, name);
        zone_cleanup(zone);
        return NULL;
    }
    zone->stats = stats_create();
    return zone;
}

/**
 * Load signer configuration for zone.
 *
 */
ods_status
zone_load_signconf(zone_type* zone, signconf_type** new_signconf)
{
    ods_status status = ODS_STATUS_OK;
    signconf_type* signconf = NULL;
    char* datestamp = NULL;

    if (!zone || !zone->name || !zone->signconf) {
        return ODS_STATUS_ASSERT_ERR;
    }
    if (!zone->signconf_filename) {
        ods_log_warning("[%s] zone %s has no signconf filename, treat as "
            "insecure?", zone_str, zone->name);
        return ODS_STATUS_INSECURE;
    }
    status = signconf_update(&signconf, zone->signconf_filename,
        zone->signconf->last_modified);
    if (status == ODS_STATUS_OK) {
        if (!signconf) {
            /* this is unexpected */
            ods_log_alert("[%s] unable to load signconf for zone %s: signconf "
                "status ok but no signconf stored", zone_str, zone->name);
            return ODS_STATUS_ASSERT_ERR;
        }
        (void)time_datestamp(signconf->last_modified, "%Y-%m-%d %T",
            &datestamp);
        ods_log_debug("[%s] zone %s signconf file %s is modified since %s",
            zone_str, zone->name, zone->signconf_filename,
            datestamp?datestamp:"Unknown");
        free((void*)datestamp);
        *new_signconf = signconf;
    } else if (status == ODS_STATUS_UNCHANGED) {
        /* OPENDNSSEC-686: changes happening within one second will not be
         * seen
         */
        (void)time_datestamp(zone->signconf->last_modified,
            "%Y-%m-%d %T", &datestamp);
        ods_log_verbose("[%s] zone %s signconf file %s is unchanged since "
            "%s", zone_str, zone->name, zone->signconf_filename,
            datestamp?datestamp:"Unknown");
        free((void*)datestamp);
    } else {
        ods_log_error("[%s] unable to load signconf for zone %s: signconf %s "
            "%s", zone_str, zone->name, zone->signconf_filename,
            ods_status2str(status));
    }
    return status;
}

/**
 * Publish the keys as indicated by the signer configuration.
 *
 */
ods_status
zone_publish_dnskeys(zone_type* zone, names_view_type view, int skip_hsm_access)
{
    hsm_ctx_t* ctx = NULL;
    uint32_t ttl = 0;
    unsigned int i;
    ods_status status = ODS_STATUS_OK;
    ldns_rr* dnskey = NULL;

    if (!zone || !zone->signconf || !zone->signconf->keys) {
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->name);

    /* hsm access */
    if (!skip_hsm_access) {
        ctx = hsm_create_context();
        if (ctx == NULL) {
            ods_log_error("[%s] unable to publish keys for zone %s: "
                "error creating libhsm context", zone_str, zone->name);
            return ODS_STATUS_HSM_ERR;
        }
    }
    ttl = zone->default_ttl;
    /* dnskey ttl */
    if (zone->signconf->dnskey_ttl) {
        ttl = (uint32_t) duration2time(zone->signconf->dnskey_ttl);
    }
    /* publish keys */
    for (i=0; i < zone->signconf->keys->count; i++) {
        if (!zone->signconf->keys->keys[i].publish) {
            continue;
        }
        if (!zone->signconf->keys->keys[i].dnskey) {
            /* get dnskey */
            if  (zone->signconf->keys->keys[i].resourcerecord) {
                if ((status = rrset_getliteralrr(&zone->signconf->keys->keys[i].dnskey, zone->signconf->keys->keys[i].resourcerecord, ttl, zone->apex)) != ODS_STATUS_OK) {
                    ods_log_error("[%s] unable to publish dnskeys for zone %s: "
                            "error decoding literal dnskey", zone_str, zone->name);
                    if (!skip_hsm_access) {
                        hsm_destroy_context(ctx);
                    }
                    return status;
                }
            } else {
                status = lhsm_get_key(ctx, zone->apex,
                        &zone->signconf->keys->keys[i], skip_hsm_access);
                if (status != ODS_STATUS_OK) {
                    ods_log_error("[%s] unable to publish dnskeys for zone %s: "
                            "error creating dnskey", zone_str, zone->name);
                    break;
                }
            }
        }
        ods_log_debug("[%s] publish %s DNSKEY locator %s", zone_str,
            zone->name, zone->signconf->keys->keys[i].locator);
        if (!skip_hsm_access) {
            ods_log_assert(zone->signconf->keys->keys[i].dnskey);
            ldns_rr_set_ttl(zone->signconf->keys->keys[i].dnskey, ttl);
            ldns_rr_set_class(zone->signconf->keys->keys[i].dnskey, zone->klass);
            status = zone_add_rr(zone, view, zone->signconf->keys->keys[i].dnskey, 0);
            if (status == ODS_STATUS_UNCHANGED) {
                /* rr already exists, adjust pointer */
                names_viewlookupone(view, NULL, LDNS_RR_TYPE_DNSKEY, zone->signconf->keys->keys[i].dnskey, &dnskey);
                ods_log_assert(dnskey);
                if (dnskey != zone->signconf->keys->keys[i].dnskey) {
                    ldns_rr_free(zone->signconf->keys->keys[i].dnskey);
                    zone->signconf->keys->keys[i].dnskey = dnskey;
                }
                status = ODS_STATUS_OK;
            } else if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to publish dnskeys for zone %s: "
                    "error adding dnskey", zone_str, zone->name);
                break;
            }
        }
    }
    /* done */
    if (!skip_hsm_access) {
        hsm_destroy_context(ctx);
    }
    return status;
}


/**
 * Publish the NSEC3 parameters as indicated by the signer configuration.
 *
 */
ods_status
zone_publish_nsec3param(zone_type* zone, names_view_type view)
{
    ldns_rr* rr = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!zone || !zone->name || !zone->signconf) {
        return ODS_STATUS_ASSERT_ERR;
    }
    if (!zone->signconf->nsec3params) {
        /* NSEC */
        ods_log_assert(zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC);
        return ODS_STATUS_OK;
    }

    if (!zone->signconf->nsec3params->rr) {
        uint32_t paramttl =
            (uint32_t) duration2time(zone->signconf->nsec3param_ttl);
        rr = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3PARAMS);
        if (!rr) {
            ods_log_error("[%s] unable to publish nsec3params for zone %s: "
                "error creating rr (%s)", zone_str, zone->name,
                ods_status2str(status));
            return ODS_STATUS_MALLOC_ERR;
        }
        ldns_rr_set_class(rr, zone->klass);
        ldns_rr_set_ttl(rr, paramttl);
        ldns_rr_set_owner(rr, ldns_rdf_clone(zone->apex));
        ldns_nsec3_add_param_rdfs(rr,
            zone->signconf->nsec3params->algorithm, 0,
            zone->signconf->nsec3params->iterations,
            zone->signconf->nsec3params->salt_len,
            zone->signconf->nsec3params->salt_data);
        /**
         * Always set bit 7 of the flags to zero,
         * according to rfc5155 section 11
         */
        ldns_set_bit(ldns_rdf_data(ldns_rr_rdf(rr, 1)), 7, 0);
        zone->signconf->nsec3params->rr = rr;
    }

    /* Delete all nsec3param rrs. */
    zone_del_nsec3params(zone, view);

    ods_log_assert(zone->signconf->nsec3params->rr);
    status = zone_add_rr(zone, view, ldns_rr_clone(zone->signconf->nsec3params->rr), 0);
    if (status == ODS_STATUS_UNCHANGED) {
        status = ODS_STATUS_OK;
    } else if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to publish nsec3params for zone %s: "
            "error adding nsec3params (%s)", zone_str,
            zone->name, ods_status2str(status));
    }
    return status;
}


/**
 * Prepare keys for signing.
 *
 */
ods_status
zone_prepare_keys(zone_type* zone)
{
    hsm_ctx_t* ctx = NULL;
    uint16_t i = 0;
    ods_status status = ODS_STATUS_OK;

    if (!zone || !zone->signconf || !zone->signconf->keys) {
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->name);
    /* hsm access */
    ctx = hsm_create_context();
    if (ctx == NULL) {
        ods_log_error("[%s] unable to prepare signing keys for zone %s: "
            "error creating libhsm context", zone_str, zone->name);
        return ODS_STATUS_HSM_ERR;
    }
    /* prepare keys */
    for (i=0; i < zone->signconf->keys->count; i++) {
        if(zone->signconf->dnskey_signature != NULL && zone->signconf->keys->keys[i].ksk)
            continue;
        /* get dnskey */
        status = lhsm_get_key(ctx, zone->apex, &zone->signconf->keys->keys[i], 0);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to prepare signing keys for zone %s: "
                "error getting dnskey", zone_str, zone->name);
            break;
        }
        ods_log_assert(zone->signconf->keys->keys[i].dnskey);
        ods_log_assert(zone->signconf->keys->keys[i].params);
    }
    /* done */
    hsm_destroy_context(ctx);
    return status;
}


ods_status
zone_add_rr(zone_type* zone, names_view_type view, ldns_rr* rr, int do_stats)
{
    recordset_type record;
    ods_status status;
    char* name;
    name = ldns_rdf2str(ldns_rr_owner(rr));
    record = names_place(view, name);
    free(name);
    /* FIXME We only ought to entize the domain when newly added, but cannot detect this properly */
    status = namedb_domain_entize(view, record, ldns_rr_owner(rr), zone->apex);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to add RR to zone %s: failed to entize domain", zone_str, zone->name);
        return ODS_STATUS_ERR;
    }
    /* FIXME we should check the TTL of the rr conforms to the other rr already present */
    if(!names_recordhasdata(record, ldns_rr_get_type(rr), rr, 0)) {
        rrset_add_rr(record, rr);
    }
    return status;
}

ods_status
zone_del_rr(zone_type* zone, names_view_type view, ldns_rr* rr, int do_stats)
{
    recordset_type record;
    const char* name;
    name = ldns_rdf2str(ldns_rr_owner(rr));
    record = names_take(view, 0, name);
    free((void*)name);
    if(record) {
        if(names_recordhasdata(record, ldns_rr_get_type(rr), rr, 0)) {
            names_recorddeldata(record, ldns_rr_get_type(rr), rr);
        }
    }
    return 0;
}



/**
 * Merge zones.
 *
 */
void
zone_merge(zone_type* z1, zone_type* z2)
{
    const char* str;
    adapter_type* adtmp = NULL;

    if (!z1 || !z2) {
        return;
    }
    /* policy name */
    if (ods_strcmp(z2->policy_name, z1->policy_name) != 0) {
        if (z2->policy_name) {
            str = strdup(z2->policy_name);
            if (!str) {
                ods_log_error("[%s] failed to merge policy %s name to zone "
                    "%s", zone_str, z2->policy_name, z1->name);
            } else {
                free((void*)z1->policy_name);
                z1->policy_name = str;
                z1->zl_status = ZONE_ZL_UPDATED;
            }
        } else {
            free((void*)z1->policy_name);
            z1->policy_name = NULL;
            z1->zl_status = ZONE_ZL_UPDATED;
        }
    }
    /* signconf filename */
    if (ods_strcmp(z2->signconf_filename, z1->signconf_filename) != 0) {
        if (z2->signconf_filename) {
            str = strdup(z2->signconf_filename);
            if (!str) {
                ods_log_error("[%s] failed to merge signconf filename %s to "
                    "zone %s", zone_str, z2->policy_name, z1->name);
            } else {
                free((void*)z1->signconf_filename);
                z1->signconf_filename = str;
                z1->zl_status = ZONE_ZL_UPDATED;
            }
        } else {
            free((void*)z1->signconf_filename);
            z1->signconf_filename = NULL;
            z1->zl_status = ZONE_ZL_UPDATED;
        }
    }
    /* adapters */
    if (adapter_compare(z2->adinbound, z1->adinbound) != 0) {
        adtmp = z2->adinbound;
        z2->adinbound = z1->adinbound;
        z1->adinbound = adtmp;
        adtmp = NULL;
    }
    if (adapter_compare(z2->adoutbound, z1->adoutbound) != 0) {
        adtmp = z2->adoutbound;
        z2->adoutbound = z1->adoutbound;
        z1->adoutbound = adtmp;
        adtmp = NULL;
    }
}


/**
 * Clean up zone.
 *
 */
void
zone_cleanup(zone_type* zone)
{
    if (!zone) {
        return;
    }
    pthread_mutex_lock(&zone->zone_lock);
    ldns_rdf_deep_free(zone->apex);
    adapter_cleanup(zone->adinbound);
    adapter_cleanup(zone->adoutbound);
    xfrd_cleanup(zone->xfrd, 1);
    notify_cleanup(zone->notify);
    signconf_cleanup(zone->signconf);
    pthread_mutex_unlock(&zone->zone_lock);
    stats_cleanup(zone->stats);
    free(zone->notify_command);
    free(zone->notify_args);
    free((void*)zone->policy_name);
    free((void*)zone->signconf_filename);
    free((void*)zone->name);
    free((void*)zone->nextserial);
    free((void*)zone->inboundserial);
    free((void*)zone->outboundserial);
    zone->nextserial = NULL;
    zone->inboundserial = NULL;
    zone->outboundserial = NULL;
    pthread_mutex_destroy(&zone->xfr_lock);
    pthread_mutex_destroy(&zone->zone_lock);
    free(zone);
}

static const char* baseviewkeys[] = { "namerevision", NULL};
static const char* inputviewkeys[] = { "nameupcoming", "namehierarchy", NULL};
static const char* prepareviewkeys[] = { "namerevision", "namenoserial", "namenewserial", NULL};
static const char* neighviewkeys[] = { "nameready", "denialname", NULL};
static const char* signviewkeys[] = { "nameready", "expiry", "denialname", NULL};
static const char* outputviewkeys[] = { "validnow", NULL};

void
zone_start(zone_type* zone)
{
    char* zoneapex;
    zoneapex = ldns_rdf2str(zone->apex);
    /*if(zoneapex[strlen(zoneapex)-1] == '.')
        zoneapex[strlen(zoneapex)-1] = '\0'; FIXME */
    zone->baseview = names_viewcreate(NULL, "  base    ", baseviewkeys);
    names_viewconfig(zone->baseview, &(zone->signconf));
    names_viewrestore(zone->baseview, zoneapex, -1, NULL); // FIXME proper restore filename
    zone->inputview = names_viewcreate(zone->baseview,   "  input   ", inputviewkeys);
    zone->prepareview = names_viewcreate(zone->baseview, "  prepare ", prepareviewkeys);
    zone->neighview = names_viewcreate(zone->baseview, "  neighbr ", neighviewkeys);
    zone->signview = names_viewcreate(zone->baseview,    "  sign    ", signviewkeys);
    zone->outputview = names_viewcreate(zone->baseview,  "  output  ", outputviewkeys);
    free(zoneapex);
}
