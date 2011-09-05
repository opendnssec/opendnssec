/*
 * $Id$
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
 * Zone.
 *
 */

#include "adapter/adapi.h"
#include "adapter/adapter.h"
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/hsm.h"
#include "shared/locks.h"
#include "shared/log.h"
#include "shared/status.h"
#include "shared/util.h"
#include "signer/backup.h"
#include "signer/zone.h"

#include <ldns/ldns.h>

static const char* zone_str = "zone";


/**
 * Create a new zone.
 *
 */
zone_type*
zone_create(char* name, ldns_rr_class klass)
{
    allocator_type* allocator = NULL;
    zone_type* zone = NULL;

    if (!name || !klass) {
        return NULL;
    }
    allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] unable to create zone %s: allocator_create() "
            "failed", zone_str, name);
        return NULL;
    }
    zone = (zone_type*) allocator_alloc(allocator, sizeof(zone_type));
    if (!zone) {
        ods_log_error("[%s] unable to create zone %s: allocator_alloc()",
            "failed", zone_str, name);
        allocator_cleanup(allocator);
        return NULL;
    }
    zone->allocator = allocator;
    /* [start] PS 9218653: Drop trailing dot in domain name */
    if (strlen(name) > 1 && name[strlen(name)-1] == '.') {
        name[strlen(name)-1] = '\0';
    }
    /* [end] PS 9218653 */
    zone->name = allocator_strdup(allocator, name);
    /* check zone->name? */
    zone->klass = klass;
    zone->default_ttl = 3600; /* TODO: configure --default-ttl option? */
    zone->apex = ldns_dname_new_frm_str(name);
    /* check zone->apex? */
    ldns_dname2canonical(zone->apex);
    zone->notify_ns = NULL;
    zone->policy_name = NULL;
    zone->signconf_filename = NULL;
    zone->adinbound = NULL;
    zone->adoutbound = NULL;
    zone->zl_status = ZONE_ZL_OK;
    zone->processed = 0;
    zone->prepared = 0;
    zone->fetch = 0;
    zone->task = NULL;
    zone->zonedata = zonedata_create(zone->allocator);
    if (!zone->zonedata) {
        ods_log_error("[%s] unable to create zone %s: create zonedata "
            "failed", zone_str, name);
        zone_cleanup(zone);
        return NULL;
    }
    zone->signconf = signconf_create();
    if (!zone->signconf) {
        ods_log_error("[%s] unable to create zone %s: create signconf "
            "failed", zone_str, name);
        zone_cleanup(zone);
        return NULL;
    }
    zone->stats = stats_create();
    lock_basic_init(&zone->zone_lock);
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
    uint32_t ustamp = 0;

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
        ustamp = time_datestamp(signconf->last_modified, "%Y-%m-%d %T",
            &datestamp);
        ods_log_debug("[%s] zone %s signconf file %s is modified since %s",
            zone_str, zone->name, zone->signconf_filename,
            datestamp?datestamp:"Unknown");
        free((void*)datestamp);
        *new_signconf = signconf;
    } else if (status == ODS_STATUS_UNCHANGED) {
        ustamp = time_datestamp(zone->signconf->last_modified,
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
zone_publish_dnskeys(zone_type* zone)
{
    hsm_ctx_t* ctx = NULL;
    uint32_t ttl = 0;
    uint16_t i = 0;
    ods_status status = ODS_STATUS_OK;

    if (!zone || !zone->zonedata || !zone->signconf || !zone->signconf->keys) {
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->name);

    /* hsm access */
    ctx = hsm_create_context();
    if (ctx == NULL) {
        ods_log_error("[%s] unable to publish keys for zone %s: "
            "error creating libhsm context", zone_str, zone->name);
        return ODS_STATUS_HSM_ERR;
    }
    /* dnskey ttl */
    ttl = zone->default_ttl;
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
            status = lhsm_get_key(ctx, zone->apex,
                &zone->signconf->keys->keys[i]);
            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to publish dnskeys for zone %s: "
                    "error creating dnskey", zone_str, zone->name);
                break;
            }
        }
        ods_log_assert(zone->signconf->keys->keys[i].dnskey);
        ldns_rr_set_ttl(zone->signconf->keys->keys[i].dnskey, ttl);
        ldns_rr_set_class(zone->signconf->keys->keys[i].dnskey, zone->klass);
        ldns_rr2canonical(zone->signconf->keys->keys[i].dnskey);
        status = zone_add_rr(zone, zone->signconf->keys->keys[i].dnskey, 0);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to publish dnskeys for zone %s: "
                "error adding dnskey", zone_str, zone->name);
            break;
        }
    }
    if (status != ODS_STATUS_OK) {
        zonedata_rollback(zone->zonedata);
    }
    /* done */
    hsm_destroy_context(ctx);
    return status;
}


/**
 * Publish the NSEC3 parameters as indicated by the signer configuration.
 *
 */
ods_status
zone_publish_nsec3param(zone_type* zone, int recover)
{
    ldns_rr* nsec3params_rr = NULL;
    domain_type* apex = NULL;
    rrset_type* rrset = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!zone || !zone->name || !zone->zonedata || !zone->signconf) {
        return ODS_STATUS_ASSERT_ERR;
    }

    if (zone->signconf->nsec_type != LDNS_RR_TYPE_NSEC3) {
        /* no preparations needed */
        return ODS_STATUS_OK;
    }

    if (!zone->signconf->nsec3params) {
        ods_log_debug("[%s] prepare NSEC3 for zone %s", zone_str, zone->name);

        zone->signconf->nsec3params = nsec3params_create((void*)zone->signconf,
            (uint8_t) zone->signconf->nsec3_algo,
            (uint8_t) zone->signconf->nsec3_optout,
            (uint16_t) zone->signconf->nsec3_iterations,
            zone->signconf->nsec3_salt);
    }
    if (!zone->signconf->nsec3params) {
        ods_log_error("[%s] unable to prepare zone %s for NSEC3: failed "
            "to create NSEC3 parameters", zone_str, zone->name);
        return ODS_STATUS_MALLOC_ERR;
    }

    if (recover) {
        nsec3params_rr = ldns_rr_clone(zone->signconf->nsec3params->rr);
        status = zone_add_rr(zone, nsec3params_rr, 0);
    } else {
        nsec3params_rr = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3PARAMS);
        if (!nsec3params_rr) {
            ods_log_error("[%s] unable to prepare zone %s for NSEC3: failed "
                "to create NSEC3PARAM RR", zone_str, zone->name);
            return ODS_STATUS_MALLOC_ERR;
        }
        ldns_rr_set_class(nsec3params_rr, zone->klass);
        ldns_rr_set_ttl(nsec3params_rr, zone->default_ttl);
        ldns_rr_set_owner(nsec3params_rr, ldns_rdf_clone(zone->apex));
        ldns_nsec3_add_param_rdfs(nsec3params_rr,
            zone->signconf->nsec3params->algorithm, 0,
            zone->signconf->nsec3params->iterations,
            zone->signconf->nsec3params->salt_len,
            zone->signconf->nsec3params->salt_data);
        /**
         * Always set bit 7 of the flags to zero,
         * according to rfc5155 section 11
         */
        ldns_set_bit(ldns_rdf_data(ldns_rr_rdf(nsec3params_rr, 1)), 7, 0);

        ldns_rr2canonical(nsec3params_rr);
        zone->signconf->nsec3params->rr = ldns_rr_clone(nsec3params_rr);
        status = zone_add_rr(zone, nsec3params_rr, 0);
    }

    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to add NSEC3PARAM RR to zone %s",
            zone_str, zone->name);
    } else if (!recover) {
        /* add ok, wipe out previous nsec3params */
        apex = zonedata_lookup_domain(zone->zonedata, zone->apex);
        if (!apex) {
            ods_log_crit("[%s] unable to delete previous NSEC3PARAM RR "
            "from zone %s: apex undefined", zone_str, zone->name);
            zonedata_rollback(zone->zonedata);
            return ODS_STATUS_ASSERT_ERR;
        }
        ods_log_assert(apex);

        rrset = domain_lookup_rrset(apex, LDNS_RR_TYPE_NSEC3PARAMS);
        if (rrset) {
            status = rrset_wipe_out(rrset);
            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to wipe out previous "
                    "NSEC3PARAM RR from zone %s", zone_str, zone->name);
                rrset_rollback(rrset);
                return status;
            }
        }
    }
    return status;
}


/**
 * Update serial.
 *
 */
ods_status
zone_update_serial(zone_type* zone)
{
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;
    rrset_type* rrset = NULL;
    ldns_rdf* serial = NULL;

    if (!zone) {
        ods_log_error("[%s] unable to update serial: no zone",
            zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);

    if (!zone->signconf) {
        ods_log_error("[%s] unable to update serial: no signconf",
            zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->signconf);

    if (!zone->zonedata) {
        ods_log_error("[%s] unable to update serial: no zonedata",
            zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->zonedata);

    status = zonedata_update_serial(zone->zonedata, zone->signconf);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to update serial: failed to increment",
            zone_str);
        return status;
    }

    /* lookup domain */
    domain = zonedata_lookup_domain(zone->zonedata, zone->apex);
    if (!domain) {
        ods_log_error("[%s] unable to update serial: apex not found",
            zone_str);
        return ODS_STATUS_ERR;
    }
    ods_log_assert(domain);

    /* lookup RRset */
    rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_SOA);
    if (!rrset) {
        ods_log_error("[%s] unable to update serial: SOA RRset not found",
            zone_str);
        return ODS_STATUS_ERR;
    }
    ods_log_assert(rrset);
    ods_log_assert(rrset->rr_type == LDNS_RR_TYPE_SOA);

    if (rrset->rrs && rrset->rrs->rr) {
        serial = ldns_rr_set_rdf(rrset->rrs->rr,
            ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32,
            zone->zonedata->internal_serial), SE_SOA_RDATA_SERIAL);
        if (serial) {
            if (ldns_rdf2native_int32(serial) !=
                zone->zonedata->internal_serial) {
                rrset->needs_signing = 1;
            }
            ldns_rdf_deep_free(serial);
         } else {
            ods_log_error("[%s] unable to update serial: failed to replace "
                "SOA SERIAL rdata", zone_str);
            return ODS_STATUS_ERR;
        }
    }
    return ODS_STATUS_OK;
}


/**
 * Add RR.
 *
 */
ods_status
zone_add_rr(zone_type* zone, ldns_rr* rr, int do_stats)
{
    domain_type* domain = NULL;
    rrset_type* rrset = NULL;
    ldns_rdf* soa_min = NULL;
    ldns_rr_type type = LDNS_RR_TYPE_FIRST;
    uint32_t tmp = 0;

    if (!rr) {
        ods_log_error("[%s] unable to add RR: no RR", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rr);

    if (!zone || !zone->zonedata) {
        ods_log_error("[%s] unable to add RR: no storage", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->zonedata);

    if (!zone->signconf) {
        ods_log_error("[%s] unable to add RR: no signconf", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->signconf);

    /* in-zone? */
    if (ldns_dname_compare(zone->apex, ldns_rr_owner(rr)) != 0 &&
        !ldns_dname_is_subdomain(ldns_rr_owner(rr), zone->apex)) {
        ods_log_warning("[%s] zone %s contains out-of-zone data, skipping",
            zone_str, zone->name?zone->name:"(null)");
        /* ok, just filter */
        ldns_rr_free(rr);
        return ODS_STATUS_OK;
    }

    /* type specific configuration */
    type = ldns_rr_get_type(rr);
    if (type == LDNS_RR_TYPE_DNSKEY && zone->signconf->dnskey_ttl) {
        tmp = (uint32_t) duration2time(zone->signconf->dnskey_ttl);
        ods_log_verbose("[%s] zone %s set DNSKEY TTL to %u",
            zone_str, zone->name?zone->name:"(null)", tmp);
        ldns_rr_set_ttl(rr, tmp);
    }
    if (type == LDNS_RR_TYPE_SOA) {
        if (zone->signconf->soa_ttl) {
            tmp = (uint32_t) duration2time(zone->signconf->soa_ttl);
            ods_log_verbose("[%s] zone %s set SOA TTL to %u",
                zone_str, zone->name?zone->name:"(null)", tmp);
            ldns_rr_set_ttl(rr, tmp);
        }
        if (zone->signconf->soa_min) {
            tmp = (uint32_t) duration2time(zone->signconf->soa_min);
            ods_log_verbose("[%s] zone %s set SOA MINIMUM to %u",
                zone_str, zone->name?zone->name:"(null)", tmp);
            soa_min = ldns_rr_set_rdf(rr,
                ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, tmp),
                SE_SOA_RDATA_MINIMUM);
            if (soa_min) {
                ldns_rdf_deep_free(soa_min);
            } else {
                ods_log_error("[%s] zone %s failed to replace SOA MINIMUM "
                    "rdata", zone_str, zone->name?zone->name:"(null)");
                return ODS_STATUS_ASSERT_ERR;
            }
        }
    }

    /* lookup domain */
    domain = zonedata_lookup_domain(zone->zonedata, ldns_rr_owner(rr));
    if (!domain) {
        /* add domain */
        domain = domain_create(ldns_rr_owner(rr));
        if (!domain) {
            ods_log_error("[%s] unable to add RR: create domain failed",
                zone_str);
            return ODS_STATUS_ERR;
        }
        if (zonedata_add_domain(zone->zonedata, domain) == NULL) {
            ods_log_error("[%s] unable to add RR: add domain failed",
                zone_str);
            return ODS_STATUS_ERR;
        }
        if (ldns_dname_compare(domain->dname, zone->apex) == 0) {
            domain->dstatus = DOMAIN_STATUS_APEX;
        }
    }
    ods_log_assert(domain);

    /* lookup RRset */
    rrset = domain_lookup_rrset(domain, ldns_rr_get_type(rr));
    if (!rrset) {
        /* add RRset */
        rrset = rrset_create(ldns_rr_get_type(rr));
        if (!rrset) {
            ods_log_error("[%s] unable to add RR: create RRset failed",
                zone_str);
            return ODS_STATUS_ERR;
        }
        if (domain_add_rrset(domain, rrset) == NULL) {
            ods_log_error("[%s] unable to add RR: add RRset failed",
                zone_str);
            return ODS_STATUS_ERR;
        }
    }
    ods_log_assert(rrset);

    /* add RR */
    if (rrset_add_rr(rrset, rr) == NULL) {
        ods_log_error("[%s] unable to add RR: pend RR failed", zone_str);
        return ODS_STATUS_ERR;
    }

    /* update stats */
    if (zone->stats && do_stats) {
        zone->stats->sort_count += 1;
    }
    return ODS_STATUS_OK;
}


/**
 * Delete RR.
 *
 */
ods_status
zone_del_rr(zone_type* zone, ldns_rr* rr, int do_stats)
{
    domain_type* domain = NULL;
    rrset_type* rrset = NULL;

    if (!rr) {
        ods_log_error("[%s] unable to del RR: no RR", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(rr);

    if (!zone || !zone->zonedata) {
        ods_log_error("[%s] unable to del RR: no storage", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->zonedata);

    /* lookup domain */
    domain = zonedata_lookup_domain(zone->zonedata, ldns_rr_owner(rr));
    if (!domain) {
        /* no domain, no del */
        ods_log_warning("[%s] unable to del RR: no such domain", zone_str);
        return ODS_STATUS_UNCHANGED;
    }
    ods_log_assert(domain);

    /* lookup RRset */
    rrset = domain_lookup_rrset(domain, ldns_rr_get_type(rr));
    if (!rrset) {
        /* no RRset, no del */
        ods_log_warning("[%s] unable to del RR: no such RRset", zone_str);
        return ODS_STATUS_UNCHANGED;
    }
    ods_log_assert(rrset);

    /* del RR */
    if (rrset_del_rr(rrset, rr, (ldns_rr_get_type(rr) == LDNS_RR_TYPE_DNSKEY))
            == NULL) {
        ods_log_error("[%s] unable to del RR: pend RR failed", zone_str);
        return ODS_STATUS_ERR;
    }

    /* update stats */
    if (do_stats && zone->stats) {
        zone->stats->sort_count -= 1;
    }
    return ODS_STATUS_OK;
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
    return;
}


/**
 * Examine zone.
 *
 */
ods_status
zone_examine(zone_type* zone)
{
    if (zone && zone->zonedata && zone->adinbound) {
        return zonedata_examine(zone->zonedata, zone->apex,
            zone->adinbound->type);
    }
    return ODS_STATUS_ASSERT_ERR;
}


/**
 * Clean up zone.
 *
 */
void
zone_cleanup(zone_type* zone)
{
    allocator_type* allocator;
    lock_basic_type zone_lock;
    if (!zone) {
        return;
    }
    allocator = zone->allocator;
    zone_lock = zone->zone_lock;
    ldns_rdf_deep_free(zone->apex);
    adapter_cleanup(zone->adinbound);
    adapter_cleanup(zone->adoutbound);
    zonedata_cleanup(zone->zonedata);
    signconf_cleanup(zone->signconf);
    stats_cleanup(zone->stats);
    allocator_deallocate(allocator, (void*) zone->notify_ns);
    allocator_deallocate(allocator, (void*) zone->policy_name);
    allocator_deallocate(allocator, (void*) zone->signconf_filename);
    allocator_deallocate(allocator, (void*) zone->name);
    allocator_deallocate(allocator, (void*) zone);
    allocator_cleanup(allocator);
    lock_basic_destroy(&zone_lock);
    return;
}


/**
 * Backup zone.
 *
 */
ods_status
zone_backup(zone_type* zone)
{
    char* filename = NULL;
    FILE* fd = NULL;

    ods_log_assert(zone);
    ods_log_assert(zone->zonedata);
    ods_log_assert(zone->signconf);

    filename = ods_build_path(zone->name, ".backup", 0);
    fd = ods_fopen(filename, NULL, "w");
    free((void*)filename);

    if (fd) {
        fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
        /** Backup zone */
        fprintf(fd, ";;Zone: name %s class %i ttl %u inbound %u internal "
            "%u outbound %u\n",
            zone->name?zone->name:"(null)",
            (int) zone->klass,
            (unsigned) zone->default_ttl,
            (unsigned) zone->zonedata->inbound_serial,
            (unsigned) zone->zonedata->internal_serial,
            (unsigned) zone->zonedata->outbound_serial);
        /** Backup task */
        if (zone->task) {
            task_backup(fd, (task_type*) zone->task);
        }
        /** Backup signconf */
        signconf_backup(fd, zone->signconf);
        fprintf(fd, ";;\n");
        /** Backup NSEC3 parameters */
        if (zone->signconf->nsec3params) {
            nsec3params_backup(fd,
                zone->signconf->nsec3_algo,
                zone->signconf->nsec3_optout,
                zone->signconf->nsec3_iterations,
                zone->signconf->nsec3_salt,
                zone->signconf->nsec3params->rr);
        }
        /** Backup keylist */
        keylist_backup(fd, zone->signconf->keys);
        /** Backup domains and stuff */
        zonedata_backup(fd, zone->zonedata);
        /** Done */
        fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
        ods_fclose(fd);
    } else {
        return ODS_STATUS_FOPEN_ERR;
    }
    return ODS_STATUS_OK;
}


/**
 * Recover zone from backup.
 *
 */
ods_status
zone_recover(zone_type* zone)
{
    char* filename = NULL;
    FILE* fd = NULL;
    const char* token = NULL;
    ods_status status = ODS_STATUS_OK;
    /* zone part */
    int klass = 0;
    uint32_t ttl = 0;
    uint32_t inbound = 0;
    uint32_t internal = 0;
    uint32_t outbound = 0;
    /* task part */
    task_type* task = NULL;
    time_t when = 0;
    time_t backoff = 0;
    int what = 0;
    int interrupt = 0;
    int halted = 0;
    int flush = 0;
    /* signconf part */
    time_t lastmod = 0;
    /* nsec3params part */
    const char* salt = NULL;
    ldns_rr* nsec3params_rr = NULL;
    nsec3params_type* nsec3params = NULL;
    /* keys part */
    key_type* key = NULL;
    /* zonedata part */
    int fetch = 0;

    ods_log_assert(zone);
    ods_log_assert(zone->signconf);
    ods_log_assert(zone->zonedata);

    filename = ods_build_path(zone->name, ".backup", 0);
    fd = ods_fopen(filename, NULL, "r");
    free((void*)filename);
    if (fd) {
        /* start recovery */
        if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC) ||
            /* zone part */
            !backup_read_check_str(fd, ";;Zone:") ||
            !backup_read_check_str(fd, "name") ||
            !backup_read_check_str(fd, zone->name) ||
            !backup_read_check_str(fd, "class") ||
            !backup_read_int(fd, &klass) ||
            !backup_read_check_str(fd, "ttl") ||
            !backup_read_uint32_t(fd, &ttl) ||
            !backup_read_check_str(fd, "inbound") ||
            !backup_read_uint32_t(fd, &inbound) ||
            !backup_read_check_str(fd, "internal") ||
            !backup_read_uint32_t(fd, &internal) ||
            !backup_read_check_str(fd, "outbound") ||
            !backup_read_uint32_t(fd, &outbound) ||
            /* task part */
            !backup_read_check_str(fd, ";;Task:") ||
            !backup_read_check_str(fd, "when") ||
            !backup_read_time_t(fd, &when) ||
            !backup_read_check_str(fd, "what") ||
            !backup_read_int(fd, &what) ||
            !backup_read_check_str(fd, "interrupt") ||
            !backup_read_int(fd, &interrupt) ||
            !backup_read_check_str(fd, "halted") ||
            !backup_read_int(fd, &halted) ||
            !backup_read_check_str(fd, "backoff") ||
            !backup_read_time_t(fd, &backoff) ||
            !backup_read_check_str(fd, "flush") ||
            !backup_read_int(fd, &flush) ||
            /* signconf part */
            !backup_read_check_str(fd, ";;Signconf:") ||
            !backup_read_check_str(fd, "lastmod") ||
            !backup_read_time_t(fd, &lastmod) ||
            !backup_read_check_str(fd, "resign") ||
            !backup_read_duration(fd,
                &zone->signconf->sig_resign_interval) ||
            !backup_read_check_str(fd, "refresh") ||
            !backup_read_duration(fd,
                &zone->signconf->sig_refresh_interval) ||
            !backup_read_check_str(fd, "valid") ||
            !backup_read_duration(fd,
                &zone->signconf->sig_validity_default) ||
            !backup_read_check_str(fd, "denial") ||
            !backup_read_duration(fd,
                &zone->signconf->sig_validity_denial) ||
            !backup_read_check_str(fd, "jitter") ||
            !backup_read_duration(fd, &zone->signconf->sig_jitter) ||
            !backup_read_check_str(fd, "offset") ||
            !backup_read_duration(fd,
                &zone->signconf->sig_inception_offset) ||
            !backup_read_check_str(fd, "nsec") ||
            !backup_read_rr_type(fd, &zone->signconf->nsec_type) ||
            !backup_read_check_str(fd, "dnskeyttl") ||
            !backup_read_duration(fd, &zone->signconf->dnskey_ttl) ||
            !backup_read_check_str(fd, "soattl") ||
            !backup_read_duration(fd, &zone->signconf->soa_ttl) ||
            !backup_read_check_str(fd, "soamin") ||
            !backup_read_duration(fd, &zone->signconf->soa_min) ||
            !backup_read_check_str(fd, "serial") ||
            !backup_read_str(fd, &zone->signconf->soa_serial) ||
            !backup_read_check_str(fd, "audit") ||
            !backup_read_int(fd, &zone->signconf->audit) ||
            !backup_read_check_str(fd, ";;")) {
            goto recover_error;
        }
        /* nsec3params part */
        if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
             if (!backup_read_check_str(fd, ";;Nsec3parameters:") ||
                 !backup_read_check_str(fd, "salt") ||
                 !backup_read_str(fd, &salt) ||
                 !backup_read_check_str(fd, "algorithm") ||
                 !backup_read_uint32_t(fd, &zone->signconf->nsec3_algo) ||
                 !backup_read_check_str(fd, "optout") ||
                 !backup_read_int(fd, &zone->signconf->nsec3_optout) ||
                 !backup_read_check_str(fd, "iterations") ||
                 !backup_read_uint32_t(fd,
                     &zone->signconf->nsec3_iterations) ||
                 ldns_rr_new_frm_fp(&nsec3params_rr, fd, NULL, NULL, NULL) ||
                 !backup_read_check_str(fd, ";;Nsec3done") ||
                 !backup_read_check_str(fd, ";;")) {
                 goto recover_error;
            }
        }
        /* keys part */
        zone->signconf->keys = keylist_create((void*) zone->signconf);
        while (backup_read_str(fd, &token)) {
            if (ods_strcmp(token, ";;Key:") == 0) {
                key = key_recover(fd, zone->signconf->keys);
                if (!key) {
                    goto recover_error;
                }
                key = NULL;
            } else if (ods_strcmp(token, ";;") == 0) {
                /* keylist done */
                free((void*) token);
                token = NULL;
                break;
            } else {
                /* keylist corrupted */
                goto recover_error;
            }
            free((void*) token);
            token = NULL;
        }
        /* zonedata part */
        filename = ods_build_path(zone->name, ".inbound", 0);
        status = adbackup_read(zone, filename);
        free((void*)filename);
        if (status != ODS_STATUS_OK) {
            goto recover_error;
        }

        zone->klass = (ldns_rr_class) klass;
        zone->default_ttl = ttl;
        zone->zonedata->inbound_serial = inbound;
        zone->zonedata->internal_serial = internal;
        zone->zonedata->outbound_serial = outbound;
        zone->signconf->nsec3_salt = allocator_strdup(
            zone->signconf->allocator, salt);
        free((void*) salt);
        salt = NULL;
        task = task_create((task_id) what, when, (void*) zone);
        if (!task) {
            goto recover_error;
        }
        if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
            nsec3params = nsec3params_create((void*) zone->signconf,
                zone->signconf->nsec3_algo,
                zone->signconf->nsec3_optout,
                zone->signconf->nsec3_iterations,
                zone->signconf->nsec3_salt);
            if (!nsec3params) {
                goto recover_error;
            }
            nsec3params->rr = nsec3params_rr;
            zone->signconf->nsec3params = nsec3params;
        }
        zone->task = (void*) task;
        zone->signconf->last_modified = lastmod;

        status = zone_publish_dnskeys(zone);
        if (status != ODS_STATUS_OK) {
            zone->task = NULL;
            goto recover_error;
        }
        status = zone_publish_nsec3param(zone, 1);
        if (status != ODS_STATUS_OK) {
            zone->task = NULL;
            goto recover_error;
        }
        status = zonedata_commit(zone->zonedata);
        if (status != ODS_STATUS_OK) {
            zone->task = NULL;
            goto recover_error;
        }
        status = zonedata_entize(zone->zonedata, zone->apex);
        if (status != ODS_STATUS_OK) {
            zone->task = NULL;
            zone->signconf->nsec3params = NULL;
            goto recover_error;
        }
        status = zonedata_recover(zone->zonedata, fd);
        if (status != ODS_STATUS_OK) {
            zone->task = NULL;
            zone->signconf->nsec3params = NULL;
            goto recover_error;
        }
        ods_fclose(fd);

        /* all ok */
        zone->zonedata->initialized = 1;
        if (zone->stats) {
            lock_basic_lock(&zone->stats->stats_lock);
            stats_clear(zone->stats);
            lock_basic_unlock(&zone->stats->stats_lock);
        }
        return ODS_STATUS_OK;
    } else {
        /* backwards compatible backup recovery (serial) */
        filename = ods_build_path(zone->name, ".state", 0);
        fd = ods_fopen(filename, NULL, "r");
        free((void*)filename);
        if (fd) {
            if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC_V1) ||
                !backup_read_check_str(fd, ";name:") ||
                !backup_read_check_str(fd, zone->name) ||
                !backup_read_check_str(fd, ";class:") ||
                !backup_read_int(fd, &klass) ||
                !backup_read_check_str(fd, ";fetch:") ||
                !backup_read_int(fd, &fetch) ||
                !backup_read_check_str(fd, ";default_ttl:") ||
                !backup_read_uint32_t(fd, &ttl) ||
                !backup_read_check_str(fd, ";inbound_serial:") ||
                !backup_read_uint32_t(fd, &inbound) ||
                !backup_read_check_str(fd, ";internal_serial:") ||
                !backup_read_uint32_t(fd, &internal) ||
                !backup_read_check_str(fd, ";outbound_serial:") ||
                !backup_read_uint32_t(fd, &outbound) ||
                !backup_read_check_str(fd, ODS_SE_FILE_MAGIC_V1))
            {
                goto recover_error;
            }
            zone->klass = (ldns_rr_class) klass;
            zone->default_ttl = ttl;
            zone->zonedata->inbound_serial = inbound;
            zone->zonedata->internal_serial = internal;
            zone->zonedata->outbound_serial = outbound;
            /* all ok */
            zone->zonedata->initialized = 1;
            if (zone->stats) {
                lock_basic_lock(&zone->stats->stats_lock);
                stats_clear(zone->stats);
                lock_basic_unlock(&zone->stats->stats_lock);
            }
            return ODS_STATUS_UNCHANGED;
        }
        ods_fclose(fd);
    }

    return ODS_STATUS_UNCHANGED;

recover_error:
    ods_log_error("[%s] unable to recover zone %s: corrupted file",
        zone_str, zone->name);
    ods_fclose(fd);

    /* signconf cleanup */
    signconf_cleanup(zone->signconf);
    zone->signconf = signconf_create();
    ods_log_assert(zone->signconf);

    /* task cleanup */
    task_cleanup(task);
    task = NULL;

    /* nsec3params cleanup */
    free((void*)salt);
    salt = NULL;

    ldns_rr_free(nsec3params_rr);
    nsec3params_rr = NULL;
    nsec3params_cleanup(nsec3params);
    nsec3params = NULL;

    /* zonedata cleanup */
    zonedata_cleanup(zone->zonedata);
    zone->zonedata = zonedata_create(zone->allocator);
    ods_log_assert(zone->zonedata);

    if (zone->stats) {
       lock_basic_lock(&zone->stats->stats_lock);
       stats_clear(zone->stats);
       lock_basic_unlock(&zone->stats->stats_lock);
    }
    return ODS_STATUS_ERR;
}
