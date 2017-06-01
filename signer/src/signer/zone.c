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
#include "signer/backup.h"
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
    zone->rrstore = rrset_store_initialize();
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
    rrset_type* rrset = NULL;
    rr_type* dnskey = NULL;

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
                rrset = zone_lookup_rrset(view, LDNS_RR_TYPE_DNSKEY);
                ods_log_assert(rrset);
                dnskey = rrset_lookup_rr(rrset,
                    zone->signconf->keys->keys[i].dnskey);
                ods_log_assert(dnskey);
                if (dnskey->rr != zone->signconf->keys->keys[i].dnskey) {
                    ldns_rr_free(zone->signconf->keys->keys[i].dnskey);
                }
                zone->signconf->keys->keys[i].dnskey = dnskey->rr;
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
    rrset_type* rrset = NULL;
    rr_type* n3prr = NULL;
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


/**
 * Update serial.
 *
 */
ods_status
zone_update_serial(zone_type* zone, names_view_type view)
{
    ods_status status = ODS_STATUS_OK;
    rrset_type* rrset = NULL;
    rr_type* soa = NULL;
    ldns_rr* rr = NULL;
    ldns_rdf* soa_rdata = NULL;

    ods_log_assert(zone);
    ods_log_assert(zone->apex);
    ods_log_assert(zone->name);
    ods_log_assert(zone->signconf);

    rrset = zone_lookup_rrset(view, LDNS_RR_TYPE_SOA);
    if (!rrset || !rrset->rrs || !rrset->rrs[0].rr) {
        ods_log_error("[%s] unable to update zone %s soa serial: failed to "
            "find soa rrset", zone_str, zone->name);
        return ODS_STATUS_ERR;
    }
    ods_log_assert(rrset);
    ods_log_assert(rrset->rrs);
    ods_log_assert(rrset->rrs[0].rr);
    rr = ldns_rr_clone(rrset->rrs[0].rr);
    if (!rr) {
        ods_log_error("[%s] unable to update zone %s soa serial: failed to "
            "clone soa rr", zone_str, zone->name);
        return ODS_STATUS_ERR;
    }
    status = namedb_update_serial(zone, zone->name,
        zone->signconf->soa_serial, *zone->inboundserial);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to update zone %s soa serial: %s",
            zone_str, zone->name, ods_status2str(status));
        if (status == ODS_STATUS_CONFLICT_ERR) {
            ods_log_error("[%s] If this is the result of a key rollover, "
                "please increment the serial in the unsigned zone %s",
                zone_str, zone->name);
        }
        ldns_rr_free(rr);
        return status;
    }
    soa_rdata = ldns_rr_set_rdf(rr,
        ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32,
        *zone->outboundserial), SE_SOA_RDATA_SERIAL);
    if (soa_rdata) {
        ldns_rdf_deep_free(soa_rdata);
        soa_rdata = NULL;
    } else {
        ods_log_error("[%s] unable to update zone %s soa serial: failed to "
            "replace soa serial rdata", zone_str, zone->name);
        ldns_rr_free(rr);
        return ODS_STATUS_ERR;
    }
    soa = rrset_add_rr(rrset, rr);
    ods_log_assert(soa);
    return ODS_STATUS_OK;
}


/**
 * Lookup RRset.
 *
 */
rrset_type*
zone_lookup_rrset(names_view_type view, ldns_rr_type type)
{
    domain_type* domain = NULL;
    if (!type) {
        return NULL;
    }
    return domain_lookup_rrset(domain, type);
}


/**
 * Add RR.
 *
 */
ods_status
zone_add_rr(zone_type* zone, names_view_type view, ldns_rr* rr, int do_stats)
{
    domain_type* domain = NULL;
    rrset_type* rrset = NULL;
    rr_type* record = NULL;
    ods_status status = ODS_STATUS_OK;
    char* str = NULL;
    int i;

    ods_log_assert(rr);
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->signconf);
    /* If we already have this RR, return ODS_STATUS_UNCHANGED */
    domain = names_lookupname(view, ldns_rr_owner(rr));
    if (!domain) {
        domain = names_addname(view, ldns_rr_owner(rr));
        if (!domain) {
            ods_log_error("[%s] unable to add RR to zone %s: "
                "failed to add domain", zone_str, zone->name);
            return ODS_STATUS_ERR;
        }
        if (ldns_dname_compare(domain->dname, zone->apex) == 0) {
            domain->is_apex = 1;
        } else {
            status = namedb_domain_entize(view, domain, zone->apex);
            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to add RR to zone %s: "
                    "failed to entize domain", zone_str, zone->name);
                return ODS_STATUS_ERR;
            }
        }
    }
    rrset = domain_lookup_rrset(domain, ldns_rr_get_type(rr));
    if (!rrset) {
        rrset = rrset_create(zone, ldns_rr_get_type(rr));
        if (!rrset) {
            ods_log_error("[%s] unable to add RR to zone %s: "
                "failed to add RRset", zone_str, zone->name);
            return ODS_STATUS_ERR;
        }
        domain_add_rrset(domain, rrset);
    }
    record = rrset_lookup_rr(rrset, rr);

    if (record && ldns_rr_ttl(rr) != ldns_rr_ttl(record->rr))
        record = NULL;

    if (record) {
        record->is_added = 1; /* already exists, just mark added */
        record->is_removed = 0; /* unset is_removed */
        return ODS_STATUS_UNCHANGED;
    } else {
        record = rrset_add_rr(rrset, rr);
        ods_log_assert(record);
        ods_log_assert(record->rr);
        ods_log_assert(record->is_added);
        if (ldns_rr_ttl(rr) != ldns_rr_ttl(rrset->rrs[0].rr)) {
            str = ldns_rr2str(rr);
            str[(strlen(str)) - 1] = '\0';
            for (i = 0; i < strlen(str); i++) {
                if (str[i] == '\t') {
                    str[i] = ' ';
                }
            }
            ods_log_error("In zone file %s: TTL for the record '%s' set to %d", zone->name, str, ldns_rr_ttl(rrset->rrs[0].rr));
            LDNS_FREE(str);
            ldns_rr_set_ttl(rr,ldns_rr_ttl(rrset->rrs[0].rr));
        }
    }
    /* update stats */
    if (do_stats && zone->stats) {
        zone->stats->sort_count += 1;
    }
    return ODS_STATUS_OK;
}


/**
 * Delete RR.
 *
 */
ods_status
zone_del_rr(zone_type* zone, names_view_type view, ldns_rr* rr, int do_stats)
{
    domain_type* domain = NULL;
    rrset_type* rrset = NULL;
    rr_type* record = NULL;
    ods_log_assert(rr);
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->signconf);
    domain = names_lookupname(view, ldns_rr_owner(rr));
    if (!domain) {
        ods_log_warning("[%s] unable to delete RR from zone %s: "
            "domain not found", zone_str, zone->name);
        return ODS_STATUS_UNCHANGED;
    }
    rrset = domain_lookup_rrset(domain, ldns_rr_get_type(rr));
    if (!rrset) {
        ods_log_warning("[%s] unable to delete RR from zone %s: "
            "RRset not found", zone_str, zone->name);
        return ODS_STATUS_UNCHANGED;
    }
    record = rrset_lookup_rr(rrset, rr);
    if (!record) {
        ods_log_error("[%s] unable to delete RR from zone %s: "
            "RR not found", zone_str, zone->name);
        return ODS_STATUS_UNCHANGED;
    }

    record->is_removed = 1;
    record->is_added = 0; /* unset is_added */
    /* update stats */
    if (do_stats && zone->stats) {
        zone->stats->sort_count -= 1;
    }
    return ODS_STATUS_OK;
}

/**
 * Delete NSEC3PARAM RRs.
 *
 * Marks all NSEC3PARAM records as removed.
 */
ods_status
zone_del_nsec3params(zone_type* zone, names_view_type view)
{
    domain_type* domain = NULL;
    rrset_type* rrset = NULL;
    int i;

    ods_log_assert(zone);
    ods_log_assert(zone->name);

    domain = names_lookupname(view, zone->apex);
    if (!domain) {
        ods_log_verbose("[%s] unable to delete RR from zone %s: "
            "domain not found", zone_str, zone->name);
        return ODS_STATUS_UNCHANGED;
    }

    rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_NSEC3PARAMS);
    if (!rrset) {
        ods_log_verbose("[%s] NSEC3PARAM in zone %s not found: "
            "skipping delete", zone_str, zone->name);
        return ODS_STATUS_UNCHANGED;
    }

    /* We don't actually delete the record as we still need the
     * information in the IXFR. Just set it as removed. The code
     * inserting the new record may flip this flag when the record
     * hasn't changed. */
    for (i=0; i < rrset->rr_count; i++) {
        rrset->rrs[i].is_removed = 1;
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
    collection_class_destroy(&zone->rrstore);
    pthread_mutex_destroy(&zone->xfr_lock);
    pthread_mutex_destroy(&zone->zone_lock);
    free(zone);
}
