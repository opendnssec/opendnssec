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
#include "signer/nsec3params.h"
#include "signer/signconf.h"
#include "signer/zone.h"
#include "signer/zonedata.h"

#include <ldns/ldns.h>

static const char* zone_str = "zone";


/**
 * Create a new zone.
 *
 */
zone_type*
zone_create(const char* name, ldns_rr_class klass)
{
    allocator_type* allocator = NULL;
    zone_type* zone = NULL;

    if (!name || !klass) {
        ods_log_error("[%s] unable to create zone: no name or class",
            zone_str);
        return NULL;
    }

    allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] unable to create zone %s: create allocator "
            "failed", zone_str, name);
        return NULL;
    }
    ods_log_assert(allocator);

    zone = (zone_type*) allocator_alloc(allocator, sizeof(zone_type));
    if (!zone) {
        ods_log_error("[%s] unable to create zone %s: allocator failed",
            zone_str, name);
        allocator_cleanup(allocator);
        return NULL;
    }
    ods_log_assert(zone);

    zone->allocator = allocator;
    zone->name = allocator_strdup(allocator, name);
    zone->klass = klass;

    zone->dname = ldns_dname_new_frm_str(name);
    ldns_dname2canonical(zone->dname);
    zone->notify_ns = NULL;
    zone->policy_name = NULL;
    zone->signconf_filename = NULL;

    zone->adinbound = NULL;
    zone->adoutbound = NULL;
    zone->nsec3params = NULL;

    zone->just_added = 0;
    zone->just_updated = 0;
    zone->tobe_removed = 0;
    zone->processed = 0;
    zone->fetch = 0;

    zone->zonedata = zonedata_create(zone->allocator);
    if (!zone->zonedata) {
        ods_log_error("[%s] unable to create zone %s: create zonedata "
            "failed", zone_str, name);
        allocator_deallocate(allocator);
        allocator_cleanup(allocator);
    }

    zone->signconf = signconf_create();
    if (!zone->signconf) {
        ods_log_error("[%s] unable to create zone %s: create signconf "
            "failed", zone_str, name);
        allocator_deallocate(allocator);
        allocator_cleanup(allocator);
        return NULL;
    }

    zone->stats = stats_create();
    zone->task = NULL;
    lock_basic_init(&zone->zone_lock);
    return zone;
}


/**
 * Withdraw DNSKEYs.
 *
 */
static ods_status
dnskey_withdraw(zone_type* zone, ldns_rr_list* del)
{
    ldns_rr* clone = NULL;
    ods_status status = ODS_STATUS_OK;
    size_t i = 0;

    for (i=0; i < ldns_rr_list_rr_count(del); i++) {
        clone = ldns_rr_clone(ldns_rr_list_rr(del, i));
        status = adapi_del_rr(zone, clone);
        if (status != ODS_STATUS_OK) {
            return status;
        }
    }
    return status;
}


/**
 * Load signer configuration for zone.
 *
 */
ods_status
zone_load_signconf(zone_type* zone, task_id* tbs)
{
    ods_status status = ODS_STATUS_OK;
    signconf_type* signconf = NULL;
    ldns_rr_list* del = NULL;
    char* datestamp = NULL;
    uint32_t ustamp = 0;
    task_id denial_what;
    task_id keys_what;
    task_id what;

    if (!zone) {
        ods_log_error("[%s] unable to load signconf: no zone", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);
    if (!zone->signconf_filename) {
        ods_log_warning("[%s] zone %s has no signconf filename, treat as "
            "insecure?", zone_str, zone->name);
        return ODS_STATUS_INSECURE;
    }
    ods_log_assert(zone->signconf_filename);

    status = signconf_update(&signconf, zone->signconf_filename,
        zone->signconf->last_modified);
    if (status == ODS_STATUS_OK) {
        if (!signconf) {
            /* this is unexpected */
            ods_log_error("[%s] unable to load signconf: zone %s signconf "
                "%s: storage empty", zone_str, zone->name,
                zone->signconf_filename);
            return ODS_STATUS_ASSERT_ERR;
        }
        ustamp = time_datestamp(signconf->last_modified, "%Y-%m-%d %T",
            &datestamp);
        ods_log_debug("[%s] zone %s signconf file %s is modified since %s",
            zone_str, zone->name, zone->signconf_filename,
            datestamp?datestamp:"Unknown");
        free((void*)datestamp);

        /* do stuff */
        del = ldns_rr_list_new();
        if (!del) {
            ods_log_error("[%s] unable to load signconf: zone %s "
                "signconf %s: ldns_rr_list_new() failed",
                zone_str, zone->name, zone->signconf_filename);
            return ODS_STATUS_MALLOC_ERR;
        }
        denial_what = signconf_compare_denial(zone->signconf, signconf);
        keys_what = signconf_compare_keys(zone->signconf, signconf, del);

        /* Key Rollover? */
        if (keys_what == TASK_READ) {
            status = dnskey_withdraw(zone, del);
        }
        ldns_rr_list_free(del);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to load signconf: zone %s "
                "signconf %s: failed to delete DNSKEY from RRset",
                zone_str, zone->name, zone->signconf_filename);
            zonedata_rollback(zone->zonedata);
            return status;
        }

        /* Denial of Existence Rollover? */
        if (denial_what == TASK_NSECIFY) {
            /* or NSEC -> NSEC3, or NSEC3 -> NSEC, or NSEC3PARAM changed */
            nsec3params_cleanup(zone->nsec3params);
            zone->nsec3params = NULL;
            /* all NSEC(3)s become invalid */
            zonedata_wipe_denial(zone->zonedata);
        }

        /* all ok, switch to new signconf */
        if (keys_what != TASK_NONE) {
            what = keys_what;
        } else {
            what = denial_what;
        }
        if (what == TASK_NONE) { /* no major changes, continue signing */
            what = TASK_SIGN;
        }
        *tbs = what;
        ods_log_debug("[%s] tbs for zone %s set to: %s", zone_str,
            zone->name, task_what2str(*tbs));
        signconf_cleanup(zone->signconf);
        zone->signconf = signconf;
        signconf_log(zone->signconf, zone->name);
    } else if (status == ODS_STATUS_UNCHANGED) {
        ustamp = time_datestamp(zone->signconf->last_modified,
            "%Y-%m-%d %T", &datestamp);
        ods_log_verbose("[%s] zone %s signconf file %s is unchanged since "
            "%s", zone_str, zone->name, zone->signconf_filename,
            datestamp?datestamp:"Unknown");
        free((void*)datestamp);
    } else {
        ods_log_error("[%s] unable to load signconf: zone %s signconf %s: "
            "%s", zone_str, zone->name, zone->signconf_filename,
            ods_status2str(status));
    }
    return status;
}


/**
 * Publish DNSKEYs.
 *
 */
ods_status
zone_publish_dnskeys(zone_type* zone)
{
    hsm_ctx_t* ctx = NULL;
    key_type* key = NULL;
    uint32_t ttl = 0;
    size_t count = 0;
    ods_status status = ODS_STATUS_OK;
    ldns_rr* dnskey = NULL;

    if (!zone) {
        ods_log_error("[%s] unable to publish dnskeys: no zone", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);

    if (!zone->signconf) {
        ods_log_error("[%s] unable to publish dnskeys zone %s: no signconf",
            zone_str, zone->name);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->signconf);

    if (!zone->signconf->keys) {
        ods_log_error("[%s] unable to publish dnskeys zone %s: no keys",
            zone_str, zone->name);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->signconf->keys);

    if (!zone->zonedata) {
        ods_log_error("[%s] unable to publish dnskeys zone %s: no zonedata",
            zone_str, zone->name);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->zonedata);

    ttl = zone->zonedata->default_ttl;
    if (zone->signconf->dnskey_ttl) {
        ttl = (uint32_t) duration2time(zone->signconf->dnskey_ttl);
    }

    key = zone->signconf->keys->first_key;
    for (count=0; count < zone->signconf->keys->count; count++) {
        if (key->publish && !key->dnskey) {
            status = lhsm_get_key(ctx, zone->dname, key);
            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to publish dnskeys zone %s: "
                    "error creating DNSKEY for key %s", zone_str,
                    zone->name, key->locator?key->locator:"(null)");
                break;
            }
            ods_log_assert(key->dnskey);
            ldns_rr_set_ttl(key->dnskey, ttl);
            ldns_rr_set_class(key->dnskey, zone->klass);
            ldns_rr2canonical(key->dnskey);
            dnskey = ldns_rr_clone(key->dnskey);
            status = adapi_add_rr(zone, dnskey);
            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to publish dnskeys zone %s: "
                    "error adding DNSKEY[%u] for key %s", zone_str,
                    zone->name, ldns_calc_keytag(dnskey),
                    key->locator?key->locator:"(null)");
                break;
            }
        }
        key = key->next;
    }
    if (status != ODS_STATUS_OK) {
        zonedata_rollback(zone->zonedata);
    }
    return status;
}


/**
 * Prepare for NSEC3.
 *
 */
ods_status
zone_prepare_nsec3(zone_type* zone)
{
    ldns_rr* nsec3params_rr = NULL;
    domain_type* apex = NULL;
    rrset_type* rrset = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!zone) {
        ods_log_error("[%s] unable to prepare NSEC3: no zone", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);

    if (!zone->signconf) {
        ods_log_error("[%s] unable to prepare NSEC3: no signconf", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone->signconf);

    if (zone->signconf->nsec_type != LDNS_RR_TYPE_NSEC3) {
        /* no preparations needed */
        return ODS_STATUS_OK;
    }

    if (!zone->nsec3params) {
        ods_log_debug("[%s] prepare NSEC3 for zone %s", zone_str, zone->name);

        zone->nsec3params = nsec3params_create(
            (uint8_t) zone->signconf->nsec3_algo,
            (uint8_t) zone->signconf->nsec3_optout,
            (uint16_t) zone->signconf->nsec3_iterations,
            zone->signconf->nsec3_salt);
    }
    if (!zone->nsec3params) {
        ods_log_error("[%s] unable to prepare zone %s for NSEC3: failed "
            "to create NSEC3 parameters", zone_str, zone->name);
        return ODS_STATUS_MALLOC_ERR;
    }
    ods_log_assert(zone->nsec3params);

    nsec3params_rr = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3PARAMS);
    if (!nsec3params_rr) {
        ods_log_error("[%s] unable to prepare zone %s for NSEC3: failed "
            "to create NSEC3PARAM RR", zone_str, zone->name);
        nsec3params_cleanup(zone->nsec3params);
        return ODS_STATUS_MALLOC_ERR;
    }
    ods_log_assert(nsec3params_rr);

    ldns_rr_set_class(nsec3params_rr, zone->klass);
    ldns_rr_set_ttl(nsec3params_rr, zone->zonedata->default_ttl);
    ldns_rr_set_owner(nsec3params_rr, ldns_rdf_clone(zone->dname));
    ldns_nsec3_add_param_rdfs(nsec3params_rr,
        zone->nsec3params->algorithm, 0,
        zone->nsec3params->iterations,
        zone->nsec3params->salt_len,
        zone->nsec3params->salt_data);
    /**
     * Always set bit 7 of the flags to zero,
     * according to rfc5155 section 11
     */
    ldns_set_bit(ldns_rdf_data(ldns_rr_rdf(nsec3params_rr, 1)), 7, 0);

    ldns_rr2canonical(nsec3params_rr);
    status = adapi_add_rr(zone, nsec3params_rr);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to add NSEC3PARAM RR to zone %s",
            zone_str, zone->name);
        nsec3params_cleanup(zone->nsec3params);
        ldns_rr_free(nsec3params_rr);
    } else {
        /* add ok, wipe out previous nsec3params */
        apex = zonedata_lookup_domain(zone->zonedata, zone->dname);
        if (!apex) {
            ods_log_crit("[%s] unable to delete previous NSEC3PARAM RR "
            "from zone %s: apex undefined", zone_str, zone->name);
            nsec3params_cleanup(zone->nsec3params);
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
                nsec3params_cleanup(zone->nsec3params);
                rrset_rollback(rrset);
                return status;
            }
        }
    }
    return status;
}


/**
 * Sign zone.
 *
 */
int
zone_sign(zone_type* zone)
{
    int error = 0;
    FILE* fd = NULL;
    char* filename = NULL;
    time_t start = 0;
    time_t end = 0;

    ods_log_assert(zone);
    ods_log_assert(zone->signconf);
    ods_log_assert(zone->zonedata);
    ods_log_assert(zone->stats);

    zone->stats->sig_count = 0;
    zone->stats->sig_reuse = 0;
    zone->stats->sig_time = 0;
    start = time(NULL);

    error = zonedata_sign(zone->zonedata, zone->dname, zone->signconf,
        zone->stats);
    if (!error) {
        end = time(NULL);
        zone->stats->sig_time = (end-start);

/*
        filename = ods_build_path(zone->name, ".rrsigs", 0);
        fd = ods_fopen(filename, NULL, "w");
        if (fd) {
            fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
            zonedata_print_rrsig(fd, zone->zonedata);
            fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
            ods_fclose(fd);
        } else {
            ods_log_warning("[%s] cannot backup RRSIG records: cannot open file "
                "%s for writing", zone_str, filename?filename:"(null)");
        }
        free((void*)filename);
*/
    }
    return error;
}


/**
 * Backup zone data.
 * \param[in] zone corresponding zone
 * \return int 0 on success, 1 on error
 *
 */
int zone_backup_state(zone_type* zone)
{
    int error = 0;
    char* filename = NULL;
    FILE* fd = NULL;

    ods_log_assert(zone);
    ods_log_assert(zone->zonedata);
    ods_log_assert(zone->signconf);

    filename = ods_build_path(zone->name, ".state", 0);
    fd = ods_fopen(filename, NULL, "w");
    if (fd) {
        fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
        fprintf(fd, ";name: %s\n", zone->name?zone->name:"(null)");
        fprintf(fd, ";class: %i\n", (int) zone->klass);
        fprintf(fd, ";fetch: %i\n", (int) zone->fetch);
        fprintf(fd, ";default_ttl: %u\n", zone->zonedata->default_ttl);
        fprintf(fd, ";inbound_serial: %u\n", zone->zonedata->inbound_serial);
        fprintf(fd, ";internal_serial: %u\n", zone->zonedata->internal_serial);
        fprintf(fd, ";outbound_serial: %u\n", zone->zonedata->outbound_serial);
        fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
        ods_fclose(fd);
    } else {
        ods_log_error("[%s] cannot backup zone: cannot open file "
        "%s for writing", zone_str, filename?filename:"(null)");
        return 1;
    }
    free((void*)filename);

    return error;
}


/**
 * Recover DNSKEYs and NSEC3PARAMS.
 *
 */
static int
zone_recover_dnskeys_from_backup(zone_type* zone, FILE* fd)
{
    int corrupted = 0;
    const char* token = NULL;
    key_type* key = NULL;
    ldns_rr* rr = NULL;

    if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC)) {
        corrupted = 1;
    }

    while (!corrupted) {
        if (backup_read_str(fd, &token)) {
            if (ods_strcmp(token, ";DNSKEY") == 0) {
                key = key_recover_from_backup(fd);
                if (!key || keylist_push(zone->signconf->keys, key) !=
                    ODS_STATUS_OK) {
                    ods_log_error("[%s] error adding key from backup file "
                        "%s.dnskeys to key list", zone_str, zone->name);
                    corrupted = 1;
                } else {
                   rr = ldns_rr_clone(key->dnskey);
                   corrupted = adapi_add_rr(zone, rr);
                   if (corrupted) {
                       ods_log_error("[%s] error recovering DNSKEY[%u] rr",
                          zone_str, ldns_calc_keytag(rr));
                   }
                   rr = NULL;
                }
                key = NULL;
            } else if (ods_strcmp(token, ";NSEC3PARAMS") == 0) {
                zone->nsec3params = nsec3params_recover_from_backup(fd,
                    &rr);
                if (!zone->nsec3params) {
                    ods_log_error("[%s] error recovering nsec3 parameters from file "
                        "%s.dnskeys", zone_str, zone->name);
                    corrupted = 1;
                } else {
                    corrupted = adapi_add_rr(zone, rr);
                    if (corrupted) {
                       ods_log_error("[%s] error recovering NSEC3PARAMS rr", zone_str);
                    } else {
                        zone->signconf->nsec3_optout =
                            (int) zone->nsec3params->flags;
                        zone->signconf->nsec3_algo =
                            (uint32_t) zone->nsec3params->algorithm;
                        zone->signconf->nsec3_iterations =
                            (uint32_t) zone->nsec3params->iterations;
                        zone->signconf->nsec3_salt =
                            nsec3params_salt2str(zone->nsec3params);
                   }
                }
                rr = NULL;
            } else if (ods_strcmp(token, ODS_SE_FILE_MAGIC) == 0) {
                free((void*) token);
                token = NULL;
                break;
            } else {
                corrupted = 1;
            }
            free((void*) token);
            token = NULL;
        } else {
            corrupted = 1;
        }
    }
    return corrupted;
}


/**
 * Recover RRSIGS.
 *
 */
static int
zone_recover_rrsigs_from_backup(zone_type* zone, FILE* fd)
{
    int corrupted = 0;
    const char* token = NULL;
    const char* locator = NULL;
    uint32_t flags = 0;
    ldns_rr* rr = NULL;
    ldns_status status = LDNS_STATUS_OK;

    if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC)) {
        corrupted = 1;
    }

    while (!corrupted) {
        if (backup_read_str(fd, &token)) {
            if (ods_strcmp(token, ";RRSIG") == 0) {
                if (!backup_read_str(fd, &locator) ||
                    !backup_read_uint32_t(fd, &flags)) {

                    ods_log_error("[%s] error reading key credentials from backup",
                        zone_str);
                    corrupted = 1;
                } else {
                    status = ldns_rr_new_frm_fp(&rr, fd, NULL, NULL, NULL);
                   if (status != LDNS_STATUS_OK) {
                       ods_log_error("[%s] error reading RRSIG from backup", zone_str);
                       corrupted = 1;
                    } else if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_RRSIG) {
                       ods_log_error("[%s] expecting RRtype RRSIG from backup", zone_str);
                       corrupted = 1;
                       ldns_rr_free(rr);
                       rr = NULL;
                    } else {
                       corrupted = zonedata_recover_rrsig_from_backup(
                           zone->zonedata, rr, locator, flags);
                    }
                }
            } else if (ods_strcmp(token, ODS_SE_FILE_MAGIC) == 0) {
                free((void*) token);
                token = NULL;
                break;
            } else {
                corrupted = 1;
            }
            free((void*) token);
            token = NULL;
        } else {
            corrupted = 1;
        }

        /* reset */
        if (locator) {
            free((void*) locator);
            locator = NULL;
        }
        rr = NULL;
        flags = 0;
        status = LDNS_STATUS_OK;
    }
    return corrupted;
}


/**
 * Recover from backup.
 *
 */
void
zone_recover_from_backup(zone_type* zone, struct schedule_struct* tl)
{
    int klass = 0;
    int fetch = 0;
    int error = 0;
    char* filename = NULL;
    task_type* task = NULL;
    time_t now = 0;
    FILE* fd = NULL;
    ods_status status = ODS_STATUS_OK;

    ods_log_assert(zone);
    ods_log_assert(zone->zonedata);

    filename = ods_build_path(zone->name, ".state", 0);
    fd = ods_fopen(filename, NULL, "r");
    free((void*)filename);
    if (fd) {
        if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC) ||
            !backup_read_check_str(fd, ";name:") ||
            !backup_read_check_str(fd, zone->name) ||
            !backup_read_check_str(fd, ";class:") ||
            !backup_read_int(fd, &klass) ||
            !backup_read_check_str(fd, ";fetch:") ||
            !backup_read_int(fd, &fetch) ||
            !backup_read_check_str(fd, ";default_ttl:") ||
            !backup_read_uint32_t(fd, &zone->zonedata->default_ttl) ||
            !backup_read_check_str(fd, ";inbound_serial:") ||
            !backup_read_uint32_t(fd, &zone->zonedata->inbound_serial) ||
            !backup_read_check_str(fd, ";internal_serial:") ||
            !backup_read_uint32_t(fd, &zone->zonedata->internal_serial) ||
            !backup_read_check_str(fd, ";outbound_serial:") ||
            !backup_read_uint32_t(fd, &zone->zonedata->outbound_serial) ||
            !backup_read_check_str(fd, ODS_SE_FILE_MAGIC))
        {
            ods_log_error("[%s] unable to recover zone state from file %s.state: "
                "file corrupted", zone_str, zone->name);
            ods_fclose(fd);
            return;
        }
        zone->klass = (ldns_rr_class) klass;
        zone->fetch = fetch;

        ods_fclose(fd);
    } else {
        ods_log_deeebug("[%s] unable to recover zone state from file %s.state: ",
            "no such file or directory", zone_str, zone->name);
        return;
    }

    /* let's see if we can recover the signconf now */
    filename = ods_build_path(zone->name, ".sc", 0);
    zone->signconf = signconf_recover_from_backup((const char*) filename);
    free((void*)filename);
    if (!zone->signconf) {
        /* no, stop recovering process */
        return;
    }
    zone->signconf->name = zone->name;
    zone->signconf->keys = keylist_create(zone->signconf->allocator);

    /* recover denial of existence */
    filename = ods_build_path(zone->name, ".denial", 0);
    fd = ods_fopen(filename, NULL, "r");
    free((void*)filename);
    if (fd) {
        error = zonedata_recover_from_backup(zone->zonedata, fd);
        ods_fclose(fd);
        if (error) {
            ods_log_error("unable to recover denial of existence from file "
            "%s.denial: file corrupted", zone_str, zone->name);
            if (zone->zonedata) {
                zonedata_cleanup(zone->zonedata);
                zone->zonedata = NULL;
            }
            zone->zonedata = zonedata_create(zone->allocator);
        }
    } else {
        ods_log_deeebug("[%s] unable to recover denial of existence from file "
            "%s.denial: no such file or directory", zone_str, zone->name);
        error = 1;
    }
    if (error) {
        goto abort_recover;
    }

    /* zone data */
    filename = ods_build_path(zone->name, ".unsorted", 0);
    error = adfile_read(zone, filename);
    free((void*)filename);
    if (error) {
        ods_log_error("[%s] unable to recover unsorted zone from file "
        "%s.unsorted: parse error", zone_str, zone->name);
        if (zone->zonedata) {
            zonedata_cleanup(zone->zonedata);
            zone->zonedata = NULL;
        }
        zone->zonedata = zonedata_create(zone->allocator);
        goto abort_recover;
    }

    /* time for the keys and nsec3params file */
    filename = ods_build_path(zone->name, ".dnskeys", 0);
    fd = ods_fopen(filename, NULL, "r");
    free((void*)filename);
    if (fd) {
        error = zone_recover_dnskeys_from_backup(zone, fd);
        ods_fclose(fd);
        if (error) {
            ods_log_error("[%s] unable to recover dnskeys from file %s.dnskeys: "
                "file corrupted", zone_str, zone->name);
        }
    } else {
        ods_log_deeebug("[%s] unable to recover dnskeys from file %s.dnskeys: ",
            "no such file or directory", zone_str, zone->name);
        error = 1;
    }
    if (error) {
        goto abort_recover;
    }

    /* retrieve signatures */
    filename = ods_build_path(zone->name, ".rrsigs", 0);
    fd = ods_fopen(filename, NULL, "r");
    free((void*)filename);
    if (fd) {
        error = zone_recover_rrsigs_from_backup(zone, fd);
        ods_fclose(fd);
        if (error) {
            ods_log_error("[%s] unable to recover rrsigs from file %s.rrsigs: "
                "file corrupted", zone_str, zone->name);
        }
    } else {
        ods_log_deeebug("[%s] unable to recover rrsigs from file %s.rrsigs: ",
            "no such file or directory", zone_str, zone->name);
    }

abort_recover:

    /* task */
    filename = ods_build_path(zone->name, ".task", 0);
    task = task_recover_from_backup((const char*) filename, zone);
    free((void*)filename);

    if (!task) {
        now = time_now();
        task = task_create(TASK_READ, now, zone->name, zone);
    }
    if (!task) {
        ods_log_error("[%s] failed to create task for zone %s", zone_str, zone->name);
    } else {
        if (error) {
            task->what = TASK_READ;
        }
        zone->task = task;

        status = schedule_task((schedule_type*) tl, (task_type*) zone->task, 1);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] failed to schedule task for zone %s", zone_str, zone->name);
        }
    }

    if (error) {
        zone->signconf->last_modified = 0;
    }
    return;
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
                ods_log_error("[%s] failed to merge policy %s name to zone %s",
                    zone_str, z2->policy_name, z1->name);
            } else {
                free((void*)z1->policy_name);
                z1->policy_name = str;
                z1->just_updated = 1;
            }
        } else {
            free((void*)z1->policy_name);
            z1->policy_name = NULL;
            z1->just_updated = 1;
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
                z1->just_updated = 1;
            }
        } else {
            free((void*)z1->signconf_filename);
            z1->signconf_filename = NULL;
            z1->just_updated = 1;
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
 * Clean up a zone.
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

    if (zone->stats) {
        stats_cleanup(zone->stats);
        zone->stats = NULL;
    }

    ldns_rdf_deep_free(zone->dname);
    free((void*)zone->notify_ns);
    free((void*)zone->policy_name);
    free((void*)zone->signconf_filename);
    adapter_cleanup(zone->adinbound);
    adapter_cleanup(zone->adoutbound);
    zonedata_cleanup(zone->zonedata);
    signconf_cleanup(zone->signconf);
    nsec3params_cleanup(zone->nsec3params);
    allocator_deallocate(allocator);
    allocator_cleanup(allocator);
    lock_basic_destroy(&zone_lock);
    return;
}
