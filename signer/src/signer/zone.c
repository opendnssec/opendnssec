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

#include "adapter/adapter.h"
#include "scheduler/locks.h"
#include "scheduler/task.h"
#include "signer/backup.h"
#include "signer/hsm.h"
#include "signer/nsec3params.h"
#include "signer/signconf.h"
#include "signer/zone.h"
#include "signer/zonedata.h"
#include "util/duration.h"
#include "util/file.h"
#include "util/log.h"
#include "util/se_malloc.h"
#include "util/util.h"

#include <ldns/ldns.h> /* ldns_*() */
#include <libhsm.h> /* hsm_create_context(), hsm_get_key(), hsm_destroy_context() */
#include <libhsmdns.h> /* hsm_create_context(), hsm_get_key(), hsm_destroy_context() */


/**
 * Create a new zone.
 *
 */
zone_type*
zone_create(const char* name, ldns_rr_class klass)
{
    zone_type* zone = (zone_type*) se_calloc(1, sizeof(zone_type));
    se_log_assert(name);
    se_log_debug("create zone %s", name?name:"(null)");
    zone->name = se_strdup(name);
    zone->dname = ldns_dname_new_frm_str(name);
    zone->klass = klass;
    zone->policy_name = NULL;
    zone->signconf_filename = NULL;
    zone->signconf = NULL;
    zone->nsec3params = NULL;
    zone->inbound_adapter = NULL;
    zone->outbound_adapter = NULL;
    zone->task = NULL;
    zone->backoff = 0;
    zone->worker = NULL;
    zone->just_added = 0;
    zone->just_updated = 0;
    zone->tobe_removed = 0;
    zone->in_progress = 0;
    zone->zonedata = zonedata_create();
    zone->stats = stats_create();
    lock_basic_init(&zone->zone_lock);
    return zone;
}


/**
 * Update zone configuration settings from zone list.
 *
 */
void
zone_update_zonelist(zone_type* z1, zone_type* z2)
{
    se_log_assert(z1);
    se_log_assert(z2);

    if (se_strcmp(z2->policy_name, z1->policy_name) != 0) {
        se_free((void*)z1->policy_name);
        if (z2->policy_name) {
            z1->policy_name = se_strdup(z2->policy_name);
        } else {
            z1->policy_name = NULL;
        }
        z1->just_updated = 1;
    }

    if (se_strcmp(z2->signconf_filename, z1->signconf_filename) != 0) {
        se_free((void*)z1->signconf_filename);
        if (z2->signconf_filename) {
            z1->signconf_filename = se_strdup(z2->signconf_filename);
        } else {
            z1->signconf_filename = NULL;
        }
        z1->just_updated = 1;
    }

    if (adapter_compare(z1->inbound_adapter, z2->inbound_adapter) != 0) {
        adapter_cleanup(z1->inbound_adapter);
        if (z2->inbound_adapter) {
            z1->inbound_adapter = adapter_create(
                z2->inbound_adapter->filename,
                z2->inbound_adapter->type,
                z2->inbound_adapter->inbound);
        } else {
            z1->inbound_adapter = NULL;
        }
        z1->just_updated = 1;
    }

    if (adapter_compare(z1->outbound_adapter, z2->outbound_adapter) != 0) {
        adapter_cleanup(z1->outbound_adapter);
        if (z2->outbound_adapter) {
            z1->outbound_adapter = adapter_create(
                z2->outbound_adapter->filename,
                z2->outbound_adapter->type,
                z2->outbound_adapter->inbound);
        } else {
            z1->outbound_adapter = NULL;
        }
        z1->just_updated = 1;
    }

    zone_cleanup(z2);
    return;
}


/**
 * Read signer configuration.
 *
 */
int
zone_update_signconf(zone_type* zone, struct tasklist_struct* tl, char* buf)
{
    task_type* task = NULL;
    signconf_type* signconf = NULL;
    time_t last_modified = 0;
    time_t now;

    se_log_assert(zone);
    se_log_debug("load zone %s signconf %s",
        zone->name?zone->name:"(null)",
        zone->signconf_filename?zone->signconf_filename:"(null)");

    if (zone->signconf) {
        last_modified = zone->signconf->last_modified;
    }

    signconf = signconf_read(zone->signconf_filename, last_modified);
    if (!signconf) {
        if (!zone->policy_name) {
            se_log_warning("zone %s has no policy",
                zone->name?zone->name:"(null)");
        } else {
            signconf = signconf_read(zone->signconf_filename, 0);
            if (!signconf) {
                se_log_warning("zone %s has policy %s configured, "
                    "but has no (valid) signconf file",
                    zone->name?zone->name:"(null)", zone->policy_name);
                if (buf) {
                    (void)snprintf(buf, ODS_SE_MAXLINE,
                        "Zone %s config has errors.\n",
                             zone->name?zone->name:"(null)");
                }
                return -1;
            } else {
                se_log_debug("zone %s has not changed",
                    zone->name?zone->name:"(null)");
                signconf_cleanup(signconf);
            }
        }
        if (buf) {
            (void)snprintf(buf, ODS_SE_MAXLINE,
                "Zone %s config has not changed.\n",
                zone->name?zone->name:"(null)");
        }
        return 0;
    } else if (signconf_check(signconf) != 0) {
        se_log_warning("zone %s signconf has errors",
            zone->name?zone->name:"(null)");
        if (buf) {
            (void)snprintf(buf, ODS_SE_MAXLINE,
                "Zone %s config has errors.\n", zone->name?zone->name:"(null)");
        }
        return -1;
    } else if (!zone->signconf) {
        zone->signconf = signconf;
        /* we don't check if foo in <Zone name="foo"> matches zone->name */
        zone->signconf->name = zone->name;
        se_log_debug("zone %s now has signconf",
            zone->name?zone->name:"(null)");
        signconf_backup(zone->signconf);

        /* zone state? */
        /* create task for new zone */
        now = time_now();
        zone->task = task_create(TASK_READ, now, zone->name, zone);
        task = tasklist_schedule_task(tl, zone->task, 0);
        if (!task) {
            if (buf) {
                (void)snprintf(buf, ODS_SE_MAXLINE, "Zone %s now has config, "
                    "but could not be scheduled.\n",
                    zone->name?zone->name:"(null)");
            }
        } else {
            if (buf) {
                (void)snprintf(buf, ODS_SE_MAXLINE,
                    "Zone %s now has config.\n",
                    zone->name?zone->name:"(null)");
            }
        }
        return 1;
    } else {
        /* update task for new zone */
        zone->task->what = signconf_compare(zone->signconf, signconf);
        zone->task->when = time_now();
        signconf_cleanup(zone->signconf);
        zone->signconf = signconf;
        zone->signconf->name = zone->name;
        se_log_debug("zone %s signconf updated",
            zone->name?zone->name:"(null)");
        signconf_backup(zone->signconf);
        if (buf) {
            (void)snprintf(buf, ODS_SE_MAXLINE,
                "Zone %s config updated.\n", zone->name?zone->name:"(null)");
        }
        return 1;
    }
    /* not reached */
    return 0;
}

/**
 * Add the DNSKEYs from the Signer Configuration to the zone data.
 *
 */
static int
zone_publish_dnskeys(zone_type* zone, FILE* fd)
{
    key_type* key = NULL;
    uint32_t ttl = 0;
    size_t count = 0;
    int error = 0;
    hsm_ctx_t* ctx = NULL;
    ldns_rr* dnskey = NULL;

    se_log_assert(zone);
    se_log_assert(zone->signconf);
    se_log_assert(zone->signconf->keys);
    se_log_assert(zone->zonedata);

    ctx = hsm_create_context();
    if (ctx == NULL) {
        se_log_error("error creating libhsm context");
        return 2;
    }

    ttl = zone->zonedata->default_ttl;
    if (zone->signconf->dnskey_ttl) {
        ttl = (uint32_t) duration2time(zone->signconf->dnskey_ttl);
    }

    key = zone->signconf->keys->first_key;
    for (count=0; count < zone->signconf->keys->count; count++) {
        if (key->publish) {
            if (!key->dnskey) {
                error = hsm_get_key(ctx, zone->dname, key);
                if (error) {
                    se_log_error("error creating DNSKEY for key %s",
                        key->locator?key->locator:"(null)");
                    error = 1;
                    break;
                }
            }
            ldns_rr_set_ttl(key->dnskey, ttl);
            ldns_rr_set_class(key->dnskey, zone->klass);
            dnskey = ldns_rr_clone(key->dnskey);
            error = zone_add_rr(zone, dnskey, 0);
            if (error) {
                se_log_error("error adding DNSKEY[%u] for key %s",
                    ldns_calc_keytag(dnskey),
                    key->locator?key->locator:"(null)");
                break;
            } else if (fd) {
                fprintf(fd, ";DNSKEY %s %u %u %i %i %i\n",
                    key->locator?key->locator:"(null)", key->algorithm,
                    key->flags, key->publish, key->ksk, key->zsk);
                ldns_rr_print(fd, dnskey);
                fprintf(fd, ";END\n");
            }
        }
        key = key->next;
    }
    hsm_destroy_context(ctx);
    return error;
}


/**
 * Add the NSEC3PARAMSs from the Signer Configuration to the zone data.
 *
 */
static int
zone_publish_nsec3params(zone_type* zone, FILE* fd)
{
    ldns_rr* nsec3params_rr = NULL;
    int error = 0;

    if (!zone->nsec3params) {
        zone->nsec3params = nsec3params_create(
            (uint8_t) zone->signconf->nsec3_algo,
            (uint8_t) zone->signconf->nsec3_optout,
            (uint16_t) zone->signconf->nsec3_iterations,
            zone->signconf->nsec3_salt);
        if (!zone->nsec3params) {
            se_log_error("error creating NSEC3 parameters for zone %s",
                zone->name?zone->name:"(null)");
            return 1;
        }
    }

    nsec3params_rr = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3PARAMS);
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

    error = zone_add_rr(zone, nsec3params_rr, 0);
    if (error) {
        se_log_error("error adding NSEC3PARAMS record to zone %s",
            zone->name?zone->name:"(null)");
    } else if (fd) {
        fprintf(fd, ";NSEC3PARAMS %s %u %u %u\n",
            zone->signconf->nsec3_salt, zone->nsec3params->algorithm,
            zone->nsec3params->flags, zone->nsec3params->iterations);
        ldns_rr_print(fd, nsec3params_rr);
        fprintf(fd, ";END\n");
    }
    return error;
}


/**
 * Update zone with pending changes.
 *
 */
int
zone_update_zonedata(zone_type* zone)
{
    se_log_assert(zone);
    se_log_assert(zone->signconf);
    se_log_assert(zone->zonedata);
    return zonedata_update(zone->zonedata, zone->signconf);
}


/**
 * Publish DNSKEY and NSEC3PARAM records to the zone.
 *
 */
int
zone_add_dnskeys(zone_type* zone)
{
    int error = 0;
    char* filename = NULL;
    FILE* fd = NULL;

    se_log_assert(zone);
    se_log_assert(zone->signconf);
    se_log_assert(zone->zonedata);

    filename = se_build_path(zone->name, ".dnskeys", 0);
    fd = se_fopen(filename, NULL, "w");
    if (fd) {
        fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
    }

    error = zone_publish_dnskeys(zone, fd);
    if (error) {
        se_log_error("error adding DNSKEYs to zone %s",
            zone->name?zone->name:"(null)");
        return error;
    }
    if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
        error = zone_publish_nsec3params(zone, fd);
        if (error) {
            se_log_error("error adding NSEC3PARAMS RR to zone %s",
                zone->name?zone->name:"(null)");
            return error;
        }
    }

    if (fd) {
        fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
        se_fclose(fd);
    } else {
        se_log_warning("cannot backup DNSKEY / NSEC3PARAMS records: "
            "cannot open file %s for writing", filename?filename:"(null)");
    }
    se_free((void*)filename);

    return error;
}


/**
 * Add a RR to the zone.
 *
 */
int
zone_add_rr(zone_type* zone, ldns_rr* rr, int recover)
{
    ldns_rr_type type = 0;
    int error = 0;
    int at_apex = 0;
    uint32_t tmp = 0;
    ldns_rdf* soa_min = NULL;

    se_log_assert(zone);
    se_log_assert(zone->zonedata);
    se_log_assert(zone->signconf);
    se_log_assert(rr);

    /* in-zone? */
    if (ldns_dname_compare(zone->dname, ldns_rr_owner(rr)) != 0 &&
        !ldns_dname_is_subdomain(ldns_rr_owner(rr), zone->dname)) {
        se_log_warning("zone %s contains out of zone data, skipping",
            zone->name?zone->name:"(null)");
        ldns_rr_free(rr);
        return 0; /* consider success */
    }
    if (ldns_dname_compare(zone->dname, ldns_rr_owner(rr)) == 0) {
        at_apex = 1;
    }

    /* type specific configuration */
    type = ldns_rr_get_type(rr);
    if (type == LDNS_RR_TYPE_DNSKEY && zone->signconf->dnskey_ttl) {
        tmp = (uint32_t) duration2time(zone->signconf->dnskey_ttl);
        se_log_verbose("zone %s set DNSKEY TTL to %u",
            zone->name?zone->name:"(null)", tmp);
        ldns_rr_set_ttl(rr, tmp);
    }
    if (type == LDNS_RR_TYPE_SOA) {
        if (zone->signconf->soa_ttl) {
            tmp = (uint32_t) duration2time(zone->signconf->soa_ttl);
            se_log_verbose("zone %s set SOA TTL to %u",
                zone->name?zone->name:"(null)", tmp);
            ldns_rr_set_ttl(rr, tmp);
        }
        if (zone->signconf->soa_min) {
            tmp = (uint32_t) duration2time(zone->signconf->soa_min);
            se_log_verbose("zone %s set SOA MINIMUM to %u",
                zone->name?zone->name:"(null)", tmp);
            soa_min = ldns_rr_set_rdf(rr,
                ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, tmp),
                SE_SOA_RDATA_MINIMUM);
            if (soa_min) {
                ldns_rdf_deep_free(soa_min);
            } else {
                se_log_error("zone %s failed to replace SOA MINIMUM "
                    "rdata", zone->name?zone->name:"(null)");
            }
        }
    }
    if (recover) {
       error = zonedata_recover_rr_from_backup(zone->zonedata, rr, at_apex);
    } else {
       error = zonedata_add_rr(zone->zonedata, rr, at_apex);
    }
    return error;
}


/**
 * Delete a RR from the zone.
 *
 */
int
zone_del_rr(zone_type* zone, ldns_rr* rr)
{
    se_log_assert(zone);
    se_log_assert(zone->zonedata);
    se_log_assert(rr);
    return zonedata_del_rr(zone->zonedata, rr);
}


/**
 * Nsecify zone.
 *
 */
int
zone_nsecify(zone_type* zone)
{
    int error = 0;
    FILE* fd = NULL;
    char* filename = NULL;
    time_t start = 0;
    time_t end = 0;

    se_log_assert(zone);
    se_log_assert(zone->signconf);
    se_log_assert(zone->zonedata);
    se_log_assert(zone->stats);

    zone->stats->nsec_count = 0;
    zone->stats->nsec_time = 0;
    start = time(NULL);

    /* add empty non-terminals */
    error = zonedata_entize(zone->zonedata, zone->dname);
    if (error) {
        se_log_error("failed to add empty non-terminals to zone %s",
            zone->name?zone->name:"(null)");
        return error;
    }

    if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC) {
        error = zonedata_nsecify(zone->zonedata, zone->klass, zone->stats);
    } else if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
        if (zone->signconf->nsec3_optout) {
            se_log_debug("OptOut is being used for zone %s",
                zone->name?zone->name:"(null)");
        }
        error = zonedata_nsecify3(zone->zonedata, zone->klass,
            zone->nsec3params, zone->stats);
    } else {
        se_log_error("unknown RR type for denial of existence, %i",
            zone->signconf->nsec_type);
        error = 1;
    }
    if (!error) {
        end = time(NULL);
        zone->stats->nsec_time = (end-start);

        filename = se_build_path(zone->name, ".denial", 0);
        fd = se_fopen(filename, NULL, "w");
        if (fd) {
            fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
            zonedata_print_nsec(fd, zone->zonedata);
            fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
            se_fclose(fd);
        } else {
            se_log_warning("cannot backup NSEC(3) records: cannot open file "
            "%s for writing", filename?filename:"(null)");
        }
        se_free((void*)filename);
    }
    return error;
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

    se_log_assert(zone);
    se_log_assert(zone->signconf);
    se_log_assert(zone->zonedata);
    se_log_assert(zone->stats);

    zone->stats->sig_count = 0;
    zone->stats->sig_reuse = 0;
    zone->stats->sig_time = 0;
    start = time(NULL);

    error = zonedata_sign(zone->zonedata, zone->dname, zone->signconf,
        zone->stats);
    if (!error) {
        end = time(NULL);
        zone->stats->sig_time = (end-start);

        filename = se_build_path(zone->name, ".rrsigs", 0);
        fd = se_fopen(filename, NULL, "w");
        if (fd) {
            fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
            zonedata_print_rrsig(fd, zone->zonedata);
            fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
            se_fclose(fd);
        } else {
            se_log_warning("cannot backup RRSIG records: cannot open file "
                "%s for writing", filename?filename:"(null)");
        }
        se_free((void*)filename);
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

    se_log_assert(zone);
    se_log_assert(zone->zonedata);
    se_log_assert(zone->signconf);

    filename = se_build_path(zone->name, ".state", 0);
    fd = se_fopen(filename, NULL, "w");
    if (fd) {
        fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
        fprintf(fd, ";name: %s\n", zone->name?zone->name:"(null)");
        fprintf(fd, ";class: %i\n", (int) zone->klass);
        fprintf(fd, ";default_ttl: %u\n", zone->zonedata->default_ttl);
        fprintf(fd, ";inbound_serial: %u\n", zone->zonedata->inbound_serial);
        fprintf(fd, ";internal_serial: %u\n", zone->zonedata->internal_serial);
        fprintf(fd, ";outbound_serial: %u\n", zone->zonedata->outbound_serial);
        fprintf(fd, "%s\n", ODS_SE_FILE_MAGIC);
        se_fclose(fd);
    } else {
        se_log_error("cannot backup zone: cannot open file "
        "%s for writing", filename?filename:"(null)");
        return 1;
    }
    se_free((void*)filename);

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
            if (se_strcmp(token, ";DNSKEY") == 0) {
                key = key_recover_from_backup(fd);
                if (!key || keylist_add(zone->signconf->keys, key)) {
                    se_log_error("error adding key from backup file "
                        "%s.dnskeys to key list", zone->name);
                    corrupted = 1;
                } else {
                   rr = ldns_rr_clone(key->dnskey);
                   corrupted = zone_add_rr(zone, rr, 1);
                   if (corrupted) {
                       se_log_error("error recovering DNSKEY[%u] rr",
                          ldns_calc_keytag(rr));
                   }
                   rr = NULL;
                }
                key = NULL;
            } else if (se_strcmp(token, ";NSEC3PARAMS") == 0) {
                zone->nsec3params = nsec3params_recover_from_backup(fd,
                    &rr);
                if (!zone->nsec3params) {
                    se_log_error("error recovering nsec3 parameters from file "
                        "%s.dnskeys", zone->name);
                    corrupted = 1;
                } else {
                    corrupted = zone_add_rr(zone, rr, 1);
                    if (corrupted) {
                       se_log_error("error recovering NSEC3PARAMS rr");
                    }
                }
                rr = NULL;
            } else if (se_strcmp(token, ODS_SE_FILE_MAGIC) == 0) {
                break;
            } else {
                corrupted = 1;
            }
            se_free((void*) token);
        } else {
            corrupted = 1;
        }
    }
    return corrupted;
}


/**
 * Recover from backup.
 *
 */
void
zone_recover_from_backup(zone_type* zone, struct tasklist_struct* tl)
{
    int klass = 0;
    int error = 0;
    char* filename = NULL;
    task_type* task = NULL;
    time_t now = 0;
    FILE* fd = NULL;

    se_log_assert(zone);
    se_log_assert(zone->zonedata);

    filename = se_build_path(zone->name, ".state", 0);
    fd = se_fopen(filename, NULL, "r");
    se_free((void*)filename);
    if (fd) {
        if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC) ||
            !backup_read_check_str(fd, ";name:") ||
            !backup_read_check_str(fd, zone->name) ||
            !backup_read_check_str(fd, ";class:") ||
            !backup_read_int(fd, &klass) ||
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
            se_log_error("unable to recover zone state from file %s.state: "
                "file corrupted", zone->name);
            se_fclose(fd);
            return;
        }
        se_fclose(fd);
    } else {
        se_log_debug("unable to recover zone state from file %s.state: ",
            "no such file or directory", zone->name);
        return;
    }

    /* let's see if we can recover the signconf now */
    filename = se_build_path(zone->name, ".sc", 0);
    zone->signconf = signconf_recover_from_backup((const char*) filename);
    se_free((void*)filename);
    if (!zone->signconf) {
        /* no, stop recovering process */
        return;
    }
    zone->signconf->keys = keylist_create();

    /* zone data */
    filename = se_build_path(zone->name, ".unsorted", 0);
    error = adfile_read(zone, filename, 1);
    se_free((void*)filename);
    if (error) {
        goto abort_recover;
    }

    /* time for the keys and nsec3params file */
    filename = se_build_path(zone->name, ".dnskeys", 0);
    fd = se_fopen(filename, NULL, "r");
    se_free((void*)filename);

    if (fd) {
        error = zone_recover_dnskeys_from_backup(zone, fd);
        se_fclose(fd);
        if (error) {
            se_log_error("unable to recover dnskeys from file %s.dnskeys: "
                "file corrupted", zone->name);
        }
    } else {
        se_log_debug("unable to recover dnskeys from file %s.dnskeys: ",
            "no such file or directory", zone->name);
        error = 1;
    }
    if (error) {
        goto abort_recover;
    }

    /* recover denial of existence */
    filename = se_build_path(zone->name, ".denial", 0);
    fd = se_fopen(filename, NULL, "r");
    se_free((void*)filename);
    if (fd) {
        /* add empty non-terminals */

/*
        error = zonedata_entize(zone->zonedata, zone->dname);
        if (error) {
            se_log_error("unable to recover denial of existence from file "
                "%s.denial: entize failed ", zone->name);
        } else {
            error = zone_recover_denial_from_backup(zone, fd);
        }
        se_fclose(fd);
        if (error) {
            se_log_error("unable to recover denial of existence from file "
                "%s.denial: file corrupted", zone->name);
        }
*/
    } else {
        se_log_debug("unable to recover denial of existence backup file "
            "%s.denial: no such file or directory", zone->name);
            error = 1;
    }
    if (error) {
        goto abort_recover;
    }

    /* retrieve signatures */
    filename = se_build_path(zone->name, ".rrsigs", 0);
    se_free((void*)filename);
    if (error) {
        goto abort_recover;
    }

abort_recover:

    /* task */
    filename = se_build_path(zone->name, ".task", 0);
    zone->task = task_recover_from_backup((const char*) filename, zone);
    se_free((void*)filename);
    if (!zone->task) {
        now = time_now();
        zone->task = task_create(TASK_READ, now, zone->name, zone);
    }
    if (!zone->task) {
        se_log_error("failed to create task for zone %s", zone->name);
    } else {
        task = tasklist_schedule_task(tl, zone->task, 1);
    }

    if (error) {
        zone->signconf->last_modified = 0;
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
    if (zone) {
        if (zone->dname) {
            ldns_rdf_deep_free(zone->dname);
            zone->dname = NULL;
        }
        if (zone->inbound_adapter) {
            adapter_cleanup(zone->inbound_adapter);
            zone->inbound_adapter = NULL;
        }
        if (zone->outbound_adapter) {
            adapter_cleanup(zone->outbound_adapter);
            zone->outbound_adapter = NULL;
        }
        if (zone->signconf) {
            signconf_cleanup(zone->signconf);
            zone->signconf = NULL;
        }
        if (zone->stats) {
            stats_cleanup(zone->stats);
            zone->stats = NULL;
        }
        if (zone->zonedata) {
            zonedata_cleanup(zone->zonedata);
            zone->zonedata = NULL;
        }
        if (zone->policy_name) {
            se_free((void*) zone->policy_name);
            zone->policy_name = NULL;
        }
        if (zone->signconf_filename) {
            se_free((void*) zone->signconf_filename);
            zone->signconf_filename = NULL;
        }
        if (zone->name) {
            se_free((void*) zone->name);
            zone->name = NULL;
        }

        lock_basic_destroy(&zone->zone_lock);
        se_free((void*) zone);
    } else {
        se_log_warning("cleanup emtpy zone");
    }
    return;
}


/**
 * Print zone.
 *
 */
void
zone_print(FILE* out, zone_type* zone, int internal)
{
    se_log_assert(out);
    se_log_assert(zone);
    se_log_assert(zone->zonedata);

    zonedata_print(out, zone->zonedata, internal);
    return;
}
