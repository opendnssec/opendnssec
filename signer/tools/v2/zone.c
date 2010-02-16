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
 * Zone attributes.
 *
 */

#include "v2/adapter.h"
#include "v2/nsec3params.h"
#include "v2/signconf.h"
#include "v2/zone.h"
#include "v2/zonedata.h"
#include "v2/se_malloc.h"
#include "v2/hsm.h"

#include <ldns/ldns.h>
#include <time.h>
#include <unistd.h>

#define SE_SOA_RDATA_MINIMUM 6

/* copycode: This define is from BIND9 */
#define DNS_SERIAL_GT(a, b) ((int)(((a) - (b)) & 0xFFFFFFFF) > 0)

/**
 * Create a new zone.
 *
 */
zone_type*
zone_create(const char* name, ldns_rr_class klass)
{
    zone_type* zone = (zone_type*) se_calloc(1, sizeof(zone_type));
    zone->name = se_strdup(name);
    zone->dname = ldns_dname_new_frm_str(name);
    zone->klass = klass;
    zone->default_ttl = 0;
    zone->inbound_serial = 0;
    zone->outbound_serial = 0;
    zone->policy_name = NULL;
    zone->signconf_filename = NULL;
    zone->signconf = NULL;
    zone->inbound_adapter = NULL;
    zone->outbound_adapter = NULL;
    zone->zonedata = zonedata_create();
    zone->nsec3params = NULL;
    return zone;
}


/**
 * Convert class to string.
 *
 */
const char*
class2str(ldns_rr_class klass)
{
    switch (klass) {
        case LDNS_RR_CLASS_IN:
            return "IN";
            break;
        case LDNS_RR_CLASS_CH:
            return "CH";
            break;
        case LDNS_RR_CLASS_HS:
            return "HS";
            break;
        case LDNS_RR_CLASS_NONE:
            return "NONE";
            break;
        case LDNS_RR_CLASS_ANY:
            return "ANY";
            break;
        case LDNS_RR_CLASS_FIRST:
        case LDNS_RR_CLASS_LAST:
        case LDNS_RR_CLASS_COUNT:
        default:
            return "";
            break;
    }
    return "";
}


/**
 * Calculate output serial.
 *
 */
void
zone_calc_outbound_serial(zone_type* zone)
{
    uint32_t soa, prev, update;
    if (zone->signconf->soa_serial == NULL)
        return;

    prev = zone->outbound_serial;

    if (strncmp(zone->signconf->soa_serial, "unixtime", 8) == 0) {
        soa = (uint32_t) time(NULL);
        if (!DNS_SERIAL_GT(soa, prev)) {
            soa = prev + 1;
        }
        update = soa - prev;
    } else if (strncmp(zone->signconf->soa_serial, "counter", 7) == 0) {
        soa = zone->inbound_serial;
        if (!DNS_SERIAL_GT(soa, prev)) {
            soa = prev + 1;
        }
        update = soa - prev;
    } else if (strncmp(zone->signconf->soa_serial, "datecounter", 11) == 0) {
        soa = (uint32_t) time_datestamp(0, "%Y%m%d", NULL) * 100;

        if (!DNS_SERIAL_GT(soa, prev)) {
            soa = prev + 1;
        }
        update = soa - prev;
    } else if (strncmp(zone->signconf->soa_serial, "keep", 4) == 0) {
        soa = zone->inbound_serial;
        if (!DNS_SERIAL_GT(soa, prev)) {
            fprintf(stderr, "can not keep SOA SERIAL from input zone '%s' "
                " (%u): output SOA SERIAL is %u\n", zone->name, soa, prev);
            return;
        }
        prev = soa;
        update = 0;
    } else {
        fprintf(stderr, "zone '%s' has unknown serial type '%s'\n",
            zone->name, zone->signconf->soa_serial);
        return;
    }

    /* serial is stored in 32 bits */
    if (update > 0x7FFFFFFF) {
        update = 0x7FFFFFFF;
    }
    soa = (prev + update); /* automatically does % 2^32 */

    zone->outbound_serial = soa;
    return;
}


/**
 * Print zone.
 *
 */
void
zone_print(FILE* out, zone_type* zone, int skip_soa)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    node = ldns_rbtree_first(zone->zonedata->domains);
    if (!node || node == LDNS_RBTREE_NULL)
        fprintf(out, "; empty zone, class %s\n", class2str(zone->klass));

    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_print(out, domain, skip_soa);
        node = ldns_rbtree_next(node);
    }
}


/**
 * Add a RR to the zone.
 *
 */
int
zone_add_rr(zone_type* zone, ldns_rr* rr)
{
    ldns_rr_type type = 0;
    int result = 0, at_apex = 0;
    uint32_t tmp = 0;
    ldns_rdf* soa_min = NULL;

    /* in-zone? */
    if (ldns_dname_compare(zone->dname, ldns_rr_owner(rr)) != 0 &&
        !ldns_dname_is_subdomain(ldns_rr_owner(rr), zone->dname)) {
        fprintf(stderr, "warning: zone '%s' contains out of zone data, skipping\n",
            zone->name);
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
        ldns_rr_set_ttl(rr, tmp);
    }
    if (type == LDNS_RR_TYPE_SOA) {
        if (zone->signconf->soa_ttl) {
            tmp = (uint32_t) duration2time(zone->signconf->soa_ttl);
            ldns_rr_set_ttl(rr, tmp);
        }
        if (zone->signconf->soa_min) {
            tmp = (uint32_t) duration2time(zone->signconf->soa_min);
            soa_min = ldns_rr_set_rdf(rr,
                ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, tmp),
                SE_SOA_RDATA_MINIMUM);
            if (soa_min) {
                ldns_rdf_free(soa_min);
            } else {
                fprintf(stderr, "zone '%s' failed to replace SOA MINIMUM "
                    "rdata\n", zone->name);
            }
        }
    }

    /* add rr */
    result = zonedata_add_rr(zone->zonedata, rr, at_apex);
    return result;
}


/**
 *  Add empty non-terminals to the zone data.
 *
 */
int
zone_entize(zone_type* zone)
{
    int result = 0;

    if (zone->zonedata->domains) {
        return zonedata_entize(zone->zonedata, zone->dname);
    }
    return result;
}


/**
 * Add the DNSKEYs from the Signer Configuration to the zone data.
 *
 */
int
zone_publish_dnskeys(zone_type* zone)
{
    key_type* key = NULL;
    uint32_t ttl = 0;
    int count = 0;
    int error = 0;
    hsm_ctx_t* ctx = NULL;
    ldns_rr* dnskey = NULL;

    ctx = hsm_create_context();
    if (ctx == NULL) {
        fprintf(stderr, "error creating libhsm context\n");
        return 2;
    }

    ttl = zone->default_ttl;
    if (zone->signconf->dnskey_ttl) {
        ttl = (uint32_t) duration2time(zone->signconf->dnskey_ttl);
    }

    key = zone->signconf->keys->first_key;
    for (count=0; count < zone->signconf->keys->count; count++) {
        if (key->publish) {
            if (!key->dnskey) {
                key->dnskey = hsm_get_key(ctx, zone->dname, key);
                if (!key->dnskey) {
                    fprintf(stderr, "error creating DNSKEYs for zone '%s'\n",
                        zone->name);
                    error = 1;
                    break;
                }
            }

            ldns_rr_set_ttl(key->dnskey, ttl);
            ldns_rr_set_class(key->dnskey, zone->klass);
            dnskey = ldns_rr_clone(key->dnskey);
            error = zone_add_rr(zone, dnskey);
            if (error) {
                fprintf(stderr, "error adding DNSKEYs for zone '%s'\n",
                    zone->name);
                break;
            }
        }
        key = key->next;
    }

    hsm_destroy_context(ctx);
    return error;
}


/**
 * Add NSEC records to the zone.
 *
 */
static int
zone_nsecify_nsec(zone_type* zone)
{
    int result = 0;

    /* default ttl holds the SOA MINIMUM value */
    result = zonedata_nsecify_nsec(zone->zonedata,
        zone->default_ttl, zone->klass);
    return result;
}


/**
 * Add NSEC3 records to the zone.
 *
 */
static int
zone_nsecify_nsec3(zone_type* zone)
{
    int result;

    /* default ttl holds the SOA MINIMUM value */
    result = zonedata_nsecify_nsec3(zone->zonedata, zone->default_ttl,
        zone->klass, zone->nsec3params);
    return result;
}


/**
 * Add NSEC(3) records to the zone.
 *
 */
int
zone_nsecify(zone_type* zone)
{
    int result = 0;
    ldns_rr* nsec3params_rr = NULL;

    if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC) {
        result = zone_nsecify_nsec(zone);
    } else if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
        /**
         * Select the hash algorithm and the values for
         *    salt and iterations.
         */
        if (!zone->nsec3params) {
            zone->nsec3params = nsec3params_create(
                (uint8_t) zone->signconf->nsec3_algo,
                (uint8_t) zone->signconf->nsec3_optout,
                (uint16_t) zone->signconf->nsec3_iterations,
                zone->signconf->nsec3_salt);
            if (!zone->nsec3params) {
                fprintf(stderr, "error creating NSEC3 parameters for zone "
                    " '%s'\n", zone->name);
                return 1;
            }

            nsec3params_rr = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3PARAMS);
            ldns_rr_set_class(nsec3params_rr, zone->klass);
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

            result = zonedata_add_rr(zone->zonedata, nsec3params_rr, 1);
            if (result != 0) {
                fprintf(stderr, "error adding NSEC3PARAMS record to zone '%s'\n",
                    zone->name);
            }
        }
        result = zone_nsecify_nsec3(zone);
    } else {
        fprintf(stderr, "unknown RR type for denial of existence, %i\n",
            zone->signconf->nsec_type);
        result = 1;
    }
    return result;
}

/**
 * Clean up a zone.
 *
 */
void
zone_cleanup(zone_type* zone)
{
    if (zone) {
        ldns_rdf_deep_free(zone->dname);
        adapter_cleanup(zone->inbound_adapter);
        adapter_cleanup(zone->outbound_adapter);
        signconf_cleanup(zone->signconf);
        zonedata_cleanup(zone->zonedata);
        se_free((void*) zone->policy_name);
        se_free((void*) zone->signconf_filename);
        se_free((void*) zone->name);
        se_free((void*) zone);
    }
}
