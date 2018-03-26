#define NOODS
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ldns/ldns.h>
#include "uthash.h"
#include "utilities.h"
#include "logging.h"
#include "proto.h"

#pragma GCC optimize ("O0")

#include "dictionary.h"

int names_rrcompare(const char* data, resourcerecord_t);
int names_rrcompare2(resourcerecord_t, resourcerecord_t);

#include "duration.h"

typedef int ods_status;
typedef struct hsm_ctx_struct hsm_ctx_t;
typedef struct signconf_struct signconf_type;
struct nsec3params_struct {
    signconf_type* sc;
    uint8_t        algorithm;
    uint8_t        flags;
    uint16_t       iterations;
    uint8_t        salt_len;
    uint8_t*       salt_data;
    ldns_rr*       rr;
};
typedef struct nsec3params_struct nsec3params_type;
typedef int hsm_sign_params_t;
typedef struct keylist_struct keylist_type;
typedef struct key_struct key_type;

struct key_struct {
    ldns_rr* dnskey;
    hsm_sign_params_t* params;
    const char* locator;
    const char* resourcerecord;
    uint8_t algorithm;
    uint32_t flags;
    int publish;
    int ksk;
    int zsk;
};
struct keylist_struct {
    signconf_type* sc;
    key_type* keys;
    size_t count;
};
struct signconf_struct {
    /* Zone */
    const char* name;
    int passthrough;
    /* Signatures */
    duration_type* sig_resign_interval;
    duration_type* sig_refresh_interval;
    duration_type* sig_validity_default;
    duration_type* sig_validity_denial;
    duration_type* sig_validity_keyset;
    duration_type* sig_jitter;
    duration_type* sig_inception_offset;
    /* Denial of existence */
    duration_type* nsec3param_ttl;
    ldns_rr_type nsec_type;
    int nsec3_optout;
    uint32_t nsec3_algo;
    uint32_t nsec3_iterations;
    const char* nsec3_salt;
    nsec3params_type* nsec3params;
    /* Keys */
    duration_type* dnskey_ttl;
    const char** dnskey_signature; /* may be NULL and must be NULL terminated */
    keylist_type* keys;
    /* Source of authority */
    duration_type* soa_ttl;
    duration_type* soa_min;
    const char* soa_serial;
    /* Other useful information */
    duration_type* max_zone_ttl;
    const char* filename;
    time_t last_modified;
};

int b64_pton(char const *src, uint8_t *target, size_t targsize);
int lhsm_sign(hsm_ctx_t* ctx, ldns_rr_list* rrset, key_type* key_id, time_t inception, time_t expiration, ldns_rr** rrsig);
key_type* keylist_lookup_by_locator(keylist_type* kl, const char* locator);

int
rrset_getliteralrr(ldns_rr** dnskey, const char *resourcerecord, uint32_t ttl, ldns_rdf* apex)
{
    uint8_t dnskeystring[4096];
    ldns_status ldnsstatus;
    int len;
    if ((len = b64_pton(resourcerecord, dnskeystring, sizeof (dnskeystring) - 2)) < 0) {
        return 1;
    }
    dnskeystring[len] = '\0';
    if ((ldnsstatus = ldns_rr_new_frm_str(dnskey, (const char*) dnskeystring, ttl, apex, NULL)) != LDNS_STATUS_OK) {
        return 1;
    }
    return 0;
}

static uint32_t
rrset_recycle(signconf_type* signconf, dictionary domain, struct itemset* rrset, time_t signtime, ldns_rr_type dstatus, ldns_rr_type delegpt)
{
    uint32_t refresh = 0;
    uint32_t expiration = 0;
    uint32_t inception = 0;
    uint32_t reusedsigs = 0;
    unsigned drop_sig = 0;
    key_type* key = NULL;
    struct itemsig * rrsig;
    names_iterator iter;

    /* Calculate the Refresh Window = Signing time + Refresh */
    if (signconf && signconf->sig_refresh_interval) {
        refresh = (uint32_t) (signtime + duration2time(signconf->sig_refresh_interval));
    }
    /* Check every signature if it matches the recycling logic. */
    for(iter=rrsigs(rrset); names_iterate(&iter,&rrsig); names_advance(&iter, NULL)) {
        drop_sig = 0;
        /* 0. Skip delegation, glue and occluded RRsets */
        if (dstatus != LDNS_RR_TYPE_SOA || (delegpt != LDNS_RR_TYPE_SOA && rrset->rrtype != LDNS_RR_TYPE_DS)) {
            drop_sig = 1;
        } else {
            ods_log_assert(dstatus == LDNS_RR_TYPE_SOA || (delegpt == LDNS_RR_TYPE_SOA || rrset->rrtype == LDNS_RR_TYPE_DS));
        }
        /* 1. If the RRset has changed, drop all signatures */
        /* 2. If Refresh is disabled, drop all signatures */
        if(!drop_sig) {
            if (refresh <= (uint32_t) signtime) {
                drop_sig = 1;
            }
        }
        /* 3. Expiration - Refresh has passed */
        if(!drop_sig) {
            expiration = ldns_rdf2native_int32(ldns_rr_rrsig_expiration(rrsig->rr));
            if (expiration < refresh) {
                drop_sig = 1;
            }
        }
        /* 4. Inception has not yet passed */
        if(!drop_sig) {
            inception = ldns_rdf2native_int32(ldns_rr_rrsig_inception(rrsig->rr));
            if (inception > (uint32_t) signtime) {
                drop_sig = 1;
            }
        }
        /* 5. Corresponding key is dead (key is locator+flags) */
        if(!drop_sig) {
            key = keylist_lookup_by_locator(signconf->keys, rrsig->keylocator);
            if (!key || key->flags != rrsig->keyflags) {
                drop_sig = 1;
            }
        }

        if (drop_sig) {
            free(domain->expiry);
            domain->expiry = NULL;
            free(rrset->signatures);
            rrset->signatures = NULL;
            rrset->nsignatures = 0;
        } else {
            /* All rules ok, recycle signature */
            reusedsigs += 1;
        }
    }
    return reusedsigs;
}

static ldns_rr_list*
rrset2rrlist(struct itemset* rrset)
{
    ldns_rr_list* rr_list = NULL;
    int ret = 0;
    size_t i = 0;
    rr_list = ldns_rr_list_new();
    for (i=0; i < rrset->nitems; i++) {
        ret = (int) ldns_rr_list_push_rr(rr_list, rrset->items[i].rr);
        if (!ret) {
            ldns_rr_list_free(rr_list);
            return NULL;
        }
    }
    ldns_rr_list_sort(rr_list);
    return rr_list;
}

/**
 * Calculate the signature validation period.
 *
 */
static void
rrset_sigvalid_period(signconf_type* sc, ldns_rr_type rrtype, time_t signtime,
    time_t* inception, time_t* expiration)
{
    time_t jitter = 0;
    time_t offset = 0;
    time_t validity = 0;
    time_t random_jitter = 0;
    if (!sc || !rrtype || !signtime) {
        return;
    }
    jitter = duration2time(sc->sig_jitter);
    if (jitter) {
        random_jitter = ods_rand(jitter*2);
    }
    offset = duration2time(sc->sig_inception_offset);
    switch (rrtype) {
        case LDNS_RR_TYPE_NSEC:
        case LDNS_RR_TYPE_NSEC3:
            validity = duration2time(sc->sig_validity_denial);
            break;
        case LDNS_RR_TYPE_DNSKEY:
            if (sc->sig_validity_keyset != NULL && duration2time(sc->sig_validity_keyset) > 0) {
                validity = duration2time(sc->sig_validity_keyset);
            } else {
                validity = duration2time(sc->sig_validity_default);
            }
            break;
        default:
            validity = duration2time(sc->sig_validity_default);
    }
    *inception = signtime - offset;
    *expiration = (signtime + validity + random_jitter) - jitter;
}

ldns_rr_type
domain_is_delegpt(names_view_type view, dictionary record)
{
    if(names_recordhasdata(record, LDNS_RR_TYPE_SOA, NULL, 0)) {
        return LDNS_RR_TYPE_SOA;
    } else if(names_recordhasdata(record, LDNS_RR_TYPE_NS, NULL, 0)) {
        if(names_recordhasdata(record, LDNS_RR_TYPE_DS, NULL, 0))
            return LDNS_RR_TYPE_DS;
        else
            return LDNS_RR_TYPE_NS;
    }
    return LDNS_RR_TYPE_SOA;
}

ldns_rr_type
domain_is_occluded(names_view_type view, dictionary record)
{
    names_iterator iter;
    dictionary parent = NULL;
    if(names_recordhasdata(record, LDNS_RR_TYPE_SOA, NULL, 0))
        return LDNS_RR_TYPE_SOA;
    for(names_viewiterate(view,"ancestors",record->name); names_iterate(&iter, &parent); names_advance(&iter,NULL)) {
        if (names_recordhasdata(parent, LDNS_RR_TYPE_NS, NULL, 0)) {
            /* Glue / Empty non-terminal to Glue */
            names_end(&iter);
            return LDNS_RR_TYPE_A;
        }
        if (names_recordhasdata(parent, LDNS_RR_TYPE_DNAME, NULL, 0)) {
            /* Occluded data / Empty non-terminal to Occluded data */
            names_end(&iter);
            return LDNS_RR_TYPE_DNAME;
        }
    }
    /* Authoritative or delegation */
    return LDNS_RR_TYPE_SOA;
}
static int
rrset_siglocator(struct itemset* rrset, const char* locator)
{
    int match = 0;
    for(int i=0; i<rrset->nsignatures; i++) {
        if (!strcmp(locator, rrset->signatures[i].keylocator)) {
            match += 1;
        }
    }
    return match;
}

static int
rrset_sigalgo_count(struct itemset* rrset, uint8_t algorithm)
{
    int match = 0;
    for(int i=0; i<rrset->nsignatures; i++) {
        if (algorithm == ldns_rdf2native_int8(ldns_rr_rrsig_algorithm(rrset->signatures[i].rr))) {
            match += 1;
        }
    }
    return match;
}

ods_status
rrset_sign(signconf_type* signconf, names_view_type view, dictionary domain, hsm_ctx_t* ctx, struct itemset* rrset, time_t signtime)
{
    ods_status status;
    uint32_t newsigs = 0;
    uint32_t reusedsigs = 0;
    ldns_rr* rrsig = NULL;
    ldns_rr_list* rr_list = NULL;
    ldns_rr_list* rr_list_clone = NULL;
    const char* locator = NULL;
    time_t inception = 0;
    time_t expiration = 0;
    size_t i = 0, j;
    ldns_rr_type dstatus = LDNS_RR_TYPE_FIRST;
    ldns_rr_type delegpt = LDNS_RR_TYPE_FIRST;
    uint8_t algorithm = 0;
    int sigcount, keycount;

    const char*ownername;
    
    /* Recycle signatures */
    if (rrset->rrtype == LDNS_RR_TYPE_NSEC ||
        rrset->rrtype == LDNS_RR_TYPE_NSEC3) {
        dstatus = LDNS_RR_TYPE_SOA;
        delegpt = LDNS_RR_TYPE_SOA;
    } else {
        dstatus = domain_is_occluded(view, domain);
        delegpt = domain_is_delegpt(view, domain);
    }
    reusedsigs = rrset_recycle(signconf, domain, rrset, signtime, dstatus, delegpt);

    /* Skip delegation, glue and occluded RRsets */
    if (dstatus != LDNS_RR_TYPE_SOA) {
        return 0;
    }
    if (delegpt != LDNS_RR_TYPE_SOA && rrset->rrtype != LDNS_RR_TYPE_DS) {
        return 0;
    }

    /* Transmogrify rrset */
    rr_list = rrset2rrlist(rrset);
    if (ldns_rr_list_rr_count(rr_list) <= 0) {
        /* Empty RRset, no signatures needed */
        ldns_rr_list_free(rr_list);
        return 0;
    }
    /* Use rr_list_clone for signing, keep the original rr_list untouched for case preservation */
    rr_list_clone = ldns_rr_list_clone(rr_list);

    /* Calculate signature validity */
    rrset_sigvalid_period(signconf, rrset->rrtype, signtime,
         &inception, &expiration);
    /* Walk keys */
    for (i=0; i < signconf->keys->count; i++) {
        /* If not ZSK don't sign other RRsets */
        if (!signconf->keys->keys[i].zsk &&
            rrset->rrtype != LDNS_RR_TYPE_DNSKEY) {
            continue;
        }
        /* If not KSK don't sign DNSKEY RRset */
        if (!signconf->keys->keys[i].ksk &&
            rrset->rrtype == LDNS_RR_TYPE_DNSKEY) {
            continue;
        }
        /* Additional rules for signatures */
        if (rrset_siglocator(rrset, signconf->keys->keys[i].locator)) {
            continue;
        }

        /** We know this key doesn't sign the set, but only if 
         * n_sig < n_active_keys we should sign. If we already counted active
         * keys for this algorithm sjip counting step */
        keycount = 0;
        if (algorithm != signconf->keys->keys[i].algorithm) {
            algorithm = signconf->keys->keys[i].algorithm;
            for (j = 0; j < signconf->keys->count; j++) {
                if (signconf->keys->keys[j].algorithm == algorithm &&
                        signconf->keys->keys[j].zsk) /* is active */
                {
                    keycount++;
                }
            }
        }
        sigcount = rrset_sigalgo_count(rrset, algorithm);
        if (rrset->rrtype != LDNS_RR_TYPE_DNSKEY && sigcount >= keycount)
            continue;

        /* If key has no locator, and should be pre-signed dnskey RR, skip */
        if (signconf->keys->keys[i].ksk && signconf->keys->keys[i].locator == NULL) {
            continue;
        }

        /* Sign the RRset with this key */
        status = lhsm_sign(ctx, rr_list_clone, &signconf->keys->keys[i], inception, expiration, &rrsig);
        if (status) {
            ods_log_crit("unable to sign RRset[%i]: lhsm_sign() failed", rrset->rrtype);
            ldns_rr_list_free(rr_list);
            ldns_rr_list_free(rr_list_clone);
            return status;
        }
        /* Add signature */
        locator = strdup(signconf->keys->keys[i].locator);
        names_recordaddsignature2(domain, rrset->rrtype, rrsig, locator, signconf->keys->keys[i].flags);
        newsigs++;
    }
    if(rrset->rrtype == LDNS_RR_TYPE_DNSKEY && signconf->dnskey_signature) {
        for(i=0; signconf->dnskey_signature[i]; i++) {
            rrsig = NULL;
            if ((status = rrset_getliteralrr(&rrsig, signconf->dnskey_signature[i], duration2time(signconf->dnskey_ttl), names_viewgetapex(view)))) {
                char* apexstr = ldns_rdf2str(names_viewgetapex(view));
                ods_log_error("unable to publish dnskeys for zone %s: error decoding literal dnskey", apexstr);
                ldns_rr_list_deep_free(rr_list_clone);
                return status;
            }
            /* Add signature */
            names_recordaddsignature2(rrset, rrset->rrtype, rrsig, NULL, 0);
            newsigs++;
            /* ixfr +RRSIG */
        }
    }
    /* RRset signing completed */
    ldns_rr_list_free(rr_list);
    ldns_rr_list_deep_free(rr_list_clone);
#ifndef NOODS
    pthread_mutex_lock(&zone->stats->stats_lock);
    if (rrset->rrtype == LDNS_RR_TYPE_SOA) {
        zone->stats->sig_soa_count += newsigs;
    }
    zone->stats->sig_count += newsigs;
    zone->stats->sig_reuse += reusedsigs;
    pthread_mutex_unlock(&zone->stats->stats_lock);
#endif
    return 0;
}

static void
denial_create_bitmap(names_view_type view, dictionary record, ldns_rr_type nsectype, ldns_rr_type** types, size_t* types_count)
{
    names_iterator iter;
    ldns_rr_type rrtype;
    ldns_rr_type occludedstatus = domain_is_occluded(view, record);
    ldns_rr_type delegptstatus = domain_is_delegpt(view, record);
    /* Type Bit Maps */
    switch(nsectype) {
        case LDNS_RR_TYPE_NSEC3:
            if (occludedstatus == LDNS_RR_TYPE_SOA) {
                if (delegptstatus != LDNS_RR_TYPE_NS && record->nitemsets > 0) {
                    *types = malloc(sizeof(ldns_rr_type) * (*types_count = 1));
                    (*types)[0] = LDNS_RR_TYPE_RRSIG;
                }
            }
            break;
        case LDNS_RR_TYPE_NSEC:
        default:
            *types = malloc(sizeof(ldns_rr_type) * (*types_count = 2));
            (*types)[0] = LDNS_RR_TYPE_RRSIG;
            (*types)[1] = nsectype;
            break;
    }
    if (occludedstatus == LDNS_RR_TYPE_SOA) {
        if (delegptstatus == LDNS_RR_TYPE_SOA || rrtype == LDNS_RR_TYPE_NS || rrtype == LDNS_RR_TYPE_DS) {
            for(iter=names_recordalltypes2(record); names_iterate(&iter,&rrtype); names_advance(&iter,NULL)) {
                /* Authoritative or delegation */
                *types = realloc(types, sizeof(ldns_rr_type) * ++*types_count);
                (*types)[*types_count] = rrtype;
            }
        }
    }
}

static ldns_rdf*
denial_create_nsec3_nxt(ldns_rdf* nxt)
{
    ldns_status status = LDNS_STATUS_OK;
    ldns_rdf* next_owner_label = NULL;
    ldns_rdf* next_owner_rdf = NULL;
    char* next_owner_string = NULL;

    ods_log_assert(nxt);
    next_owner_label = ldns_dname_label(nxt, 0);
    if (!next_owner_label) {
        ods_log_alert("[%s] unable to create NSEC3 Next: ldns_dname_label() failed");
        return NULL;
    }
    next_owner_string = ldns_rdf2str(next_owner_label);
    if (!next_owner_string) {
        ods_log_alert("[%s] unable to create NSEC3 Next: ldns_rdf2str() failed");
        ldns_rdf_deep_free(next_owner_label);
        return NULL;
    }
    if (next_owner_string[strlen(next_owner_string)-1] == '.') {
        next_owner_string[strlen(next_owner_string)-1] = '\0';
    }
    status = ldns_str2rdf_b32_ext(&next_owner_rdf, next_owner_string);
    if (status != LDNS_STATUS_OK) {
        ods_log_alert("[%s] unable to create NSEC3 Next: ldns_str2rdf_b32_ext() failed");
    }
    free((void*)next_owner_string);
    ldns_rdf_deep_free(next_owner_label);
    return next_owner_rdf;
}

static ldns_rr*
denial_create_nsec(names_view_type view, dictionary domain, ldns_rdf* nxt, uint32_t ttl,
    ldns_rr_class klass, nsec3params_type* n3p)
{
    ldns_rr* nsec_rr;
    ldns_rr_type rrtype;
    ldns_rr_type dstatus = LDNS_RR_TYPE_FIRST;
    ldns_rdf* rdf = NULL;
    ldns_rr_type* types;
    size_t types_count = 0;
    int i = 0;
    ods_log_assert(nxt);
    nsec_rr = ldns_rr_new();
    /* RRtype */
    if (n3p) {
        rrtype = LDNS_RR_TYPE_NSEC3;
    } else {
        rrtype = LDNS_RR_TYPE_NSEC;
    }
    ldns_rr_set_type(nsec_rr, rrtype);
    /* owner */
    rdf = ldns_rdf_clone(domain->spanhashrr);
    if (!rdf) {
        ods_log_alert("[%s] unable to create NSEC(3) RR: ldns_rdf_clone(owner) failed");
        ldns_rr_free(nsec_rr);
        return NULL;
    }
    ldns_rr_set_owner(nsec_rr, rdf);
    /* NSEC3 parameters */
    if (n3p) {
        /* set all to NULL first, then call nsec3_add_param_rdfs. */
#ifndef SE_NSEC3_RDATA_NSEC3PARAMS
#define SE_NSEC3_RDATA_NSEC3PARAMS 4
#endif
        for (i=0; i < SE_NSEC3_RDATA_NSEC3PARAMS; i++) {
            ldns_rr_push_rdf(nsec_rr, NULL);
        }
        ldns_nsec3_add_param_rdfs(nsec_rr, n3p->algorithm, n3p->flags, n3p->iterations, n3p->salt_len, n3p->salt_data);
    }
    /* NXT */
    if (n3p) {
        rdf = denial_create_nsec3_nxt(nxt);
    } else {
        rdf = ldns_rdf_clone(nxt);
    }
    if (!rdf) {
        ods_log_alert("unable to create NSEC(3) RR: create next field failed");
        ldns_rr_free(nsec_rr);
        return NULL;
    }
    ldns_rr_push_rdf(nsec_rr, rdf);
    denial_create_bitmap(view, domain, (n3p?LDNS_RR_TYPE_NSEC3:LDNS_RR_TYPE_NSEC), &types, &types_count);
    rdf = ldns_dnssec_create_nsec_bitmap(types, types_count, rrtype);
    if (!rdf) {
        ods_log_alert("unable to create NSEC(3) RR: ldns_dnssec_create_nsec_bitmap() failed");
        ldns_rr_free(nsec_rr);
        return NULL;
    }
    ldns_rr_push_rdf(nsec_rr, rdf);
    ldns_rr_set_ttl(nsec_rr, ttl);
    ldns_rr_set_class(nsec_rr, klass);
    return nsec_rr;
}

void
denial_nsecify(signconf_type* signconf, names_view_type view, dictionary domain, ldns_rdf* nxt, uint32_t* num_added)
{
    ldns_rr* nsec_rr = NULL;
    uint32_t ttl = 0;
    /* SOA MINIMUM */
    if (signconf->soa_min) {
        ttl = (uint32_t) duration2time(signconf->soa_min);
    } else {
        ttl = names_viewgetdefaultttl(view);
    }
    /* create new NSEC(3) rr */
    nsec_rr = denial_create_nsec(view, domain, nxt, ttl, LDNS_RR_CLASS_IN, signconf->nsec3params);
    domain->spanhashrr = nsec_rr;
}

int
lhsm_sign(hsm_ctx_t* ctx, ldns_rr_list* rrset, key_type* key_id, time_t inception, time_t expiration, ldns_rr** rrsig)
{
    *rrsig = NULL;
    return 0;
}

key_type*
keylist_lookup_by_locator(keylist_type* kl, const char* locator)
{
    return &kl[0];
}
