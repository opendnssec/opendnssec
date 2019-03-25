/*
 * Copyright (c) 2018 NLNet Labs.
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

#include "config.h"

#pragma GCC optimize ("O0")

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ldns/ldns.h>
#include "utilities.h"
#include "logging.h"
#include "views/proto.h"
#include "duration.h"
#include "util.h"
#include "compat.h"
#include "hsm.h"

static logger_cls_type cls = LOGGER_INITIALIZE("signing");

ods_status
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
domain_is_delegpt(names_view_type view, recordset_type record)
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
domain_is_occluded(names_view_type view, recordset_type record)
{
    names_iterator iter;
    recordset_type parent = NULL;
    if(names_recordhasdata(record, LDNS_RR_TYPE_SOA, NULL, 0))
        return LDNS_RR_TYPE_SOA;
    for(iter=names_viewiterator(view,names_iteratorancestors,names_recordgetname(record)); names_iterate(&iter,&parent); names_advance(&iter,NULL)) {
        if (names_recordhasdata(parent, LDNS_RR_TYPE_SOA, NULL, 0)) {
            names_end(&iter);
            return LDNS_RR_TYPE_SOA;
        }
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




#ifdef NOTDEFINED
static uint32_t
rrset_recycle(signconf_type* signconf, recordset_type domain, ldns_rr_type rrtype, ldns_rr_list* rrset, ldns_rr_list* rrsigs, time_t signtime, ldns_rr_type dstatus, ldns_rr_type delegpt)
{
    uint32_t refresh;
    uint32_t expiration;
    uint32_t inception;
    uint32_t reusedsigs;
    unsigned drop_sig;
    key_type* key = NULL;
    ldns_rr* rrsig;
    names_iterator iter;
    ldns_rr_list* newrrsigs;
    newrrsigs = ldns_rr_list_new();

    /* Calculate the Refresh Window = Signing time + Refresh */
    if (signconf && signconf->sig_refresh_interval) {
        refresh = (uint32_t) (signtime + duration2time(signconf->sig_refresh_interval));
    }
    /* Check every signature if it matches the recycling logic. */
    while((rrsig = ldns_rr_list_pop_rr(rrsigs))) {
        drop_sig = 0;
        /* 0. Skip delegation, glue and occluded RRsets */
        if (dstatus != LDNS_RR_TYPE_SOA || (delegpt != LDNS_RR_TYPE_SOA && rrtype != LDNS_RR_TYPE_DS)) {
            drop_sig = 1;
        } else {
            ods_log_assert(dstatus == LDNS_RR_TYPE_SOA || (delegpt == LDNS_RR_TYPE_SOA || rrtype == LDNS_RR_TYPE_DS));
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
            expiration = ldns_rdf2native_int32(ldns_rr_rrsig_expiration(rrsig));
            if (expiration < refresh) {
                drop_sig = 1;
            }
        }
        /* 4. Inception has not yet passed */
        if(!drop_sig) {
            inception = ldns_rdf2native_int32(ldns_rr_rrsig_inception(rrsig));
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
            // FIXME clear expiry to force resign
        } else {
            /* All rules ok, recycle signature */
            reusedsigs += 1;
        }
    }
    ldns_rr_list_push_rr_list(rrsigs, newrrsigs);
    ldns_rr_list_free(newrrsigs);
    return reusedsigs;
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

#endif




struct rrsigkeymatching {
    struct signature_struct* signature;
    key_type* key;
};

static int
rrsigkeyismatching(struct signature_struct* signature, key_type* key)
{
    if(signature->keyflags == key->flags && !strcmp(signature->keylocator,key->locator)) {
        return 1;
    } else {
        return 0;
    }
}

static void 
rrsigkeymatching(signconf_type* signconf, struct signature_struct** rrsigs, struct rrsigkeymatching** rrsigkeymatchingptr, int* nrrsigkeymatchingptr)
{
    int nmatches = 0;
    int nrrsigs = 0;
    for(i=0; rrsigs[i]; i++)
        ++nrrsigs;
    struct rrsigkeymatching* matches = malloc(sizeof(struct rrsigkeymatching) * (signconf->keys->count + nrrsigs));
    for(int i=0; i<nrrsigs; i++) {
        matches[nmatches].signature = rrsigs[i];
        matches[nmatches].key = NULL;
        ++nmatches;
    }
    for(int keyidx=0; keyidx<signconf->keys->count; keyidx++) {
        int matchidx;
        for(matchidx=0; matchidx<nmatches; matchidx++) {
            if(matches[matchidx].signature && rrsigkeyismatching(matches[matchidx].signature, &signconf->keys->keys[keyidx])) {
                matches[matchidx].key = &signconf->keys->keys[keyidx];
                break;
            }
        }
        if(matchidx==nmatches) {
            matches[nmatches].signature = NULL;
            matches[nmatches].key = &signconf->keys->keys[keyidx];
            ++nmatches;
        }
    }
    *rrsigkeymatchingptr = matches;
    *nrrsigkeymatchingptr = nmatches;
}


/**
 * Sign RRset.
 *
 */
ods_status
rrset_sign(signconf_type* signconf, names_view_type view, recordset_type record, ldns_rr_type rrtype, hsm_ctx_t* ctx, time_t signtime)
{
    ods_status status;
    uint32_t newsigs;
    ldns_rr* rrsig;
    time_t inception;
    time_t expiration;
    ldns_rr_type dstatus = LDNS_RR_TYPE_FIRST;
    ldns_rr_type delegpt = LDNS_RR_TYPE_FIRST;
    ldns_rr_list* rrset = NULL;
    int nmatchedsignatures;

    /* Calculate the Refresh Window = Signing time + Refresh */
    uint32_t refresh = 0;
    if (signconf && signconf->sig_refresh_interval) {
        refresh = (uint32_t) (signtime + duration2time(signconf->sig_refresh_interval));
    }

    struct signature_struct** signatures;
    struct rrsigkeymatching* matchedsignatures;
    names_recordlookupall(record, rrtype, NULL, &rrset, &signatures);
    rrsigkeymatching(signconf, signatures, &matchedsignatures, &nmatchedsignatures);
    free(signatures);

    /* Transmogrify rrset */
    if (ldns_rr_list_rr_count(rrset) <= 0) {
        if(rrset) ldns_rr_list_free(rrset);
        /* Empty RRset, no signatures needed */
        return 0;
    }

    ldns_rr_list_sort(rrset);

    /* Recycle signatures */
    if (rrtype == LDNS_RR_TYPE_NSEC ||
        rrtype == LDNS_RR_TYPE_NSEC3) {
        dstatus = LDNS_RR_TYPE_SOA;
        delegpt = LDNS_RR_TYPE_SOA;
    } else {
        dstatus = domain_is_occluded(view, record);
        delegpt = domain_is_delegpt(view, record);
    }

    /* Skip delegation, glue and occluded RRsets */
    if (dstatus != LDNS_RR_TYPE_SOA) {
        if(rrset) ldns_rr_list_free(rrset);
        return 0;
    }
    if (delegpt != LDNS_RR_TYPE_SOA && rrtype != LDNS_RR_TYPE_DS) {
        if(rrset) ldns_rr_list_free(rrset);
        return 0;
    }
    
    /* for each signature,key pair, dettermin whether the signature is valid and/or the key
     * should produce a signature.
     */
    for (int i=0; i<nmatchedsignatures; i++) {
        if(matchedsignatures[i].signature) {
            expiration = ldns_rdf2native_int32(ldns_rr_rrsig_expiration(matchedsignatures[i].signature->rr));
            inception = ldns_rdf2native_int32(ldns_rr_rrsig_inception(matchedsignatures[i].signature->rr));
        }
        if (matchedsignatures[i].key && !matchedsignatures[i].key->zsk && rrtype != LDNS_RR_TYPE_DNSKEY) {
            /* If not ZSK don't sign other RRsets */
            matchedsignatures[i].key = NULL;
            matchedsignatures[i].signature = NULL;
        } else if (matchedsignatures[i].key && !matchedsignatures[i].key->ksk && rrtype == LDNS_RR_TYPE_DNSKEY) {
            /* If not KSK don't sign DNSKEY RRset */
            matchedsignatures[i].key = NULL;
            matchedsignatures[i].signature = NULL;
        } else if (matchedsignatures[i].key && matchedsignatures[i].key->ksk && matchedsignatures[i].key->locator == NULL) {
            /* If key has no locator, and should be pre-signed dnskey RR, skip */
            matchedsignatures[i].key = NULL;
        } else if (refresh <= (uint32_t) signtime) {
            /* If Refresh is disabled, drop all signatures */
            matchedsignatures[i].signature = NULL;
        } else if (matchedsignatures[i].signature && expiration < refresh) {
            /* Expiration - Refresh has passed */
            matchedsignatures[i].signature = NULL;
        } else if (matchedsignatures[i].signature && inception > (uint32_t) signtime) {
            /* Inception has not yet passed */
            matchedsignatures[i].signature = NULL;
        } else if (matchedsignatures[i].signature && !matchedsignatures[i].key) {
            matchedsignatures[i].signature = NULL;
        } else if (dstatus != LDNS_RR_TYPE_SOA || (delegpt != LDNS_RR_TYPE_SOA && rrtype != LDNS_RR_TYPE_DS)) {
            /* Skip delegation, glue and occluded RRsets */
        } else {
            ods_log_assert(dstatus == LDNS_RR_TYPE_SOA || (delegpt == LDNS_RR_TYPE_SOA || rrtype == LDNS_RR_TYPE_DS));
        }
    }
    /* At this time, each signature, key pair is valid, if there is a signature and a key, it is valid, if there is 
     * no key, there should be no signature, if there is no key, there should be no signature.  However for DNS
     * optimization, there needs to be no signature, if there is a signature for another key with the same algorithm
     * that is still valid.
     */
    for (int i=0; i<nmatchedsignatures; i++) {
        if(!matchedsignatures[i].signature && matchedsignatures[i].key) {
            /* We now know this key doesn't sign the set, we will only
             * sign when there isn't already an active key for that algorithm
             */
            int j;
            for(j=0; j<nmatchedsignatures; j++) {
                if(j!=i) {
                    if(matchedsignatures[j].key && matchedsignatures[j].signature && matchedsignatures[j].key->algorithm == matchedsignatures[i].key->algorithm) {
                        break;
                    }
                }
            }
            if (j < nmatchedsignatures) {
                matchedsignatures[i].key = NULL;
                matchedsignatures[i].signature = NULL;
            }
        }
    }
    /* Calculate signature validity for new signatures */
    rrset_sigvalid_period(signconf, rrtype, signtime, &inception, &expiration);
    /* for each missing signature (no signature, but with key in the tuplie list) produce a signature */
    for (int i = 0; i < nmatchedsignatures; i++) {
        if (!matchedsignatures[i].signature && matchedsignatures[i].key) {
            /* Sign the RRset with this key */
            logger_message(&cls,logger_noctx,logger_TRACE, "sign %s with key %s inception=%ld expiration=%ld delegation=%s occluded=%s\n",names_recordgetname(record),matchedsignatures[i].key->locator,(long)expiration,(long)expiration,(delegpt!=LDNS_RR_TYPE_SOA?"yes":"no"),(dstatus!=LDNS_RR_TYPE_SOA?"yes":"no"));
            rrsig = lhsm_sign(ctx, rrset, matchedsignatures[i].key, inception, expiration);
            if (rrsig == NULL) {
                ods_log_crit("unable to sign RRset[%i]: lhsm_sign() failed", rrtype);
                return ODS_STATUS_HSM_ERR;
            }
            /* Add signature */
            names_recordaddsignature(record, rrtype, rrsig, strdup(matchedsignatures[i].key->locator), matchedsignatures[i].key->flags);
            newsigs++;
        }
        /* Add signatures for DNSKEY if have been configured to be added explicitjy */
        if(rrtype == LDNS_RR_TYPE_DNSKEY && signconf->dnskey_signature) {
            ldns_rdf* apex = NULL;
            names_viewgetapex(view, &apex);
            for(int j=0; signconf->dnskey_signature[j]; j++) {
                rrsig = NULL;
                if ((status = rrset_getliteralrr(&rrsig, signconf->dnskey_signature[j], duration2time(signconf->dnskey_ttl), apex))) {
                    ods_log_error("unable to publish dnskeys for zone %s: error decoding literal dnskey", signconf->name);
                    if(apex)
                        ldns_rdf_free(apex);
                    if(rrset) ldns_rr_list_free(rrset);
                    return status;
                }
                /* Add signature */
                names_recordaddsignature(record, rrtype, rrsig, NULL, 0);
                newsigs++;
                /* ixfr +RRSIG */
            }
            if(apex)
                ldns_rdf_free(apex);
        }
    }

    /* RRset signing completed */
    if(rrset) ldns_rr_list_free(rrset);
    free(matchedsignatures);
    return 0;
}

static void
denial_create_bitmap(names_view_type view, recordset_type record, ldns_rr_type nsectype, ldns_rr_type** types, size_t* types_count)
{
    names_iterator iter;
    ldns_rr_type rrtype;
    ldns_rr_type occludedstatus = domain_is_occluded(view, record);
    ldns_rr_type delegptstatus = domain_is_delegpt(view, record);
    *types = NULL;
    /* Type Bit Maps */
    switch(nsectype) {
        case LDNS_RR_TYPE_NSEC3:
            if (occludedstatus == LDNS_RR_TYPE_SOA) {
                if (delegptstatus != LDNS_RR_TYPE_NS /* FIXME investigate if the next predicate could still happen: && record->nitemsets > 0*/) {
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
        for(iter=names_recordalltypes(record); names_iterate(&iter,&rrtype); names_advance(&iter,NULL)) {
            if (delegptstatus == LDNS_RR_TYPE_SOA || rrtype == LDNS_RR_TYPE_NS || rrtype == LDNS_RR_TYPE_DS) {
                /* Authoritative or delegation */
                *types_count += 1;
                *types = realloc(*types, sizeof(ldns_rr_type) * *types_count);
                (*types)[*types_count - 1] = rrtype;
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
        ods_log_alert("unable to create NSEC3 Next: ldns_dname_label() failed");
        return NULL;
    }
    next_owner_string = ldns_rdf2str(next_owner_label);
    if (!next_owner_string) {
        ods_log_alert("unable to create NSEC3 Next: ldns_rdf2str() failed");
        ldns_rdf_deep_free(next_owner_label);
        return NULL;
    }
    if (next_owner_string[strlen(next_owner_string)-1] == '.') {
        next_owner_string[strlen(next_owner_string)-1] = '\0';
    }
    status = ldns_str2rdf_b32_ext(&next_owner_rdf, next_owner_string);
    if (status != LDNS_STATUS_OK) {
        ods_log_alert("unable to create NSEC3 Next: ldns_str2rdf_b32_ext() failed");
    }
    free((void*)next_owner_string);
    ldns_rdf_deep_free(next_owner_label);
    return next_owner_rdf;
}

static ldns_rr*
denial_create_nsec(names_view_type view, recordset_type domain, ldns_rdf* nxt, uint32_t ttl,
    ldns_rr_class klass, nsec3params_type* n3p)
{
    const char* denialname;
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
    if(n3p) {
        denialname = names_recordgetdenial(domain);
    } else {
        denialname = names_recordgetname(domain);
    }
    rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, denialname); // FIXME denial name for NSEC3, NSEC for uses name
    if (!rdf) {
        ods_log_alert("unable to create NSEC(3) RR: ldns_rdf_clone(owner) failed");
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
    free(types);
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

ldns_rr*
denial_nsecify(signconf_type* signconf, names_view_type view, recordset_type domain, ldns_rdf* nxt)
{
    ldns_rr* nsec_rr = NULL;
    int ttl = 0;
    /* SOA MINIMUM */
    names_viewgetdefaultttl(view, &ttl);
    if (signconf->soa_min) {
        ttl = duration2time(signconf->soa_min);
    }
    /* create new NSEC(3) rr */
    nsec_rr = denial_create_nsec(view, domain, nxt, ttl, LDNS_RR_CLASS_IN, signconf->nsec3params);
    return nsec_rr;
}

/**
 * Delete NSEC3PARAM RRs.
 *
 * Marks all NSEC3PARAM records as removed.
 */
ods_status
zone_del_nsec3params(zone_type* zone, names_view_type view)
{
    recordset_type record = names_take(view, 0, NULL);
    if(record) {
        names_amend(view, record);
        names_recorddeldata(record, LDNS_RR_TYPE_NSEC3PARAMS, NULL);
    }

    return ODS_STATUS_OK;
}

ods_status
namedb_domain_entize(names_view_type view, recordset_type domain, ldns_rdf* dname, ldns_rdf* apex)
{
    char* parent_name;
    ldns_rdf* parent_rdf = NULL;
    recordset_type parent_domain;
    ods_log_assert(apex);
    ods_log_assert(domain);

    while (domain && ldns_dname_is_subdomain(dname, apex) &&
           ldns_dname_compare(dname, apex) != 0) {
        /**
         * RFC5155:
         * 4. If the difference in number of labels between the apex and
         *    the original owner name is greater than 1, additional NSEC3
         *    RRs need to be added for every empty non-terminal between
         *     the apex and the original owner name.
         */
        parent_rdf = ldns_dname_left_chop(dname);
        if (!parent_rdf) {
            ods_log_error("unable to entize domain: left chop failed");
            return ODS_STATUS_ERR;
        }
        parent_name = ldns_rdf2str(parent_rdf);
        parent_domain = names_take(view, 0, parent_name);
        if (!parent_domain) {
            parent_domain = names_place(view, parent_name);
            ldns_rdf_deep_free(parent_rdf);
            free(parent_name);
            if (!parent_domain) {
                ods_log_error("unable to entize domain: failed to add parent domain");
                return ODS_STATUS_ERR;
            }
            /* continue with the parent domain */
            domain = parent_domain;
        } else {
            ldns_rdf_deep_free(parent_rdf);
            free(parent_name);
            /* domain has parent, entize done */
            domain = NULL;
        }
    }
    return ODS_STATUS_OK;
}

ods_status
namedb_update_serial(zone_type* zone)
{
    const char* format = zone->signconf->soa_serial;
    uint32_t serial;
    if (zone->nextserial) {
        serial = *zone->nextserial;
        free(zone->nextserial);
        zone->nextserial = NULL;
    } else if (!strcmp(format, "unixtime")) {
        serial = (uint32_t) time_now();
    } else if (!strcmp(format, "datecounter")) {
        serial = (uint32_t) time_datestamp(0, "%Y%m%d", NULL) * 100;
    } else if (!strcmp(format, "counter")) {
        if(zone->inboundserial) {
            serial = *(zone->inboundserial) + 1;
            if (zone->outboundserial && !util_serial_gt(serial, *(zone->outboundserial))) {
                serial = *(zone->outboundserial) + 1;
            }
        } else if(zone->outboundserial) {
            serial = *(zone->outboundserial) + 1;
        }
    } else if (!strcmp(format, "keep")) {
        serial = *(zone->inboundserial);
    } else {
        ods_log_error("zone %s unknown serial type %s", zone->name, format);
        return ODS_STATUS_ERR;
    }
    if(zone->nextserial) {
        free(zone->nextserial);
        zone->nextserial = NULL;
    }
    zone->nextserial = malloc(sizeof(uint32_t));
    *zone->nextserial = serial;
    return ODS_STATUS_OK;
}

ods_status
zone_update_serial(zone_type* zone, names_view_type view)
{
    ods_status status = ODS_STATUS_OK;
    ldns_rr* rr = NULL;
    ldns_rdf* soa_rdata = NULL;
    uint32_t serial;

    ods_log_assert(zone);
    ods_log_assert(zone->apex);
    ods_log_assert(zone->name);
    ods_log_assert(zone->signconf);

    recordset_type d = names_take(view, 3, NULL);
    assert(d);

    if(!zone->inboundserial) {
        names_recordlookupone(d, LDNS_RR_TYPE_SOA, NULL, &rr);
        assert(rr);
        serial = ldns_rdf2native_int32(ldns_rr_rdf(rr, 2));
        zone->inboundserial = malloc(sizeof(uint16_t));
        *(zone->inboundserial) = serial;
        rr = NULL;
    }
    /* FIXME set min TTL from signconf */

    serial = *(zone->nextserial);
    free(zone->nextserial);
    zone->nextserial = NULL;
    /* FIXME we should also disallow a forced serial lower then this discarded nextserial */

    if(names_recordhasexpiry(d)) {
        names_amend(view, d);
        names_recordsetvalidupto(d, serial);
        names_underwrite(view, &d);
        names_recordsetvalidfrom(d, serial);
    } else {
        names_underwrite(view, &d);
        names_recordsetvalidfrom(d, serial);
    }
    names_recordlookupone(d, LDNS_RR_TYPE_SOA, NULL, &rr);
    rr = ldns_rr_clone(rr);;
    names_recorddelall(d, LDNS_RR_TYPE_SOA);
    if(zone->outboundserial)
        free(zone->outboundserial);
    zone->outboundserial = malloc(sizeof(uint32_t));
    *(zone->outboundserial) = serial;
    soa_rdata = ldns_rr_set_rdf(rr, ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, serial), 2);
    if (soa_rdata) {
        ldns_rdf_deep_free(soa_rdata);
    } else {
        ods_log_error("unable to update zone %s soa serial: failed to replace soa serial rdata", zone->name);
        ldns_rr_free(rr);
        return ODS_STATUS_ERR;
    }
    if (zone->signconf->soa_ttl) {
        ldns_rr_set_ttl(rr, (uint32_t) duration2time(zone->signconf->soa_ttl));
    }
    if (zone->signconf->soa_min) {
        soa_rdata = ldns_rr_set_rdf(rr, ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, (uint32_t) duration2time(zone->signconf->soa_min)), 6);
        if (soa_rdata) {
            ldns_rdf_deep_free(soa_rdata);
            soa_rdata = NULL;
        } else {
            ods_log_error("unable to adapt soa to zone %s: failed to replace soa minimum rdata", zone->name);
            return ODS_STATUS_ASSERT_ERR;
        }
    }
    names_recordadddata(d, rr);
    ldns_rr_free(rr);
    return ODS_STATUS_OK;
}
