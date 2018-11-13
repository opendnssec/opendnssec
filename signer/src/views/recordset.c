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

struct item {
    ldns_rr* rr;
};

struct itemset {
    ldns_rr_type rrtype;
    int nitems;
    struct item* items;
    struct signatures_struct* signatures;
};

struct recordset_struct {
    char* name;
    int revision;
    int marker;
    ldns_rr* spanhashrr;
    char* spanhash;
    struct signatures_struct* spansignatures;
    int* validupto;
    int* validfrom;
    int64_t* expiry;
    int nitemsets;
    struct itemset* itemsets;
};

static void
names_signaturedispose(struct signatures_struct** signatures)
{
    int i;
    if(*signatures) {
        for (i=0; i<(*signatures)->nsigs; i++) {
            free((void*)(*signatures)->sigs[i].keylocator);
            ldns_rr_free((*signatures)->sigs[i].rr);
        }
        free((*signatures)->sigs);
        free((*signatures));
        *signatures = NULL;
    }
}

void
names_recordaddsignature(recordset_type d, ldns_rr_type rrtype, ldns_rr* rrsig, const char* keylocator, int keyflags)
{
    int i, j;
    for(i=0; i<d->nitemsets; i++)
        if(rrtype == d->itemsets[i].rrtype)
            break;
    if (i<d->nitemsets) {
        if(!d->itemsets[i].signatures) {
            d->itemsets[i].signatures = malloc(sizeof(struct signatures_struct));
            d->itemsets[i].signatures->nsigs = 0;
            d->itemsets[i].signatures->sigs = NULL;
        }
        d->itemsets[i].signatures->nsigs += 1;
        d->itemsets[i].signatures->sigs = realloc(d->itemsets[i].signatures->sigs, sizeof(struct signature_struct) * d->itemsets[i].signatures->nsigs);
        d->itemsets[i].signatures->sigs[d->itemsets[i].signatures->nsigs-1].rr = rrsig;
        d->itemsets[i].signatures->sigs[d->itemsets[i].signatures->nsigs-1].keylocator = keylocator;
        d->itemsets[i].signatures->sigs[d->itemsets[i].signatures->nsigs-1].keyflags = keyflags;
    } else if(rrtype == LDNS_RR_TYPE_NSEC || rrtype == LDNS_RR_TYPE_NSEC3) {
        if(!d->spansignatures) {
            d->spansignatures = malloc(sizeof(struct signatures_struct));
            d->spansignatures->nsigs = 0;
            d->spansignatures->sigs = NULL;            
        }
        d->spansignatures->nsigs += 1;
        d->spansignatures->sigs = realloc(d->spansignatures->sigs, sizeof(struct signature_struct) * d->spansignatures->nsigs);
        d->spansignatures->sigs[d->spansignatures->nsigs-1].rr = rrsig;
        d->spansignatures->sigs[d->spansignatures->nsigs-1].keylocator = keylocator;
        d->spansignatures->sigs[d->spansignatures->nsigs-1].keyflags = keyflags;
    }
}

int
names_recordcompare_namerevision(recordset_type a, recordset_type b)
{
    int rc;
    rc = strcmp(a->name, b->name);
    if(rc == 0) {
        if(a->revision != 0 && b->revision != 0) {
            rc = a->revision - b->revision;
        }
    }
    return rc;
}

static recordset_type
recordcreate()
{
    struct recordset_struct* dict;
    dict = malloc(sizeof(struct recordset_struct));
    dict->nitemsets = 0;
    dict->itemsets = NULL;
    dict->spanhash = NULL;
    dict->spanhashrr = NULL;
    dict->spansignatures = NULL;
    dict->validupto = NULL;
    dict->validfrom = NULL;
    dict->expiry = NULL;
    dict->marker = 0;
    return dict;
}

recordset_type
names_recordcreate(char** name)
{
    struct recordset_struct* dict;
    dict = recordcreate();
    if (name) {
        dict->name = *name = ((*name) ? strdup(*name) : NULL);
    } else {
        dict->name = NULL;
    }
    dict->revision = 1;
    return dict;
}

recordset_type
names_recordcreatetemp(const char* name)
{
    recordset_type dict;
    dict = recordcreate();
    dict->name = (name ? strdup(name) : NULL);
    dict->revision = 0;
    return dict;
}

void
names_recordannotate(recordset_type d, struct names_view_zone* zone)
{
    if(zone) {
        if(zone->signconf && *(zone->signconf) && (*(zone->signconf))->nsec3params) {
            nsec3params_type* n3p = (*zone->signconf)->nsec3params;
            ldns_rdf* dname;
            ldns_rdf* apex;
            ldns_rdf* hashed_label;
            ldns_rdf* hashed_ownername;
            dname = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, d->name);
            apex = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, zone->apex);
            /*
             * The owner name of the NSEC3 RR is the hash of the original owner
             * name, prepended as a single label to the zone name.
             */
            hashed_label = ldns_nsec3_hash_name(dname, n3p->algorithm, n3p->iterations, n3p->salt_len, n3p->salt_data);
            hashed_ownername = ldns_dname_cat_clone(hashed_label, apex);
            d->spanhash = ldns_rdf2str(hashed_ownername);
            ldns_rdf_deep_free(hashed_ownername);
            ldns_rdf_deep_free(hashed_label);
            ldns_rdf_deep_free(apex);
            ldns_rdf_deep_free(dname);
        } else {
            /* ldns_rdf* rdf;
             * ldns_rdf* revrdf;
             * rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, d->name);
             * ldns_dname2canonical(rdf);
             * revrdf = ldns_dname_reverse(rdf);
             * d->spanhash = ldns_rdf2str(revrdf);
             * ldns_rdf_deep_free(rdf);
             * ldns_rdf_deep_free(revrdf);
             */
            int i, j, end, len, l;
            end = len = strlen(d->name);
            d->spanhash = malloc(len+1);
            d->spanhash[end--] = '\0';
            for (i=0; i<len; ) {
                for (j=0; d->name[i+j]; j++) {
                    if (d->name[i+j] == '.')
                        break;
                }
                l = j;
                for(j=0; j<l; j++) {
                    d->spanhash[end--] = d->name[i+l-j-1];
                }
                i += l;
                if (i != len) {
                    d->spanhash[end--] = '~';
                    i++;
                }
            }
        }
    } else {
        if(d->spanhash)
            free(d->spanhash);
        if(d->spanhashrr)
            ldns_rr_free(d->spanhashrr);
        d->spanhash = NULL;
        d->spanhashrr = NULL;
    }
}

recordset_type
names_recordcopy(recordset_type dict, int clear)
{
    int i, j;
    struct recordset_struct* target;
    char* name = dict->name;
    target = (struct recordset_struct*) names_recordcreate(&name);
    target->revision = dict->revision + 1;
    target->nitemsets = dict->nitemsets;
    CHECKALLOC(target->itemsets = malloc(sizeof(struct itemset) * target->nitemsets));
    for(i=0; i<target->nitemsets; i++) {
        target->itemsets[i].rrtype = dict->itemsets[i].rrtype;
        target->itemsets[i].nitems = dict->itemsets[i].nitems;
        target->itemsets[i].items = malloc(sizeof(struct item) * dict->itemsets[i].nitems);
        target->itemsets[i].signatures = NULL;
        for(j=0; j<dict->itemsets[i].nitems; j++) {
            target->itemsets[i].items[j].rr = ldns_rr_clone(dict->itemsets[i].items[j].rr);
        }
    }
    target->spanhash = (dict->spanhash ? strdup(dict->spanhash) : NULL);
    target->spanhashrr = (dict->spanhashrr ? ldns_rr_clone(dict->spanhashrr) : NULL);
    names_signaturedispose(&target->spansignatures);
    if(clear == 0) {
        if(dict->expiry) {
            target->expiry = malloc(sizeof(int64_t));
            *(target->expiry) = *(dict->expiry);
        } else
            target->expiry = NULL;
        if(dict->validfrom) {
            target->validfrom = malloc(sizeof(int));
            *(target->validfrom) = *(dict->validfrom);
        } else
            target->validfrom = NULL;
        if(dict->validupto) {
            target->validupto = malloc(sizeof(int));
            *(target->validupto) = *(dict->validupto);
        } else
            target->validupto = NULL;
    }
    return target;
}

int
names_recordhasdata(recordset_type record, ldns_rr_type recordtype, ldns_rr* rr, int exact)
{
    int i, j;
    if(!record)
        return 0;
    if(recordtype == 0) { /* note there is no rrtype of 0 in DNS */
        return record->nitemsets > 0;
    } else {
        for(i=0; i<record->nitemsets; i++)
            if(record->itemsets[i].rrtype == recordtype)
                break;
        if (i<record->nitemsets) {
            if(rr == NULL) {
                return record->itemsets[i].nitems > 0;
            } else {
                for(j=0; j<record->itemsets[i].nitems; j++)
                    if(!ldns_rr_compare(rr, record->itemsets[i].items[j].rr))
                        break;
                if (j<record->itemsets[i].nitems) {
                    if(exact) {
                        if(ldns_rr_ttl(record->itemsets[i].items[j].rr) != ldns_rr_ttl(rr))
                            return 0;
                        return  1;
                    } else
                        return 1;
                }
            }
        }
    }
    return 0;
}

void
names_recordadddata(recordset_type d, ldns_rr* rr)
{
    int i, j;
    ldns_rr_type rrtype;
    rrtype = ldns_rr_get_type(rr);
    for(i=0; i<d->nitemsets; i++)
        if(rrtype == d->itemsets[i].rrtype)
            break;
    if (i==d->nitemsets) {
        d->nitemsets += 1;
        CHECKALLOC(d->itemsets = realloc(d->itemsets, sizeof(struct itemset) * d->nitemsets));
        d->itemsets[i].rrtype = rrtype;
        d->itemsets[i].items = NULL;
        d->itemsets[i].nitems = 0;
        d->itemsets[i].signatures = NULL;
    }
    for(j=0; j<d->itemsets[i].nitems; j++)
        if(!ldns_rr_compare(rr, d->itemsets[i].items[j].rr))
            break;
    if (j==d->itemsets[i].nitems) {
        d->itemsets[i].nitems += 1;
        d->itemsets[i].items = realloc(d->itemsets[i].items, sizeof(struct item) * d->itemsets[i].nitems);
        d->itemsets[i].items[j].rr = ldns_rr_clone(rr);
    }
}

void
names_recorddeldata(recordset_type d, ldns_rr_type rrtype, ldns_rr* rr)
{
    int i, j;
    for(i=0; i<d->nitemsets; i++)
        if(rrtype == d->itemsets[i].rrtype)
            break;
    if (i<d->nitemsets) {
        if(rr) {
            for(j=0; j<d->itemsets[i].nitems; j++)
                if(ldns_rr_compare(rr, d->itemsets[i].items[j].rr))
                    break;
            if (j<d->itemsets[i].nitems) {
                ldns_rr_free(d->itemsets[i].items[j].rr);
                d->itemsets[i].nitems -= 1;
                for(; j<d->itemsets[i].nitems; j++) {
                    d->itemsets[i].items[j] = d->itemsets[i].items[j+1];
                }
                if(d->itemsets[i].nitems > 0) {
                    d->itemsets[i].items = realloc(d->itemsets[i].items, sizeof(struct item) * d->itemsets[i].nitems);
                } else {
                    free(d->itemsets[i].items);
                    d->itemsets[i].items = NULL;
                    d->nitemsets -= 1;
                    for(; i<d->nitemsets; i++)
                        d->itemsets[i] = d->itemsets[i+1];
                    if(d->nitemsets > 0) {
                        CHECKALLOC(d->itemsets = realloc(d->itemsets, sizeof(struct itemset) * d->nitemsets));
                    } else {
                        free(d->itemsets);
                        d->itemsets = NULL;
                    }
                }
            }
        } else {
            for(j=0; j<d->itemsets[i].nitems; j++) {
                ldns_rr_free(d->itemsets[i].items[j].rr);
            }
            free(d->itemsets[i].items);
            d->itemsets[i].items = NULL;
            d->nitemsets -= 1;
            for(; i<d->nitemsets; i++)
                d->itemsets[i] = d->itemsets[i+1];
            if(d->nitemsets > 0) {
                CHECKALLOC(d->itemsets = realloc(d->itemsets, sizeof(struct itemset) * d->nitemsets));
            } else {
                free(d->itemsets);
                d->itemsets = NULL;
            }
        }
    }
}

void
names_recorddelall(recordset_type d, ldns_rr_type rrtype)
{
    int i, j;
    for(i=0; i<d->nitemsets; i++) {
        if(rrtype==0 || d->itemsets[i].rrtype == rrtype) {
            for(j=0; j<d->itemsets[i].nitems; j++) {
                ldns_rr_free(d->itemsets[i].items[j].rr);
            }
            free(d->itemsets[i].items);
            names_signaturedispose(&d->itemsets[i].signatures);
            if(rrtype != 0)
                break;
        }
    }
    if(rrtype == 0) {
        free(d->itemsets); // FIXME
        d->itemsets = NULL;
        d->nitemsets = 0;
    } else if(i<d->nitemsets) {
        d->itemsets[i].items = NULL;
        d->nitemsets -= 1;
        for (; i < d->nitemsets; i++)
            d->itemsets[i] = d->itemsets[i + 1];
        if (d->nitemsets > 0) {
            CHECKALLOC(d->itemsets = realloc(d->itemsets, sizeof (struct itemset) * d->nitemsets));
        } else {
            free(d->itemsets); // FIXME
            d->itemsets = NULL;
        }        
    }
}

static void names_recordalltypes_func(names_iterator iter, void* base, int index, void* dst)
{
    recordset_type d = (recordset_type)base;
    ldns_rr_type* ptr = (ldns_rr_type*)dst;
    if(index >= 0)
        memcpy(ptr, &(d->itemsets[index].rrtype), sizeof(ldns_rr_type));
}
names_iterator
names_recordalltypes(recordset_type d)
{
    names_iterator iter;
    iter = names_iterator_createarray(d->nitemsets, d, names_recordalltypes_func);
    return iter;
}

static void names_recordallvaluestrings_func(names_iterator iter, void* base, int index, void* dst)
{
    struct item* items = (struct item*) base;
    char** ptr = (char**)dst;
    free(*ptr);
    if (index >= 0)
        *ptr = ldns_rr2str(items[index].rr);
    else
        *ptr = NULL;
}
names_iterator
names_recordallvaluestrings(recordset_type d, ldns_rr_type rrtype)
{
    int i;
    for(i=0; i<d->nitemsets; i++) {
        if(rrtype == d->itemsets[i].rrtype)
            break;
    }
    if(i<d->nitemsets) {
        int j;
        names_iterator iter = names_iterator_createrefs(free);
        for(j=0; j<d->itemsets[i].nitems; j++) {
            names_iterator_addptr(iter, ldns_rr2str(d->itemsets[i].items[j].rr));
        }
        if(d->itemsets[i].signatures) {
            for(j=0; j<d->itemsets[i].signatures->nsigs; j++) {
                names_iterator_addptr(iter, ldns_rr2str(d->itemsets[i].signatures->sigs[j].rr));
            }
        }
        return iter;
    } else {
        if(rrtype == LDNS_RR_TYPE_NSEC || rrtype == LDNS_RR_TYPE_NSEC3) {
            int j;
            names_iterator iter = names_iterator_createrefs(free);
            names_iterator_addptr(iter, ldns_rr2str(d->spanhashrr));
            if(d->spansignatures) {
                for(j=0; j<d->spansignatures->nsigs; j++) {
                    names_iterator_addptr(iter, ldns_rr2str(d->spansignatures->sigs[j].rr));
                }
            }
            return iter;            
        }
        return NULL;
    }
}

void
names_recorddispose(recordset_type dict)
{
    int i, j;
    for(i=0; i<dict->nitemsets; i++) {
        for(j=0; j<dict->itemsets[i].nitems; j++) {
            ldns_rr_free(dict->itemsets[i].items[j].rr);
        }
        names_signaturedispose(&dict->itemsets[i].signatures);
        free(dict->itemsets[i].items);
    }
    free(dict->itemsets);
    free(dict->name);
    free(dict->spanhash);
    if(dict->spanhashrr) {
        ldns_rr_free(dict->spanhashrr);
    }
    names_signaturedispose(&dict->spansignatures);
    free(dict->validupto);
    free(dict->validfrom);
    free(dict->expiry);
    free(dict);
}

void
names_recorddisposal(recordset_type record, int doit)
{
    if(doit) {
        if(record->marker)
            names_recorddispose(record);
    } else {
        record->marker = 1;
    }
}

const char*
names_recordgetname(recordset_type record)
{
    return record->name;
}

int
names_recordgetrevision(recordset_type record)
{
    return record->revision;
}

const char *
names_recordgetsummary(recordset_type dict, char** dest)
{
    char* s = NULL;
    if(dest && *dest)
        free(*dest);
    if(dict != NULL)
        asprintf(&s, "%s %d (from=%d upto=%d expiry=%ld)%s%s", dict->name, dict->revision,
                     (dict->validfrom?(int)*dict->validfrom:-2),
                     (dict->validupto?(int)*dict->validupto:-2),
                     (dict->expiry?(int64_t)*dict->expiry:-2),
                     (dict->spanhash?" ":""),(dict->spanhash?dict->spanhash:""));
    if(dest!=NULL)
        *dest = s;
    return (s?s:"");
}

const char*
names_recordgetdenial(recordset_type record)
{
    return record->spanhash;
}

int
names_recordvalidupto(recordset_type record, int* validupto)
{
    if(validupto)
        *validupto = *(record->validupto);
    return record->validupto != NULL;
}

void
names_recordsetvalidupto(recordset_type record, int value)
{
    assert(record->validupto == NULL);
    record->validupto = malloc(sizeof(int));
    *(record->validupto) = value;
}

int
names_recordvalidfrom(recordset_type record, int* validfrom)
{
    if(validfrom)
        *validfrom = *(record->validfrom);
    return record->validfrom != NULL;
}

void
names_recordsetvalidfrom(recordset_type record, int value)
{
    assert(record->validfrom == NULL);
    record->validfrom = malloc(sizeof(int));
    *(record->validfrom) = value;
}

int
names_recordcmpdenial(recordset_type record, ldns_rr* denial)
{
    if(record->spanhashrr == NULL || ldns_rr_compare(record->spanhashrr, denial)) {
        return 1;
    } else {
        return 0;
    }
}

void
names_recordsetdenial(recordset_type record, ldns_rr* denial)
{
    assert(denial != NULL);
    record->spanhashrr = denial;
}

int
names_recordhasexpiry(recordset_type record)
{
    return record->expiry != NULL;
}

int64_t
names_recordgetexpiry(recordset_type record)
{
    return *(record->expiry);
}

void
names_recordsetexpiry(recordset_type record, int64_t value)
{
    assert(record->expiry == NULL);
    record->expiry = malloc(sizeof(int64_t));
    *(record->expiry) = value;
}

int
marshall(marshall_handle h, void* ptr)
{
    recordset_type d = ptr;
    int size = 0;
    int i, j;
    size += marshalling(h, "name", &(d->name), NULL, 0, marshallstring);
    size += marshalling(h, "marker", &(d->marker), NULL, 0, marshallinteger);
    size += marshalling(h, "revision", &(d->revision), NULL, 0, marshallinteger);
    size += marshalling(h, "spanhash", &(d->spanhash), NULL, 0, marshallstring);
    size += marshalling(h, "spansignatures", &(d->spansignatures), marshall_OPTIONAL, sizeof(struct signatures_struct), marshallsigs);
    size += marshalling(h, "spanhashrr", &(d->spanhashrr), NULL, 0, marshallldnsrr);
    size += marshalling(h, "validupto", &(d->validupto), marshall_OPTIONAL, sizeof(int), marshallinteger);
    size += marshalling(h, "validfrom", &(d->validfrom), marshall_OPTIONAL, sizeof(int), marshallinteger);
    size += marshalling(h, "expiry", &(d->expiry), marshall_OPTIONAL, sizeof(int64_t), marshallint64);
    size += marshalling(h, "itemsets", &(d->itemsets), &(d->nitemsets), sizeof(struct itemset), marshallself);
    for(i=0; i<d->nitemsets; i++) {
        size += marshalling(h, "itemname", &(d->itemsets[i].rrtype), NULL, 0, marshallinteger);
        size += marshalling(h, "items", &(d->itemsets[i].items), &(d->itemsets[i].nitems), sizeof(struct item), marshallself);
        for(j=0; j<d->itemsets[i].nitems; j++) {
            size += marshalling(h, "rr", &(d->itemsets[i].items[j].rr), NULL, 0, marshallldnsrr);
            size += marshalling(h, NULL, NULL, &(d->itemsets[i].nitems), j, marshallself);
        }
        size += marshalling(h, "signatures", &(d->itemsets[i].signatures), marshall_OPTIONAL, sizeof(struct signatures_struct), marshallsigs);
        size += marshalling(h, NULL, NULL, &(d->nitemsets), i, marshallself);
    }
    return size;
}

int
names_recordmarshall(recordset_type* record, marshall_handle h)
{
    int rc;
    recordset_type dummy = NULL;
    if(record == NULL)
        record = &dummy;
    rc = marshalling(h, "domain", record, marshall_OPTIONAL, sizeof(struct recordset_struct), marshall);
    return rc;
}

#define DEFINECOMPARISON(N) \
    int N(recordset_type, recordset_type, int*); \
    int N ## _ldns(const void* a, const void* b) { \
    int rc; N((recordset_type)a, (recordset_type)b, &rc); return rc; }

DEFINECOMPARISON(compareready)
DEFINECOMPARISON(comparenamerevision)
DEFINECOMPARISON(comparenamehierarchy)
DEFINECOMPARISON(compareexpiry)
DEFINECOMPARISON(comparedenialname)
DEFINECOMPARISON(compareupcomingset)
DEFINECOMPARISON(compareincomingset)
DEFINECOMPARISON(comparecurrentset)
DEFINECOMPARISON(comparerelevantset)
DEFINECOMPARISON(comparesignedset)
DEFINECOMPARISON(comparechangesset)
DEFINECOMPARISON(comparedeletesset)
DEFINECOMPARISON(compareinsertsset)
DEFINECOMPARISON(compareoutdatedset)

int
comparenamerevision(recordset_type newitem, recordset_type curitem, int* cmp)
{
    if (curitem) {
        if (cmp) {
            assert(newitem);
            *cmp = strcmp(newitem->name, curitem->name);
            if(*cmp == 0 && newitem->revision != 0) {
                *cmp = newitem->revision - curitem->revision;
            }
        }
    }
    return 1;
}

int
comparenamehierarchy(recordset_type newitem, recordset_type curitem, int* cmp)
{
    if (curitem) {
        if (cmp) {
            assert(newitem);
            assert(curitem);
            *cmp = strcmp(curitem->name, newitem->name);
            if(*cmp == 0 && newitem->revision != 0) {
                *cmp = curitem->revision - newitem->revision;
            }
        }
    }
    return 1;
}

int
compareexpiry(recordset_type newitem, recordset_type curitem, int* cmp)
{
    if (curitem) {
        if (cmp) {
            *cmp = (newitem->expiry?*(newitem->expiry):0) - (curitem->expiry?*(curitem->expiry):0);
            if(*cmp == 0) {
                *cmp = strcmp(newitem->name,curitem->name);
                if(*cmp == 0) {
                    if(newitem->revision >= curitem->revision) {
                        return 2;
                    } else {
                        return 0;
                    }
                }
                assert(*cmp != 0 || newitem->revision == curitem->revision);
            }
        }
    }
    return 1;
}

/* rule: you cannot ammend a field when that field is in use for to store a record in an index */

int
comparedenialname(recordset_type newitem, recordset_type curitem, int* cmp)
{
    const char* left;
    const char* right;
    left = newitem->spanhash;
    if (curitem) {
        if(cmp) {
            right = curitem->spanhash;
            if(!left) left = "";
            if(!right) right = "";
            *cmp = strcmp(left, right);
            /* in case *cmp == 0 then we could make an assertion that
             * the names of a and b also need to be the same, otherwise
             * we have a hash collision we cannot continue with.
             */
        }
    }
    if (!left)
        return 0;
    return 1;
}

int
compareupcomingset(recordset_type newitem, recordset_type curitem, int* cmp)
{
    int c;
    if(curitem) {
        c = strcmp(newitem->name, curitem->name);
        if(cmp)
            *cmp = c;
        if(c == 0) {
            if(newitem->revision - curitem->revision <= 0) {
                return 0;
            }
        }
    }
    return 1;
}

int
compareincomingset(recordset_type newitem, recordset_type curitem, int* cmp)
{
    int rc = 1;
    int compare;
    if(curitem) {
        compare = strcmp(newitem->name, curitem->name);
        if(cmp)
            *cmp = compare;
        if(compare == 0) {
            if(newitem->revision - curitem->revision <= 0) {
                rc = 0;
            }
        }
    }
    if(newitem->validfrom) {
        if(curitem && compare == 0) {
            rc = 2;
        } else
            rc = 0;
    }
    return rc;
}

int
compareready(recordset_type newitem, recordset_type curitem, int* cmp)
{
    int c;
    if (curitem) {
        c = strcmp(curitem->name, newitem->name);
        if (cmp)
            *cmp = c;
        if (c == 0) {
            if (newitem->revision - curitem->revision <= 0)
                return 0;
        }
    }
    if (newitem->validupto)
        return 0;
    if (!newitem->validfrom)
        return 0;
    return 1;
}


int
comparecurrentset(recordset_type newitem, recordset_type curitem, int* cmp)
{
    if (curitem) {
        if (cmp) {
            *cmp = strcmp(curitem->name, newitem->name);
        }
    }
    if (newitem->validupto)
        return 0;
    if (!newitem->validfrom)
        return 0;
    return 1;
}

int
comparecurrentsetnew(recordset_type newitem, recordset_type curitem, int* cmp)
{
    int rc = 1;
    int c = 0;
    if (curitem) {
        c = strcmp(curitem->name, newitem->name);
        if (cmp)
            *cmp = c;
        if (c == 0) {
            c = newitem->revision - curitem->revision;
            if (newitem->revision < curitem->revision) {
                rc = 0;
            } else {
                rc = 1;
            }
        }
    }
    if (newitem->validupto)
        rc = 0;
    if (!newitem->validfrom)
        rc = 0;
    return rc;
}

int
comparerelevantset(recordset_type newitem, recordset_type curitem, int* cmp)
{
    int c;
    if (curitem) {
        c = strcmp(curitem->name, newitem->name);
        if (cmp)
            *cmp = c;
        if (c == 0) {
            if (newitem->revision - curitem->revision <= 0)
                return 0;
        }
    }
    if (newitem->validupto)
        return 0;
    return 1;
}

int
comparesignedset(recordset_type newitem, recordset_type curitem, int* cmp)
{
    const char* left;
    const char* right;
    if (curitem) {
        if (cmp) {
            *cmp = strcmp(curitem->name, newitem->name);
        }
    }
    if (newitem->validupto) {
        return 0;
    }
    if (!newitem->validfrom) {
        return 0;
    }
    if (!newitem->expiry) {
        return 0;
    }
    return 1;
}

int
comparechangesset(recordset_type newitem, recordset_type curitem, int* cmp)
{
    if (curitem) {
        if (cmp) {
            *cmp = strcmp(newitem->name, curitem->name);
            if(*cmp == 0) {
                if(newitem->validfrom) {
                    *cmp = *(newitem->validfrom) - *(curitem->validfrom);
                } else {
                    *cmp = -1;
                }
            } else {
            }
        }
    }
    if (!newitem->validfrom) {
        return 0;
    }
    if (!newitem->expiry) {
        return 0;
    }
    return 1;
}

int
compareinsertsset(recordset_type newitem, recordset_type curitem, int* cmp)
{
    if (curitem) {
        if (cmp) {
            *cmp = *newitem->validfrom - *curitem->validfrom;
            if(*cmp == 0 && newitem->name) {
                *cmp = strcmp(newitem->name, curitem->name);
            }
        }
    }
    if (!newitem->validfrom) {
        return 0;
    }
    if (!newitem->expiry) {
        return 0;
    }
    return 1;
}

int
comparedeletesset(recordset_type newitem, recordset_type curitem, int* cmp)
{
    if (curitem) {
        if (cmp) {
            if(curitem->validupto == NULL) {
                *cmp = -1;
            } else if(newitem->validupto == NULL) {
                *cmp = 1;
            } else {
                *cmp = *newitem->validupto - *curitem->validupto;
            }
            if(*cmp == 0)
                *cmp = strcmp(newitem->name, curitem->name);
        }
        if (cmp && newitem->name) {
            *cmp = strcmp(newitem->name, curitem->name);
        }
    }
    if (!newitem->validfrom) {
        return 0;
    }
    if (!newitem->expiry) {
        return 0;
    }
    return 1;
}

int
compareoutdatedset(recordset_type newitem, recordset_type curitem, int* cmp)
{
    if (curitem) {
        if (cmp) {
            if(curitem->validupto == NULL) {
                *cmp = -1;
            } else if(newitem->validupto == NULL) {
                *cmp = 1;
            } else {
                *cmp = *newitem->validupto - *curitem->validupto;
            }
            if(*cmp == 0 && newitem->name != NULL)
                *cmp = strcmp(curitem->name, newitem->name);
            if(*cmp == 0 && newitem->name != NULL)
                *cmp = curitem->revision - newitem->revision;
        }
    }
    if (!newitem->validupto) {
        return 0;
    }
    if (!newitem->validfrom) {
        return 0;
    }
    return 1;
}

void
names_recordindexfunction(const char* keyname, int (**acceptfunc)(recordset_type newitem, recordset_type currentitem, int* cmp), int (**comparfunc)(const void *, const void *))
{
#define REFERCOMPARISON(F,N) do { if(comparfunc) *comparfunc = N ## _ldns; if(acceptfunc) *acceptfunc = N; } while(0)
    if(!strcmp(keyname,"nameready")) {
        REFERCOMPARISON("namerevision", compareready);
    } else if(!strcmp(keyname,"namerevision")) {
        REFERCOMPARISON("namerevision", comparenamerevision);
    } else if(!strcmp(keyname,"nameupcoming")) {
        REFERCOMPARISON("name", compareupcomingset);
    } else if(!strcmp(keyname,"incomingset")) {
        REFERCOMPARISON("name", compareincomingset);
    } else if(!strcmp(keyname,"currentset")) {
        REFERCOMPARISON("name", comparecurrentset);
    } else if(!strcmp(keyname,"relevantset")) {
        REFERCOMPARISON("name", comparerelevantset);
    } else if(!strcmp(keyname,"validnow")) {
        REFERCOMPARISON("name", comparesignedset);
    } else if(!strcmp(keyname,"validchanges")) {
        REFERCOMPARISON("name", comparechangesset);
    } else if(!strcmp(keyname,"validinserts")) {
        REFERCOMPARISON("name", compareinsertsset);
    } else if(!strcmp(keyname,"validdeletes")) {
        REFERCOMPARISON("name", comparedeletesset);
    } else if(!strcmp(keyname,"expiry")) {
        REFERCOMPARISON("expiry",compareexpiry);
    } else if(!strcmp(keyname,"denialname")) {
        REFERCOMPARISON("denialname",comparedenialname);
    } else if(!strcmp(keyname,"namehierarchy")) {
        REFERCOMPARISON("name",comparenamehierarchy);
    } else if(!strcmp(keyname,"outdated")) {
        REFERCOMPARISON("name",compareoutdatedset);
    } else {
        abort(); // FIXME
    }    
}

void
names_recordlookupone(recordset_type record, ldns_rr_type recordtype, ldns_rr* template, ldns_rr** rr)
{
    int i, j;
    assert(record);
    assert(recordtype != 0);
    *rr = NULL;
    for(i=0; i<record->nitemsets; i++)
        if(record->itemsets[i].rrtype == recordtype)
            break;
    if (i<record->nitemsets) {
        if(rr == NULL) {
            if(record->itemsets[i].nitems > 0) {
                *rr = record->itemsets[i].items[0].rr;
            }
        } else {
            for(j=0; j<record->itemsets[i].nitems; j++)
                if(!template || !ldns_rr_compare(template, record->itemsets[i].items[j].rr))
                    break;
            if (j<record->itemsets[i].nitems) {
                *rr = record->itemsets[i].items[j].rr;
            }
        }
    }
}

void
names_recordlookupall(recordset_type record, ldns_rr_type rrtype, ldns_rr* template, ldns_rr_list** rrs, ldns_rr_list** rrsigs)
{
    int i, j;
    assert(record);
    if(rrs)
        *rrs = NULL;
    if(rrsigs)
        *rrsigs = NULL;
    if(rrtype==LDNS_RR_TYPE_RRSIG) {
        if(rrsigs)
            *rrsigs = ldns_rr_list_new();
        for(i=0; i<record->nitemsets; i++) {
            if(record->itemsets[i].signatures) {
                for(j=0; j<record->itemsets[i].signatures->nsigs; j++) {
                    ldns_rr_list_push_rr(*rrsigs, record->itemsets[i].signatures->sigs[j].rr);
                }
            }
        }
        if(record->spansignatures)
            for(j=0; j<record->spansignatures->nsigs; j++) {
                if(rrsigs)
                    ldns_rr_list_push_rr(*rrsigs, record->spansignatures->sigs[j].rr);
            }
  } else {
    for(i=0; i<record->nitemsets; i++) {
        if(record->itemsets[i].rrtype == rrtype) {
            break;
        }
    }
    if (i<record->nitemsets) {
        *rrs = ldns_rr_list_new();
        if(rrsigs)
            *rrsigs = ldns_rr_list_new();
        if(template == NULL) {
            if(record->itemsets[i].nitems > 0) {
                for(j=0; j<record->itemsets[i].nitems; j++) {
                    if(rrs) {
                        assert(record->itemsets[i].items[j].rr);
                        ldns_rr_list_push_rr(*rrs, record->itemsets[i].items[j].rr);
                    }
                    // FIXME also push rrsigs
                }
            }
        } else {
            for(j=0; j<record->itemsets[i].nitems; j++)
                if(!ldns_rr_compare(template, record->itemsets[i].items[j].rr))
                    break;
            if (j<record->itemsets[i].nitems) {
                if(rrs) {
                    assert(record->itemsets[i].items[j].rr);
                    ldns_rr_list_push_rr(*rrs, record->itemsets[i].items[j].rr);
                }
            }
        }
    } else {
        if(rrtype == LDNS_RR_TYPE_NSEC || rrtype == LDNS_RR_TYPE_NSEC3) {
            if(rrs)
                *rrs = ldns_rr_list_new();
            if(rrsigs)
                *rrsigs = ldns_rr_list_new();
            if(rrs) {
                assert(record->spanhashrr);
                ldns_rr_list_push_rr(*rrs, record->spanhashrr);
            }
            if(record->spansignatures)
                for(j=0; j<record->spansignatures->nsigs; j++) {
                    ldns_rr_list_push_rr(*rrsigs, record->spansignatures->sigs[j].rr);
                    // FIXME should push whole structure
                }
        }
    }
  }
}
