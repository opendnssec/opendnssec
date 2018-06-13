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

struct dictionary_struct {
    char* name;
    int revision;
    int marker;
    ldns_rr* spanhashrr;
    char* spanhash;
    struct signatures_struct* spansignatures;
    int* validupto;
    int* validfrom;
    int* expiry;
    int nitemsets;
    struct itemset* itemsets;
    char* tmpRevision;
    char* tmpNameSerial;
    char* tmpValidFrom;
    char* tmpValidUpto;
    char* tmpExpiry;
};

static void
names_signaturedispose(struct signatures_struct* signatures)
{
    int i;
    if(signatures) {
        for (i=0; i<signatures->nsigs; i++) {
            free((void*)signatures->sigs[i].keylocator);
            ldns_rr_free(signatures->sigs[i].rr);
        }
        free(signatures);
    }
}

void
names_recordaddsignature(dictionary d, ldns_rr_type rrtype, ldns_rr* rrsig, const char* keylocator, int keyflags)
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
names_recordcompare_namerevision(dictionary a, dictionary b)
{
    int rc;
    const char* left;
    const char* right;
    getset(a, "name", &left, NULL);
    getset(b, "name", &right, NULL);
    assert(left);
    assert(right);

    rc = strcmp(a->name, b->name);
    if(rc == 0) {
        if(a->revision != 0 && b->revision != 0) {
            rc = a->revision - b->revision;
        }
    }
    return rc;
}

static dictionary
recordcreate(char** name)
{
    struct dictionary_struct* dict;
    dict = malloc(sizeof(struct dictionary_struct));
    if (name) {
        dict->name = *name = ((*name) ? strdup(*name) : NULL);
    } else {
        dict->name = NULL;
    }
    dict->marker = 0;
    dict->nitemsets = 0;
    dict->itemsets = NULL;
    dict->spanhash = NULL;
    dict->spanhashrr = NULL;
    dict->spansignatures = NULL;
    dict->validupto = NULL;
    dict->validfrom = NULL;
    dict->expiry = NULL;
    dict->tmpNameSerial = NULL;
    dict->tmpRevision = NULL;
    dict->tmpValidFrom = NULL;
    dict->tmpValidUpto = NULL;
    dict->tmpExpiry = NULL;
    return dict;
}

dictionary
names_recordcreate(char** name)
{
    struct dictionary_struct* dict;
    dict = recordcreate(name);
    if (name) {
        dict->name = *name = ((*name) ? strdup(*name) : NULL);
    } else {
        dict->name = NULL;
    }
    dict->revision = 1;
    return dict;
}

dictionary
names_recordcreatetemp(const char* name)
{
    dictionary dict;
    dict = recordcreate((char**)&name);
    dict->revision = 0;
    return dict;
}

static char*
dname_hash(char* name, const char* zone) // FIXME salt, waht?
{
    ldns_rdf* dname;
    ldns_rdf* apex;
    ldns_rdf* hashed_ownername;
    ldns_rdf* hashed_label;
    char* hashed;
    unsigned char salt[8];
    salt[0] = '\0';

    memset(salt,0,8);
    dname = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, name);
    apex = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, zone);

    /*
     * The owner name of the NSEC3 RR is the hash of the original owner
     * name, prepended as a single label to the zone name.
     */
    hashed_label = ldns_nsec3_hash_name(dname, 1, 5, 8, salt);
    hashed_ownername = ldns_dname_cat_clone((const ldns_rdf*) hashed_label,
        (const ldns_rdf*) apex);
    hashed = ldns_rdf2str(hashed_ownername);
    ldns_rdf_deep_free(dname);
    ldns_rdf_deep_free(apex);
    ldns_rdf_deep_free(hashed_label);
    ldns_rdf_deep_free(hashed_ownername);
    return hashed;
}

void
names_recordannotate(dictionary d, struct names_view_zone* zone)
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
            ldns_rdf_free(hashed_ownername);
            ldns_rdf_free(hashed_label);
            ldns_rdf_free(apex);
            ldns_rdf_free(dname);
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
        d->spanhash = NULL;
        d->spanhashrr = NULL;
    }
}
        
void
names_recorddestroy(dictionary dict)
{
    int i, j;
    for(i=0; i<dict->nitemsets; i++) {
        for(j=0; j<dict->itemsets[i].nitems; j++) {
            ldns_rr_free(dict->itemsets[i].items[j].rr);
        }
        free(dict->itemsets[i].items);
    }
    free(dict->itemsets);
    free(dict->name);
    free(dict);
}

/* deletion marker */
void
names_recordsetmarker(dictionary dict)
{
    dict->marker = 1;
}

int
names_recordhasmarker(dictionary dict)
{
    return dict->marker;
}

dictionary
names_recordcopy(dictionary dict, int increment)
{
    int i, j;
    struct dictionary_struct* target;
    char* name = dict->name;
    target = (struct dictionary_struct*) names_recordcreate(&name);
    target->revision = dict->revision + (increment ? 1 : 1);
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
    names_signaturedispose(target->spansignatures);
    if(increment == 0) {
        if(dict->expiry) {
            target->expiry = malloc(sizeof(int));
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
names_recordhasdata(dictionary record, ldns_rr_type recordtype, ldns_rr* rr, int exact)
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

/* FIXME to be renamed to names_recordadddata */
void
rrset_add_rr(dictionary d, ldns_rr* rr)
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
names_recorddeldata(dictionary d, ldns_rr_type rrtype, ldns_rr* rr)
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
names_recorddelall(dictionary d, ldns_rr_type rrtype)
{
    int i, j;
    for(i=0; i<d->nitemsets; i++) {
        if(rrtype==0 || d->itemsets[i].rrtype == rrtype) {
            for(j=0; j<d->itemsets[i].nitems; j++) {
                ldns_rr_free(d->itemsets[i].items[j].rr);
            }
            free(d->itemsets[i].items);
            names_signaturedispose(d->itemsets[i].signatures);
            free(d->itemsets[i].signatures);
            if(rrtype != 0)
                break;
        }
    }
    if(rrtype == 0) {
        free(d->itemsets);
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
            free(d->itemsets);
            d->itemsets = NULL;
        }        
    }
}

static void names_recordalltypes_func(names_iterator iter, dictionary d, int index, ldns_rr_type* ptr)
{
    if(index >= 0)
        memcpy(ptr, &(d->itemsets[index].rrtype), sizeof(ldns_rr_type));
}
names_iterator
names_recordalltypes(dictionary d)
{
    names_iterator iter;
    iter = names_iterator_createarray(d->nitemsets, d, names_recordalltypes_func);
    return iter;
}

static void names_recordallvaluestrings_func(names_iterator iter, struct item* items, int index, char** ptr)
{
    free(*ptr);
    if (index >= 0)
        *ptr = ldns_rr2str(items[index].rr);
    else
        *ptr = NULL;
}
names_iterator
names_recordallvaluestrings(dictionary d, ldns_rr_type rrtype)
{
    int i;
    for(i=0; i<d->nitemsets; i++) {
        if(rrtype == d->itemsets[i].rrtype)
            break;
    }
    if(i<d->nitemsets) {
        int j;
        names_iterator iter = names_iterator_createrefs();
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
            names_iterator iter = names_iterator_createrefs();
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

#ifdef NOTDEFINED
static void names_recordallvalueidents_func(names_iterator iter, struct itemset* itemset, int index, ldns_rr_type* ptr)
{
    if (index >= 0) {
        rrtypestr = ldns_rr_type2str(rrtype);
        size = header + strlen(record->name) + 1 + strlen(rrtypestr) + 1;
        sprintf(&buffer[header],"%s %s",record->name,rrtypestr);
        buffer[header + strlen(&buffer[header])] = ' ';

 names_rr2ident(domainitem, recordtype, item, sizeof(struct removal_struct));
    char* rrtypestr;
    char* buffer;
    size_t size;

    return buffer;
        ;
}
names_iterator
names_recordallvalueidents(dictionary d, ldns_rr_type rrtype)
{
    int i;
    for(i=0; i<d->nitemsets; i++) {
        if(rrtype == d->itemsets[i].rrtype)
            break;
    }
    if(i<d->nitemsets) {

        char* rrtypestr = ldns_rr_type2str(rrtype);
        buffer = names_rr2data(item->rr, size);
record->name


        return names_iterator_createarray(d->itemsets[i].nitems, d->nitemsets, names_recordallvalueidents_func);
    } else {
        return NULL;
    }
}
#endif

void
names_recorddispose(dictionary dict)
{
    int i, j;
    for(i=0; i<dict->nitemsets; i++) {
        for(j=0; j<dict->itemsets[i].nitems; j++) {
            ldns_rr_free(dict->itemsets[i].items[j].rr);
        }
        names_signaturedispose(dict->itemsets[i].signatures);
        free(dict->itemsets[i].signatures);
        free(dict->itemsets[i].items);
    }
    free(dict->itemsets);
    free(dict->name);
    free(dict->spanhash);
    names_signaturedispose(dict->spansignatures);
    free(dict->spansignatures);
    free(dict->validupto);
    free(dict->validfrom);
    free(dict->expiry);
    free(dict->tmpNameSerial);
    free(dict->tmpRevision);
    free(dict->tmpValidFrom);
    free(dict->tmpValidUpto);
    free(dict->tmpExpiry);
    free(dict);
}

const char*
names_recordgetid(dictionary record, const char* name)
{
    const char* id;
    if(name == NULL) {
        name = "namerevision";
    }
    getset(record, name, &id, NULL);
    return id;
}

int
names_recordhasvalidupto(dictionary record)
{
    return record->validupto != NULL;
}

void
names_recordsetvalidupto(dictionary record, int value)
{
    assert(record->validupto == NULL);
    record->validupto = malloc(sizeof(int));
    *(record->validupto) = value;
}

int
names_recordhasvalidfrom(dictionary record)
{
    return record->validfrom != NULL;
}

void
names_recordsetvalidfrom(dictionary record, int value)
{
    assert(record->validfrom == NULL);
    record->validfrom = malloc(sizeof(int));
    *(record->validfrom) = value;
}

void
names_recordsetdenial(dictionary record, ldns_rr* denial)
{
    record->spanhashrr = ldns_rr_clone(denial); // FIXME
}

int
names_recordhasexpiry(dictionary record)
{
    return record->expiry != NULL;
}

int
names_recordgetexpiry(dictionary record)
{
    return *(record->expiry);
}

void
names_recordsetexpiry(dictionary record, int value)
{
    assert(record->expiry == NULL);
    record->expiry = malloc(sizeof(int));
    *(record->expiry) = value;
}

int
marshall(marshall_handle h, void* ptr)
{
    dictionary d = ptr;
    int size = 0;
    int i, j;
    size += marshalling(h, "name", &(d->name), NULL, 0, marshallstring);
    size += marshalling(h, "revision", &(d->revision), NULL, 0, marshallinteger);
    size += marshalling(h, "marker", &(d->marker), NULL, 0, marshallinteger);
    size += marshalling(h, "spanhash", &(d->spanhash), NULL, 0, marshallstring);
    //FIXME size += marshalling(h, "spansignatures", &(d->spansignatures), marshall_OPTIONAL, sizeof(struct signatures_struct), marshallsigs); FIXME bugs?
    size += marshalling(h, "spanhashrr", &(d->spanhashrr), NULL, 0, marshallldnsrr);
    size += marshalling(h, "validupto", &(d->validupto), marshall_OPTIONAL, sizeof(int), marshallinteger);
    size += marshalling(h, "validfrom", &(d->validfrom), marshall_OPTIONAL, sizeof(int), marshallinteger);
    size += marshalling(h, "expiry", &(d->expiry), marshall_OPTIONAL, sizeof(int), marshallinteger);
    size += marshalling(h, "itemsets", &(d->itemsets), &(d->nitemsets), sizeof(struct itemset), marshallself);
    for(i=0; i<d->nitemsets; i++) {
        size += marshalling(h, "itemname", &(d->itemsets[i].rrtype), NULL, 0, marshallinteger);
        size += marshalling(h, "items", &(d->itemsets[i].items), &(d->itemsets[i].nitems), sizeof(struct item), marshallself);
        for(j=0; j<d->itemsets[i].nitems; j++) {
            size += marshalling(h, "rr", &(d->itemsets[i].items[j].rr), NULL, 0, marshallldnsrr);
            size += marshalling(h, NULL, NULL, &(d->itemsets[i].nitems), j, marshallself);
        }
        size += marshalling(h, NULL, NULL, &(d->nitemsets), i, marshallself);
    }
    d->tmpNameSerial = NULL;
    d->tmpRevision = NULL;
    d->tmpValidFrom = NULL;
    d->tmpValidUpto = NULL;
    d->tmpExpiry = NULL;
    return size;
}

int
names_recordmarshall(dictionary* record, marshall_handle h)
{
    int rc;
    dictionary dummy = NULL;
    if(record == NULL)
        record = &dummy;
    rc = marshalling(h, "domain", record, marshall_OPTIONAL, sizeof(struct dictionary_struct), marshall);
    return rc;
}

void
composestring(char* dst, const char* src, ...)
{
    va_list ap;
    int len;
    va_start(ap, src);
    while (src != NULL) {
        len = strlen(src);
        memcpy(dst, src, len);
        dst += len;
        src = va_arg(ap, char*);
        *dst = (src == NULL ? '\0' : ' ');
        dst += 1;
    }
    va_end(ap);
}

int
composestring2(char** ptr, const char* src, ...)
{
    va_list ap;
    int size, len, nomatch;
    char* dst;
    if(ptr != NULL) {
        dst = NULL;
        nomatch = 1;
    } else {
        dst = *ptr;
        if(dst == NULL) {
            nomatch = 1;
        } else {
            nomatch = 0;
        }
    }
    size = 0;
    va_start(ap, src);
    while (src != NULL) {
        len = strlen(src);
        if(nomatch || strcmp(dst, src)) {
            nomatch = 1;
        } else {
            dst += len;
        }
        src = va_arg(ap, char*);
        if(nomatch || (src == NULL ? *dst != '\0' : *dst != ' ')) {
            nomatch = 1;
        } else {
            dst += 1;
        }
        size += len + 1;
    }
    va_end(ap);
    if(ptr == NULL) {
        return len;
    } else if(nomatch == 0) {
        return 0;
    } else {
        if(*ptr)
            free(*ptr);
        dst = *ptr = malloc(size);
        va_start(ap, src);
        while (src != NULL) {
            len = strlen(src);
            memcpy(dst, src, len);
            dst += len;
            src = va_arg(ap, char*);
            *dst = (src == NULL ? '\0' : ' ');
            dst += 1;
        }
        va_end(ap);
        return 1;
    }
}

int
composestringf(char** ptr, const char* fmt,...)
{
    va_list ap;
    int size;
    char* dst;
    va_start(ap,fmt);
    size = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    dst = alloca(size+1);
    va_start(ap,fmt);
    vsnprintf(dst, size+1, fmt, ap);
    va_end(ap);
    if (!*ptr || strcmp(*ptr,dst)) {
        free(*ptr);
        *ptr = malloc(size+1);
        memcpy(*ptr, dst, size+1);
        return 1;
    } else {
        return 0;
    }
}

void
decomposestringf(const char* ptr, const char* fmt,...)
{
    va_list ap;
    va_start(ap,fmt);
    vsscanf(ptr,fmt,ap);
    va_end(ap);
}

//FIXME
int
getset(dictionary d, const char* name, const char** get, const char** set)
{
    int rc = 1;
    if (get)
        *get = NULL;
    if (!strcmp(name,"name") || !strcmp(name,"nameupcoming") || !strcmp(name,"nameready")) {
        rc = (d->name == NULL);
        if (get) {
            *get = d->name;
        }
        if (set) {
            d->name = strdup(*set);
        }
    } else if(!strcmp(name,"revision")) {
        if (get) {
            composestringf(&(d->tmpRevision), "%d", d->revision);
            *get = d->tmpRevision;
        }
        if (set) {
            decomposestringf(name,"%d",&(d->revision));
        }
    } else if(!strcmp(name,"namerevision")) {
        if (get) {
            composestringf(&(d->tmpNameSerial), "%s %d", d->name, d->revision);
            *get = d->tmpNameSerial;
        }
        if (set) {
            decomposestringf(name,"%ms %d",&d->name,&d->revision);
        }
    } else if(!strcmp(name,"validfrom")) {
        rc = (d->validfrom != NULL);
        if (get) {
            if(d->validfrom) {
                composestringf(&(d->tmpValidFrom), "%d", *(d->validfrom));
                *get = d->tmpValidFrom;
            } else
                *get = NULL;
        }
        if (set) {
            if(!d->validfrom)
                d->validfrom = malloc(sizeof(int));
            decomposestringf(*set,"%d",d->validfrom);
        }
    } else if(!strcmp(name,"validupto")) {
        rc = (d->validupto != NULL);
        if (get) {
            if(d->validupto) {
                composestringf(&(d->tmpValidUpto), "%d", *(d->validupto));
                *get = d->tmpValidUpto;
            } else
                *get = NULL;
        }
        if (set) {
            if(!d->validupto)
                d->validupto = malloc(sizeof(int));
            decomposestringf(*set,"%d",d->validupto);
        }
    } else if(!strcmp(name,"expiry")) {
        rc = (d->expiry != NULL);
        if (get) {
            if(d->expiry) {
                composestringf(&(d->tmpExpiry), "%d", *(d->expiry));
                *get = d->tmpExpiry;
            } else
                *get = NULL;
        }
        if (set) {
            if(!d->expiry)
                d->expiry = malloc(sizeof(int));
            decomposestringf(*set,"%d",d->expiry);
        }
    } else if(!strcmp(name,"denialname")) {
        rc = (d->spanhash != NULL);
        if (get) {
            *get = d->spanhash;
        }
        if (set) {
            d->spanhash = strdup(*set);
        }
    } else {
        abort(); // FIXME
    }
    return rc;
}

#define DEFINECOMPARISON(N) \
    int N(dictionary, dictionary, int*); \
    int N ## _ldns(const void* a, const void* b) { \
    int rc; N((dictionary)a, (dictionary)b, &rc); return rc; }

DEFINECOMPARISON(compareready)
DEFINECOMPARISON(comparenamerevision)
DEFINECOMPARISON(comparenamehierarchy)
DEFINECOMPARISON(compareexpiry)
DEFINECOMPARISON(comparedenialname)
DEFINECOMPARISON(compareupcomingset)
DEFINECOMPARISON(compareincomingset)
DEFINECOMPARISON(comparecurrentset)
#ifdef NOTDEFINED
DEFINECOMPARISON(comparerelevantset)
#endif
DEFINECOMPARISON(comparesignedset)

int
comparenamerevision(dictionary newitem, dictionary curitem, int* cmp)
{
    const char* left;
    const char* right;
    (void)index;
    if (curitem) {
        if (cmp) {
            *cmp = strcmp(newitem->name, curitem->name);
            if(*cmp == 0 && newitem->revision != 0) {
                *cmp = newitem->revision - curitem->revision;
            }
        }
    }
    return 1;
}

int
comparenamehierarchy(dictionary newitem, dictionary curitem, int* cmp)
{
    const char* left;
    const char* right;
    (void)index;
    if (curitem) {
        if (cmp) {
            getset(newitem, "name", &left, NULL);
            getset(curitem, "name", &right, NULL);
            assert(left);
            assert(right);
            *cmp = strcmp(right, left);
        }
    }
    return 1;
}

int
compareexpiry(dictionary newitem, dictionary curitem, int* cmp)
{
    const char* left;
    const char* right;
    (void)index;
    getset(newitem, "expiry", &left, NULL);
    if (curitem) {
        if (cmp) {
            getset(curitem, "expiry", &right, NULL);
            if(!left) left = "";
            if(!right) right = "";
            *cmp = strcmp(left, right);
        }
    }
    if (!left)
        return 0;
    return 1;
}

/* rule: you cannot ammend a field when that field is in use for to store a record in an index */

int
comparedenialname(dictionary newitem, dictionary curitem, int* cmp)
{
    const char* left;
    const char* right;
    (void)index;
    getset(newitem, "denialname", &left, NULL);
    if (curitem) {
        if(cmp) {
            getset(curitem, "denialname", &right, NULL);
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
compareupcomingset(dictionary newitem, dictionary curitem, int* cmp)
{
    int c;
    const char* left;
    const char* right;
    (void)index;
    if(curitem) {
        getset(newitem, "name", &left, NULL);
        getset(curitem, "name", &right, NULL);
        c = strcmp(left, right);
        if(cmp)
            *cmp = c;
        if(c == 0) {
            getset(newitem, "revision", &left, NULL);
            getset(curitem, "revision", &right, NULL);
            if(strcmp(left, right) <= 0) {
                return 0;
            }
        }
    }
    return 1;
}

int
compareincomingset(dictionary newitem, dictionary curitem, int* cmp)
{
    int rc = 1;
    int compare;
    const char* left;
    const char* right;
    (void)index;
    if(curitem) {
        getset(newitem, "name", &left, NULL);
        getset(curitem, "name", &right, NULL);
        compare = strcmp(left, right);
        if(cmp)
            *cmp = compare;
        if(compare == 0) {
            getset(newitem, "revision", &left, NULL);
            getset(curitem, "revision", &right, NULL);
            if(strcmp(left, right) <= 0) {
                rc = 0;
            }
        }
    }
    if(getset(newitem, "validfrom", NULL, NULL)) {
        if(curitem && compare == 0) {
            rc = 2;
        } else
            rc = 0;
    }
    return rc;
}

int
compareready(dictionary newitem, dictionary curitem, int* cmp)
{
    int c;
    const char* left;
    const char* right;
    (void)index;
    if (curitem) {
        getset(curitem, "name", &left, NULL);
        getset(newitem, "name", &right, NULL);
        c = strcmp(left, right);
        if (cmp)
            *cmp = c;
        if (c == 0) {
            getset(newitem, "revision", &left, NULL);
            getset(curitem, "revision", &right, NULL);
            if (strcmp(left, right) <= 0)
                return 0;
        }
    }
    if (getset(newitem, "validupto", NULL, NULL))
        return 0;
    if (!getset(newitem, "validfrom", NULL, NULL))
        return 0;
    if (getset(newitem, "expiry", NULL, NULL))
        return 0;
    return 1;
}


int
comparecurrentset(dictionary newitem, dictionary curitem, int* cmp)
{
    const char* left;
    const char* right;
    (void)index;
    if (curitem) {
        if (cmp) {
            getset(curitem, "name", &left, NULL);
            getset(newitem, "name", &right, NULL);
            *cmp = strcmp(left, right);
        }
    }
    if (getset(newitem, "validupto", NULL, NULL))
        return 0;
    if (!getset(newitem, "validfrom", NULL, NULL))
        return 0;
    return 1;
}

#ifdef NOTDEFINED
int
comparerelevantset(dictionary newitem, dictionary curitem, int* cmp)
{
    int c;
    const char* left;
    const char* right;
    (void)index;
    if (curitem) {
        getset(curitem, "name", &left, NULL);
        getset(newitem, "name", &right, NULL);
        c = strcmp(left, right);
        if (cmp)
            *cmp = c;
        if (c == 0) {
            getset(newitem, "revision", &left, NULL);
            getset(curitem, "revision", &right, NULL);
            if (strcmp(left, right) <= 0)
                return 0;
        }
    }
    if (getset(newitem, "validupto", NULL, NULL))
        return 0;
    return 1;
}
#endif

int
comparesignedset(dictionary newitem, dictionary curitem, int* cmp)
{
    const char* left;
    const char* right;
    (void)index;
    if (curitem) {
        if (cmp) {
            getset(curitem, "name", &left, NULL);
            getset(newitem, "name", &right, NULL);
            *cmp = strcmp(left, right);
        }
    }
    if (getset(newitem, "validupto", NULL, NULL)) {
        return 0;
    }
    if (!getset(newitem, "validfrom", NULL, NULL)) {
        return 0;
    }
    if (!getset(newitem, "expiry", NULL, NULL)) {
        return 0;
    }
    return 1;
}

void
names_recordindexfunction(const char* keyname, int (**acceptfunc)(dictionary newitem, dictionary currentitem, int* cmp), int (**comparfunc)(const void *, const void *))
{
#define REFERCOMPARISON(F,N) do { *comparfunc = N ## _ldns; *acceptfunc = N; } while(0)
    if(!strcmp(keyname,"nameready")) {
        REFERCOMPARISON("namerevision", compareready);
    } else if(!strcmp(keyname,"namerevision")) {
        REFERCOMPARISON("namerevision", comparenamerevision);
    } else if(!strcmp(keyname,"nameupcoming")) {
        REFERCOMPARISON("name", compareupcomingset);
    } else if(!strcmp(keyname,"namenoserial")) {
        REFERCOMPARISON("name", compareincomingset);
    } else if(!strcmp(keyname,"namenewserial")) {
        REFERCOMPARISON("name", comparecurrentset);
    } else if(!strcmp(keyname,"validnow")) {
        REFERCOMPARISON("name", comparesignedset);
    } else if(!strcmp(keyname,"expiry")) {
        REFERCOMPARISON("expiry",compareexpiry);
    } else if(!strcmp(keyname,"denialname")) {
        REFERCOMPARISON("denialname",comparedenialname);
    } else if(!strcmp(keyname,"namehierarchy")) {
        REFERCOMPARISON("name",comparenamehierarchy);
    } else {
        abort(); // FIXME
    }    
}

char*
names_rr2data(ldns_rr* rr, size_t header)
{
    unsigned int i;
    char* s;
    int recorddatalen;
    char* recorddata;
    recorddatalen = header;
    for (i = 0; i < ldns_rr_rd_count(rr); i++) {
        s = ldns_rdf2str(ldns_rr_rdf(rr, i));
        recorddatalen += strlen(s) + 1;
        free(s);
    }
    recorddata = malloc(recorddatalen);
    recorddata[header] = '\0';
    for (i = 0; i < ldns_rr_rd_count(rr); i++) {
        s = ldns_rdf2str(ldns_rr_rdf(rr, i));
        if (i > 0)
            strcat(&recorddata[header], " ");
        strcat(&recorddata[header], s);
        free(s);
    }
    return recorddata;
}

#ifdef NOTDEFINED
void*
names_rr2ident(dictionary record, ldns_rr_type rrtype, resourcerecord_t item, size_t header)
{
    char* rrtypestr;
    char* buffer;
    size_t size;
    
    rrtypestr = ldns_rr_type2str(rrtype);
    size = header + strlen(record->name) + 1 + strlen(rrtypestr) + 1;
    buffer = names_rr2data(item->rr, size);
    sprintf(&buffer[header],"%s %s",record->name,rrtypestr);
    buffer[header + strlen(&buffer[header])] = ' ';
    return buffer;
}

ldns_rr*
names_rr2ldns(dictionary record, const char* recordname, ldns_rr_type recordtype, resourcerecord_t item)
{
    (void)record;
    (void)recordname;
    (void)recordtype;
    return ldns_rr_clone(item->rr);
}
#endif

void
names_recordlookupone(dictionary record, ldns_rr_type recordtype, ldns_rr* template, ldns_rr** rr)
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
names_recordlookupall(dictionary record, ldns_rr_type rrtype, ldns_rr* template, ldns_rr_list** rrs, ldns_rr_list** rrsigs)
{
    int i, j;
    assert(record);
    assert(rrtype != 0);
    *rrs = NULL;
    *rrsigs = NULL;
    for(i=0; i<record->nitemsets; i++)
        if(record->itemsets[i].rrtype == rrtype)
            break;
    if (i<record->nitemsets) {
        *rrs = ldns_rr_list_new();
        *rrsigs = ldns_rr_list_new();
        if(template == NULL) {
            if(record->itemsets[i].nitems > 0) {
                for(j=0; j<record->itemsets[i].nitems; j++) {
                    ldns_rr_list_push_rr(*rrs, record->itemsets[i].items[j].rr);
                    // FIXME also push rrsigs
                }
            }
        } else {
            for(j=0; j<record->itemsets[i].nitems; j++)
                if(!ldns_rr_compare(template, record->itemsets[i].items[j].rr))
                    break;
            if (j<record->itemsets[i].nitems) {
                ldns_rr_list_push_rr(*rrs, record->itemsets[i].items[j].rr);
            }
        }
    } else {
        if(rrtype == LDNS_RR_TYPE_NSEC || rrtype == LDNS_RR_TYPE_NSEC3) {
            *rrs = ldns_rr_list_new();
            *rrsigs = ldns_rr_list_new();
            ldns_rr_list_push_rr(*rrs, record->spanhashrr);
            if(record->spansignatures)
                for(j=0; j<record->spansignatures->nsigs; j++) {
                    ldns_rr_list_push_rr(*rrsigs, record->spansignatures->sigs[j].rr);
                    // FIXME should push whole structure
                }
        }
    }
}
