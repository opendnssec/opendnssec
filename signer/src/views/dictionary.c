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

dictionary
names_recordcreate(char** name)
{
    struct dictionary_struct* dict;
    dict = malloc(sizeof(struct dictionary_struct));
    if (name) {
        dict->name = *name = ((*name) ? strdup(*name) : NULL);
    } else {
        dict->name = NULL;
    }
    dict->revision = 1;
    dict->marker = 0;
    dict->nitemsets = 0;
    dict->itemsets = NULL;
    dict->spanhash = NULL;
    dict->nspansignatures = 0;
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

static char*
dname_hash(char* name, const char* zone)
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
annotate(dictionary d, const char* apex)
{
    d->spanhash = dname_hash(d->name, apex);
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
names_recordcopy(dictionary dict)
{
    int i, j;
    struct dictionary_struct* target;
    char* name = dict->name;
    target = (struct dictionary_struct*) names_recordcreate(&name);
    target->revision = dict->revision + 1;
    target->nitemsets = dict->nitemsets;
    CHECKALLOC(target->itemsets = malloc(sizeof(struct itemset) * target->nitemsets));
    for(i=0; i<target->nitemsets; i++) {
        target->itemsets[i].rrtype = dict->itemsets[i].rrtype;
        target->itemsets[i].nitems= dict->itemsets[i].nitems;
        target->itemsets[i].items = malloc(sizeof(struct item) * dict->itemsets[i].nitems);
        target->itemsets[i].nsignatures = 0;
        target->itemsets[i].signatures = NULL;
        for(j=0; j<dict->itemsets[i].nitems; j++) {
            target->itemsets[i].items[j].rr = ldns_rr_clone(dict->itemsets[i].items[j].rr);
        }
    }
    target->spanhash = strdup(dict->spanhash);
    target->nspansignatures = 0;
    target->spansignatures = NULL;
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
                    if(!ldns_rr_compare(rr, &record->itemsets[i].items[j].rr))
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
    const char* name;
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
    }
    free((void*)name);
    for(j=0; j<d->itemsets[i].nitems; j++)
        if(!ldns_rr_compare(rr, &d->itemsets[i].items[j]))
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
            for(j=0; j<d->itemsets[i].nsignatures; j++) {
                ldns_rr_free(d->itemsets[i].signatures[j].rr);
                free(d->itemsets[i].signatures[j].keylocator);
            }
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
        free(d->itemsets[i].items);
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

names_iterator
names_recordalltypes(dictionary d)
{
    names_iterator iter;
    iter = names_iterator_create(0);
    names_iterator_addall(iter, d->nitemsets, d->itemsets, sizeof(struct itemset), offsetof(struct itemset, rrtype));
    return iter;
}

names_iterator
names_recordalltypes2(dictionary d)
{
    names_iterator iter;
    iter = names_iterator_create(0);
    names_iterator_addall(iter, d->nitemsets, d->itemsets, sizeof(struct itemset), offsetof(struct itemset, rrtype));
    return iter;
}

names_iterator
rrsigs(struct itemset* rrset)
{
    names_iterator iter;
    iter = names_iterator_create(0);
    names_iterator_addall(iter, rrset->nsignatures, rrset->signatures, sizeof(struct itemsig), offsetof(struct itemsig, rr));
    return iter;
}

names_iterator
names_recordallvalues(dictionary d, ldns_rr_type rrtype)
{
    int i;
    for(i=0; i<d->nitemsets; i++) {
        if(rrtype == d->itemsets[i].rrtype)
            break;
    }
    if(i<d->nitemsets) {
        names_iterator iter;
        iter = names_iterator_create(sizeof(struct item));
        names_iterator_addall(iter, d->itemsets[i].nitems, d->itemsets[i].items, sizeof(struct item), -1);
        return iter;
    } else {
        return NULL;
    }
}

void
dispose(dictionary dict)
{
    int i, j;
    for(i=0; i<dict->nitemsets; i++) {
        for(j=0; j<dict->itemsets[i].nitems; j++) {
            ldns_rr_free(dict->itemsets[i].items[j].rr);
        }
        for(j=0; j<dict->itemsets[i].nsignatures; j++) {
            ldns_rr_free(dict->itemsets[i].signatures[j].rr);
            free(dict->itemsets[i].signatures[j].keylocator);
        }
        free(dict->itemsets[i].signatures);
        free(dict->itemsets[i].items);
    }
    free(dict->itemsets);
    free(dict->name);
    free(dict->spanhash);
    for(i=0; i<dict->nspansignatures; i++) {
        ldns_rr_free(dict->spansignatures[i].rr);
        free(dict->spansignatures[i].keylocator);
    }
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

void
names_recordaddsignature(dictionary record, ldns_rr_type rrtype, char* signature, const char* keylocator, int keyflags) /* FIXME pass TTL */
{
    int i;
    if(rrtype == 0) {
        record->nspansignatures += 1;
        record->spansignatures = realloc(record->spansignatures, sizeof(struct itemsig) * record->nspansignatures);
        record->spansignatures[record->nspansignatures-1].keylocator = strdup(keylocator);
        record->spansignatures[record->nspansignatures-1].keyflags = keyflags;
        ldns_rr_new_frm_str(&record->spansignatures[record->nspansignatures-1].rr, signature, 0, NULL, NULL);
    } else {
        for(i=0; i<record->nitemsets; i++) {
            if(rrtype == record->itemsets[i].rrtype) {
                break;
            }
        }
        if(i<record->nitemsets) {
            record->itemsets[i].nsignatures += 1;
            record->itemsets[i].signatures = realloc(record->spansignatures, sizeof(struct itemsig) * record->itemsets[i].nsignatures);
            record->itemsets[i].signatures[record->itemsets[i].nsignatures-1].keylocator = strdup(keylocator);
            record->itemsets[i].signatures[record->itemsets[i].nsignatures-1].keyflags = keyflags;
            ldns_rr_new_frm_str(&record->itemsets[i].signatures[record->itemsets[i].nsignatures-1].rr, signature, 0, NULL, NULL);
        }
    }
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
    size += marshalling(h, "itemsets", &(d->spansignatures), &(d->nspansignatures), sizeof(struct itemsig), marshallself);
    for(i=0; i<d->nitemsets; i++) {
        size += marshalling(h, "rr", &(d->spansignatures[i].rr), NULL, 0, marshallldnsrr);
        size += marshalling(h, "keylocator", &(d->spansignatures[i].keylocator), NULL, 0, marshallstring);
        size += marshalling(h, "keyflags", &(d->spansignatures[i].keyflags), NULL, 0, marshallinteger);
        size += marshalling(h, NULL, NULL, &(d->nspansignatures), i, marshallself);
    }
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

int
getset(dictionary d, const char* name, const char** get, const char** set)
{
    int rc = 1;
    if (get)
        *get = NULL;
    if (!strcmp(name,"name") || !strcmp(name,"nameupcoming")) {
        rc = (d->name != NULL);
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
DEFINECOMPARISON(comparerelevantset)
DEFINECOMPARISON(comparesignedset)

int
comparenamerevision(dictionary newitem, dictionary curitem, int* cmp)
{
    const char* left;
    const char* right;
    (void)index;
    if (curitem) {
        if (cmp) {
            getset(newitem, "namerevision", &left, NULL);
            getset(curitem, "namerevision", &right, NULL);
            assert(left);
            assert(right);
            *cmp = strcmp(left, right);
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
    int x = 0;
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
        x |= 1;
        if(curitem && compare == 0) {
            x |= 2;
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
    int i;
    char* s;
    size_t recorddatalen;
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

char*
names_rr2str(dictionary record, ldns_rr_type recordtype, resourcerecord_t item)
{
    return ldns_rr2str(item->rr);
}

ldns_rr*
names_rr2ldns(dictionary record, const char* recordname, ldns_rr_type recordtype, resourcerecord_t item)
{
    return ldns_rr_clone(item->rr);
}
