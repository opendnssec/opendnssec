#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ldns/ldns.h>
#include "uthash.h"
#include "proto.h"

#pragma GCC optimize ("O0")

struct itemset {
    char* itemname;
    int nitems;
    char** items;
    char* signature;
};
struct dictionary_struct {
    char* name;
    int revision;
    char* spanhash;
    char* spansignature;
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

struct names_iterator_struct {
    int (*iterate)(names_iterator*iter, void**);
    int (*advance)(names_iterator*iter, void**);
    int (*end)(names_iterator*iter);
    int count;
    int index;
    void** array;
};

static int
iterateimpl(names_iterator*i, void** item)
{
    struct names_iterator_struct** iter = i;
    if (item)
        *item = NULL;
    if (*iter) {
        if ((*iter)->index < (*iter)->count) {
            if (item)
                *item = (*iter)->array[(*iter)->index];
            return 1;
        } else {
            free((*iter)->array);
            free(*iter);
            *iter = NULL;
        }
    }
    return 0;
}

static int
advanceimpl(names_iterator*i, void** item)
{
    struct names_iterator_struct** iter = i;
    if(*iter) {
        if((*iter)->index+1 < (*iter)->count) {
            (*iter)->index += 1;
            if(item)
                *item = (*iter)->array[(*iter)->index];
            return 1;
        }
        free((*iter)->array);
        free(*iter);
        *iter = NULL;
    }
    return 0;
}

static int
endimpl(names_iterator*iter)
{
    if(*iter) {
        free((*iter)->array);
        free(*iter);
    }
    *iter = NULL;
    return 0;
}

static names_iterator
iterator(int count, void* base, size_t memsize, size_t offset)
{
    struct names_iterator_struct* iter;
    void** array;
    int i;
    array = malloc(sizeof(void*) * count);
    for(i=0; i<count; i++) {
        array[i] = *(char**)&(((char*)base)[memsize*i+offset]);
        assert(array[i]);
    }
    iter = malloc(sizeof(struct names_iterator_struct));
    iter->iterate = iterateimpl;
    iter->advance = advanceimpl;
    iter->end = endimpl;
    iter->count = count;
    iter->index = 0;
    iter->array = array;
    return iter;
}

int
names_recordcompare_namerevision(dictionary a, dictionary b)
{
    int rc;
    const char* left;
    const char* right;
    getset(a, "name", &left, NULL);
    getset(a, "name", &right, NULL);
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
create(char** name)
{
    struct dictionary_struct* dict;
    dict = malloc(sizeof(struct dictionary_struct));
    if (name) {
        dict->name = *name = ((*name) ? strdup(*name) : NULL);
    } else {
        dict->name = NULL;
    }
    dict->revision = 1;
    dict->nitemsets = 0;
    dict->itemsets = NULL;
    dict->spanhash = NULL;
    dict->spansignature= NULL;
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
            free(dict->itemsets[i].items[j]);
        }
        free(dict->itemsets[i].itemname);
        free(dict->itemsets[i].items);
    }
    free(dict->itemsets);
    free(dict->name);
    free(dict);
}

dictionary
copy(dictionary dict)
{
    int i, j;
    struct dictionary_struct* target;
    char* name = dict->name;
    target = (struct dictionary_struct*) create(&name);
    target->revision = dict->revision + 1;
    target->nitemsets = dict->nitemsets;
    target->itemsets = malloc(sizeof(struct itemset) * target->nitemsets);
    for(i=0; i<target->nitemsets; i++) {
        target->itemsets[i].itemname = strdup(dict->itemsets[i].itemname);
        target->itemsets[i].nitems= dict->itemsets[i].nitems;
        target->itemsets[i].items = malloc(sizeof(char*) * dict->itemsets[i].nitems);
        for(j=0; j<dict->itemsets[i].nitems; j++)
            target->itemsets[i].items[j] = strdup(dict->itemsets[i].items[j]);
    }
    return target;
}

int
names_recordhasdata(dictionary d, char* name, char* data)
{
    int i, j;
    if(!d)
        return 0;
    if(name == NULL) {
        return d->nitemsets > 0;
    } else {
        for(i=0; i<d->nitemsets; i++)
            if(!strcmp(name, d->itemsets[i].itemname))
                break;
        if (i<d->nitemsets) {
            if(data == NULL) {
                return d->itemsets[i].nitems > 0;
            } else {
                for(j=0; j<d->itemsets[i].nitems; j++)
                    if(!strcmp(data, d->itemsets[i].items[j]))
                        break;
                if (j<d->itemsets[i].nitems) {
                    return 1;
                }
            }
        }
    }
    return 0;
}


void
names_recordadddata(dictionary d, char* name, char* data)
{
    int i, j;
    assert(name);
    assert(data);
    for(i=0; i<d->nitemsets; i++)
        if(!strcmp(name, d->itemsets[i].itemname))
            break;
    if (i==d->nitemsets) {
        d->nitemsets += 1;
        d->itemsets = realloc(d->itemsets, sizeof(struct itemset) * d->nitemsets);
        d->itemsets[i].itemname = strdup(name);
        d->itemsets[i].items = NULL;
        d->itemsets[i].nitems = 0;
    }
    for(j=0; j<d->itemsets[i].nitems; j++)
        if(!strcmp(data, d->itemsets[i].items[j]))
            break;
    if (j==d->itemsets[i].nitems) {
        d->itemsets[i].nitems += 1;
        d->itemsets[i].items = realloc(d->itemsets[i].items, sizeof(char*) * d->itemsets[i].nitems);
        d->itemsets[i].items[j] = strdup(data);
    }
}

void
names_recorddeldata(dictionary d, char* name, char* data)
{
    int i, j;
    for(i=0; i<d->nitemsets; i++)
        if(!strcmp(name, d->itemsets[i].itemname))
            break;
    if (i<d->nitemsets) {
        for(j=0; j<d->itemsets[i].nitems; j++)
            if(!strcmp(data, d->itemsets[i].items[j]))
                break;
        if (j<d->itemsets[i].nitems) {
            d->itemsets[i].nitems -= 1;
            for(; j<d->itemsets[i].nitems; j++)
                d->itemsets[i].items[j] = d->itemsets[i].items[j+1];
            if(d->itemsets[i].nitems > 0) {
                d->itemsets[i].items = realloc(d->itemsets[i].items, sizeof(char*) * d->itemsets[i].nitems);
            } else {
                free(d->itemsets[i].items);
                d->itemsets[i].items = NULL;
                d->nitemsets -= 1;
                for(; i<d->nitemsets; i++)
                    d->itemsets[i] = d->itemsets[i+1];
                if(d->nitemsets > 0) {
                    d->itemsets = realloc(d->itemsets, sizeof(struct itemset) * d->nitemsets);
                } else {
                    free(d->itemsets);
                    d->itemsets = NULL;
                }
            }
        }
    }
}

names_iterator
names_recordalltypes(dictionary d)
{
    return iterator(d->nitemsets, d->itemsets, sizeof(struct itemset), offsetof(struct itemset, itemname));
}

names_iterator
names_recordallvalues(dictionary d, char*name)
{
    int i;
    for(i=0; i<d->nitemsets; i++) {
        if(!strcmp(name, d->itemsets[i].itemname))
            break;
    }
    if(i<d->nitemsets) {
        return iterator(d->itemsets[i].nitems, d->itemsets[i].items, sizeof(char*), 0);
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
        free(dict->itemsets[i].items[j]);
      }
      free(dict->itemsets[i].itemname);
      free(dict->itemsets[i].items);
    }
    free(dict->itemsets);

    free(dict->name);
    free(dict->spanhash);
    free(dict->spansignature);
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

void
clearvalidity(dictionary record)
{
    free(record->validfrom);
    free(record->validupto);
    free(record->expiry);
    record->validfrom = NULL;
    record->validupto = NULL;
    record->expiry = NULL;
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

int
names_recordmarshall(marshall_handle h, void* ptr)
{
    dictionary d = ptr;
    int size = 0;
    int i;
    //size += marshalling(h, "record", d, NULL, sizeof(struct dictionary_struct), marshallself);    *(char**)ptr = malloc(sizeof(struct dictionary_struct));
    size += marshalling(h, "name", &(d->name), NULL, 0, marshallstring);
    size += marshalling(h, "revision", &(d->revision), NULL, 0, marshallinteger);
    size += marshalling(h, "spanhash", &(d->spanhash), NULL, 0, marshallstring);
    size += marshalling(h, "spansignature", &(d->spansignature), NULL, 0, marshallstring);
    size += marshalling(h, "validupto", &(d->validupto), marshall_OPTIONAL, 0, marshallinteger);
    size += marshalling(h, "validfrom", &(d->validfrom), marshall_OPTIONAL, 0, marshallinteger);
    size += marshalling(h, "expiry", &(d->expiry), marshall_OPTIONAL, 0, marshallinteger);
    size += marshalling(h, "itemsets", &(d->itemsets), &(d->nitemsets), sizeof(struct itemset), marshallself);
    for(i=0; i<d->nitemsets; i++) {
        size += marshalling(h, "itemname", &(d->itemsets[i].itemname), NULL, 0, marshallstring);
        size += marshalling(h, "items", &(d->itemsets[i].items), &(d->itemsets[i].nitems), sizeof(char*), marshallstringarray);
        size += marshalling(h, NULL, NULL, &(d->nitemsets), i, marshallself);
    }
    return size;
}

void
composestring(char* dst, char* src, ...)
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
composestring2(char** ptr, char* src, ...)
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
composestringf(char** ptr, char* fmt,...)
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
decomposestringf(const char* ptr, char* fmt,...)
{
    va_list ap;
    va_start(ap,fmt);
    vsscanf(ptr,fmt,ap);
    va_end(ap);
}

int
getset(dictionary d, const char* name, const char** get, char** set)
{
    int rc = 1;
    if (get)
        *get = NULL;
    if (!strcmp(name,"name")) {
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
            abort();
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
            abort();
            decomposestringf(name,"%d",&d->tmpValidUpto);
        }
    } else if(!strcmp(name,"expiry")) {
        rc = (d->expiry != NULL);
        if (get) {
            if(d->validupto) {
                composestringf(&(d->tmpExpiry), "%d", *(d->expiry));
                *get = d->tmpExpiry;
            } else
                *get = NULL;
        }
        if (set) {
            abort();
            decomposestringf(name,"%d",&d->tmpExpiry);
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
        abort();
    }
    return rc;
}
