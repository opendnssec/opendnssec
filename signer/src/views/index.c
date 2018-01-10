#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ldns/ldns.h>
#include "uthash.h"
#include "proto.h"

#pragma GCC optimize ("O0")

typedef int (*comparefunction)(const void *, const void *);
typedef int (*acceptfunction)(names_index_type index, dictionary newitem, dictionary currentitem, int* cmp);

struct names_index_struct {
    char* keyname;
    ldns_rbtree_t* tree;
    acceptfunction  acceptfunc;
};

struct names_iterator_struct {
    int (*iterate)(names_iterator*iter, void**);
    int (*advance)(names_iterator*iter, void**);
    int (*end)(names_iterator*iter);
    ldns_rbnode_t* current;
};

int
acceptance1(names_index_type index, dictionary newitem, dictionary currentitem, int *cmp)
{
    (void)index;
    (void)currentitem;
    if(getset(newitem,"validfrom",NULL,NULL))
        return 1;
    else
        return 0;
}

#define DEFINECOMPARISON(N) \
    int N(names_index_type, dictionary, dictionary, int*); \
    int N ## _ldns(const void* a, const void* b) { \
    int rc; N(NULL, (dictionary)a, (dictionary)b, &rc); return rc; }

DEFINECOMPARISON(comparename)
DEFINECOMPARISON(comparenamerevision)
DEFINECOMPARISON(compareexpiry)
DEFINECOMPARISON(comparedenialname)
DEFINECOMPARISON(compareupcomingset)
DEFINECOMPARISON(compareincomingset)
DEFINECOMPARISON(comparecurrentset)
DEFINECOMPARISON(comparerelevantset)
DEFINECOMPARISON(comparesignedset)

int
comparename(names_index_type index, dictionary newitem, dictionary curitem, int* cmp)
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
            *cmp = strcmp(left, right);
        }
    }
    return 1;
}

int
comparenamerevision(names_index_type index, dictionary newitem, dictionary curitem, int* cmp)
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
compareexpiry(names_index_type index, dictionary newitem, dictionary curitem, int* cmp)
{
    const char* left;
    const char* right;
    (void)index;
    getset(newitem, "expiry", &left, NULL);
    if (curitem) {
        if (cmp) {
            getset(curitem, "expiry", &right, NULL);
            assert(left);
            assert(right);
            *cmp = strcmp(left, right);
        }
    }
    if (!left)
        return 0;
    return 1;
}

/* rule: you cannot ammend a field when that field is in use for to store a record in an index */

int
comparedenialname(names_index_type index, dictionary newitem, dictionary curitem, int* cmp)
{
    const char* left;
    const char* right;
    (void)index;
    getset(newitem, "denialname", &left, NULL);
    if (curitem) {
        if(cmp) {
            getset(curitem, "denialname", &right, NULL);
            assert(left);
            assert(right);
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
compareupcomingset(names_index_type index, dictionary newitem, dictionary curitem, int* cmp)
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
compareincomingset(names_index_type index, dictionary newitem, dictionary curitem, int* cmp)
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
    if(getset(newitem, "validfrom", NULL, NULL))
        return 0;
    return 1;
}

int
comparecurrentset(names_index_type index, dictionary newitem, dictionary curitem, int* cmp)
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
comparerelevantset(names_index_type index, dictionary newitem, dictionary curitem, int* cmp)
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
comparesignedset(names_index_type index, dictionary newitem, dictionary curitem, int* cmp)
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
names_indexcreate(names_index_type* index, const char* keyname)
{
    *index = malloc(sizeof(struct names_index_struct));
    comparefunction comparfunc;
#define REFERCOMPARISON(F,N) do { (*index)->keyname = strdup(F); comparfunc = N ## _ldns; (*index)->acceptfunc = N; } while(0)
    if(!strcmp(keyname,"name")) {
        REFERCOMPARISON("name", comparename);
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
    } else {
        abort();
    }
    (*index)->tree = ldns_rbtree_create(comparfunc);
    return 0;
}

struct destroyinfo {
    void (*free)(void* arg, void* key, void* val);
    void* arg;
};

static void
disposenode(ldns_rbnode_t* node, void* cargo)
{
    struct destroyinfo* user = cargo;
    if(user && user->free) {
        user->free(user->arg, (void*)node->key, (void*)node->data);
    }
    free(node);
}

void
names_indexdestroy(names_index_type index, void (*userfunc)(void* arg, void* key, void* val), void* userarg)
{
    struct destroyinfo cargo;
    cargo.free = userfunc;
    cargo.arg = userarg;
    ldns_traverse_postorder(index->tree, disposenode, (userfunc?&cargo:NULL));
    ldns_rbtree_free(index->tree);
    free(index->keyname);
    free(index);
}

int
names_indexaccept(names_index_type index, dictionary record)
{
    int cmp;
    if(index->acceptfunc) {
        return index->acceptfunc(index, record, NULL, &cmp);
    } else
        return 1;
}

int
names_indexinsert(names_index_type index, dictionary d)
{
    int cmp;
    ldns_rbnode_t* node;
    if(index->acceptfunc(index, d, NULL, NULL)) {
        node = malloc(sizeof(ldns_rbnode_t));
        assert(d);
        node->key = d;
        node->data = d;
        if(!ldns_rbtree_insert(index->tree, node)) {
            free(node);
            node = ldns_rbtree_search(index->tree, d);
            assert(node);
            if(index->acceptfunc(index, d, (dictionary)node->data, &cmp)) {
                node->key = d;
                node->data = d;
                return 1;
            } else
                return 0;
        } else
            return 1;
    } else
        return 0;
}

dictionary
names_indexlookupkey(names_index_type index, char* keyvalue)
{
    dictionary find;
    dictionary found;
    find = create(NULL);
    getset(find,index->keyname,NULL,&keyvalue);
    found = names_indexlookup(index, find);
    dispose(find);
    return found;
}

dictionary
names_indexlookup(names_index_type index, dictionary find)
{
    ldns_rbnode_t* node;
    node = ldns_rbtree_search(index->tree, find);
    return node ? (dictionary) node->data : NULL;
}

int
names_indexremove(names_index_type index, dictionary d)
{
    const char *value;
    if(getset(d, index->keyname, &value, NULL)) {
        return names_indexremovekey(index, value);
    } else
        return 0;
}

int
names_indexremovekey(names_index_type index, const char* keyvalue)
{
    dictionary find;
    ldns_rbnode_t* node;
    find = create(NULL);
    getset(find, index->keyname, NULL, &keyvalue);
    node = ldns_rbtree_delete(index->tree, find);
    dispose(find);
    if(node) {
        free(node);
        return 1;
    } else
        return 0;
}

static int
iterateimpl(names_iterator* i, void** item)
{
    struct names_iterator_struct** iter = i;
    if (item)
        *item = NULL;
    if (*iter) {
        if ((*iter)->current != NULL && (*iter)->current != LDNS_RBTREE_NULL) {
            if (item)
                *item = (void*) (*iter)->current->data;
            return 1;
        } else {
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
    if (item)
        *item = NULL;
    if (*iter) {
        if((*iter)->current != NULL && (*iter)->current != LDNS_RBTREE_NULL) {
            (*iter)->current = ldns_rbtree_next((*iter)->current);
            if((*iter)->current != NULL && (*iter)->current != LDNS_RBTREE_NULL) {
                if(item)
                    *item = (void*)  (*iter)->current->data;
                return 1;
            }
        }
        free(*iter);
        *iter = NULL;
    }
    return 0;
}

static int
endimpl(names_iterator*iter)
{
    if(*iter) free(*iter);
        *iter = NULL;
    return 0;
}

names_iterator
names_indexiterator(names_index_type index)
{
    names_iterator iter;
    iter = malloc(sizeof(struct names_iterator_struct));
    iter->iterate = iterateimpl;
    iter->advance = advanceimpl;
    iter->end = endimpl;
    iter->current = (index->tree != NULL ? ldns_rbtree_first(index->tree) : NULL);
    return iter;
}

names_iterator
names_indexrange(names_index_type index, char* selection,...)
{
    va_list ap;
    names_iterator iter;
    va_start(ap, selection);
    va_end(ap);
    iter = malloc(sizeof (struct names_iterator_struct));
    iter->iterate = iterateimpl;
    iter->advance = advanceimpl;
    iter->end = endimpl;
    if (index->tree) {
        if (!ldns_rbtree_find_less_equal(index->tree, selection, &iter->current)) {
            if (iter->current)
                iter->current = ldns_rbtree_next(iter->current);
        }
    } else
        iter->current = NULL;
    return iter;
}
