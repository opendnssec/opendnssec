#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ldns/ldns.h>
#include "uthash.h"
#include "proto.h"

#pragma GCC optimize ("O0")

typedef int (*comparefunction)(const void *, const void *);
typedef int (*acceptfunction)(dictionary newitem, dictionary currentitem, int* cmp);

struct names_index_struct {
    const char* keyname;
    ldns_rbtree_t* tree;
    acceptfunction acceptfunc;
};

struct names_iterator_struct {
    int (*iterate)(names_iterator*iter, void**);
    int (*advance)(names_iterator*iter, void**);
    int (*end)(names_iterator*iter);
    ldns_rbnode_t* current;
};

int
names_indexcreate(names_index_type* index, const char* keyname)
{
    comparefunction comparfunc;
    acceptfunction  acceptfunc;
    *index = malloc(sizeof(struct names_index_struct));
    names_recordindexfunction(keyname, &acceptfunc, &comparfunc);
    assert(acceptfunc);
    assert(comparfunc);
    (*index)->keyname = strdup(keyname);
    (*index)->acceptfunc = acceptfunc;
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
    free((void*)index->keyname);
    free(index);
}

int
names_indexaccept(names_index_type index, dictionary record)
{
    int cmp;
    if(index->acceptfunc) {
        return index->acceptfunc(record, NULL, &cmp);
    } else
        return 1;
}

int
names_indexinsert(names_index_type index, dictionary d)
{
    int cmp;
    ldns_rbnode_t* node;
    if(index->acceptfunc(d, NULL, NULL)) {
        node = malloc(sizeof(ldns_rbnode_t));
        assert(d);
        node->key = d;
        node->data = d;
        if(!ldns_rbtree_insert(index->tree, node)) {
            free(node);
            node = ldns_rbtree_search(index->tree, d);
            assert(node);
            switch(index->acceptfunc(d, (dictionary)node->data, &cmp)) {
                case 0:
                    return 0;
                case 1:
                    if(names_recordhasmarker(d)) {
                        ldns_rbtree_delete(index->tree, node->key);
                    } else {
                        node->key = d;
                        node->data = d;
                    }
                    return 1;
                case 2:
                    ldns_rbtree_delete(index->tree, node->key);
                    return 0;
                default:
                    abort(); // FIXME
            }
        } else {
            return 1;
        }
    } else {
        node = ldns_rbtree_search(index->tree, d);
        if(node != NULL) {
            if(names_recordhasmarker(d) ||
               index->acceptfunc(d, (dictionary)node->data, &cmp) == 0 ||
               (cmp == 0 && node->key == d)) {
                ldns_rbtree_delete(index->tree, node->key);
            }
        }
        return 0;
    }
}

dictionary
names_indexlookupkey(names_index_type index, const char* keyvalue)
{
    dictionary find;
    dictionary found;
    find = names_recordcreate(NULL);
    getset(find,index->keyname,NULL,&keyvalue); // FIXME realisticly we only lookup on name
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
    find = names_recordcreate(NULL);
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
names_indexrange(names_index_type index, char* selection, ...)
{
    va_list ap;
    const char* find;
    const char* found;
    int findlen;
    dictionary record;
    ldns_rbnode_t* node;
    names_iterator iter;
    va_start(ap, selection);
    iter = names_iterator_create(0);
    if (index->tree) {
        find = va_arg(ap, char*);
        findlen = strlen(find);
        record = names_recordcreate(NULL);
        getset(record, "name", NULL, &find);
        (void)ldns_rbtree_find_less_equal(index->tree, record, &node);
        names_recorddestroy(record);
        while(node && node != LDNS_RBTREE_NULL) {
            record = (dictionary)node->key;
            getset(record,"name",&found,NULL);
            if(!strncmp(find,found,findlen) && (found[findlen-1]=='\0' || found[findlen-1]=='.')) {
                names_iterator_add(iter, record);
            } else {
                break;
            }
            node = ldns_rbtree_previous(node);
        }
    }
    va_end(ap);
    return iter;
}
