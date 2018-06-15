#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ldns/ldns.h>
#include "uthash.h"
#include "proto.h"

#pragma GCC optimize ("O0")

typedef int (*comparefunction)(const void *, const void *);
typedef int (*acceptfunction)(recordset_type newitem, recordset_type currentitem, int* cmp);

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
names_indexinsert(names_index_type index, recordset_type d, recordset_type* existing)
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
            if(existing && *existing == NULL) {
                *existing = node->data;
            }
            switch(index->acceptfunc(d, (recordset_type)node->data, &cmp)) {
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
               index->acceptfunc(d, (recordset_type)node->data, &cmp) == 0 ||
               (cmp == 0 && node->key == d)) {
                ldns_rbtree_delete(index->tree, node->key);
            }
        }
        if(existing && *existing) {
            node = ldns_rbtree_search(index->tree, *existing);
            if(node != NULL) {
                if(node->key == *existing) {
                    node = ldns_rbtree_delete(index->tree, node->key);
                    assert(node);
                    ldns_rbtree_free(node);
                }
            }
        }
        return 0;
    }
}

recordset_type
names_indexlookupkey(names_index_type index, const char* keyvalue)
{
    recordset_type find;
    recordset_type found;
    /* FIXME, we will only call this function to perform lookups by name (without revision), but
     * fundamentally we should use the index key
     */
    find = names_recordcreatetemp((char*)keyvalue);
    found = names_indexlookup(index, find);
    names_recorddispose(find);
    return found;
}

recordset_type
names_indexlookup(names_index_type index, recordset_type find)
{
    ldns_rbnode_t* node;
    node = ldns_rbtree_search(index->tree, find);
    return (node != NULL && node != LDNS_RBTREE_NULL) ? (recordset_type) node->data : NULL;
}

recordset_type
names_indexlookupnext(names_index_type index, recordset_type find)
{
    ldns_rbnode_t* node;
    node = ldns_rbtree_search(index->tree, find);
    if(node != NULL && node != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_next(node);
        if(node == NULL || node == LDNS_RBTREE_NULL) {
            node = ldns_rbtree_first(index->tree);
        }
    }
    return (node != NULL && node != LDNS_RBTREE_NULL) ? (recordset_type) node->data : NULL;
}

int
names_indexremove(names_index_type index, recordset_type d)
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
    recordset_type find;
    ldns_rbnode_t* node;
    find = names_recordcreatetemp(NULL);
    getset(find, index->keyname, NULL, &keyvalue);
    node = ldns_rbtree_delete(index->tree, find);
    names_recorddispose(find);
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
names_indexrange(names_index_type index, const char* selection, ...)
{
    va_list ap;
    const char* find;
    const char* found;
    int findlen;
    recordset_type record;
    ldns_rbnode_t* node;
    names_iterator iter;
    va_start(ap, selection);
    iter = names_iterator_createrefs();
    if (index->tree) {
        if(!strcmp(selection, "descendants")) {
            find = va_arg(ap, char*);
            findlen = strlen(find);
            record = names_recordcreatetemp(NULL);
            getset(record, "name", NULL, &find);
            (void)ldns_rbtree_find_less_equal(index->tree, record, &node);
            names_recorddestroy(record);
            while(node && node != LDNS_RBTREE_NULL) {
                record = (recordset_type)node->key;
                getset(record,"name",&found,NULL);
                if(!strncmp(find,found,findlen) && (found[findlen-1]=='\0' || found[findlen-1]=='.')) {
                    names_iterator_addptr(iter, record);
                } else {
                    break;
                }
                node = ldns_rbtree_previous(node);
            }
        } else if(!strcmp(selection, "ancestors")) {
            char* name;
            ldns_rdf* dname;
            ldns_rdf* parent;
            name = va_arg(ap, char*);
            do {
                dname = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, name);
                parent = ldns_dname_left_chop(dname);
                if(parent) {
                    name = ldns_rdf2str(parent);
                    ldns_rdf_free(parent);
                    record = names_recordcreatetemp(NULL);
                    getset(record, "name", NULL, &name);
                    node = ldns_rbtree_search(index->tree, record);
                    names_recorddestroy(record);
                    if(node && node != LDNS_RBTREE_NULL) {
                        names_iterator_addptr(iter, record);
                    }
                }
                ldns_rdf_free(dname);
            } while(name && strcmp(name,".") && strcmp(name,""));
        }
    }
    va_end(ap);
    return iter;
}

names_iterator
names_iteratordescendants(names_index_type index, va_list ap)
{
    const char* find;
    const char* found;
    int findlen;
    recordset_type record;
    ldns_rbnode_t* node;
    names_iterator iter;
    iter = names_iterator_createrefs();
    find = va_arg(ap, char*);
    findlen = strlen(find);
    record = names_recordcreatetemp(NULL);
    getset(record, "name", NULL, &find);
    (void) ldns_rbtree_find_less_equal(index->tree, record, &node);
    names_recorddestroy(record);
    while (node && node != LDNS_RBTREE_NULL) {
        record = (recordset_type) node->key;
        getset(record, "name", &found, NULL);
        if (!strncmp(find, found, findlen) && (found[findlen - 1] == '\0' || found[findlen - 1] == '.')) {
            names_iterator_addptr(iter, record);
        } else {
            break;
        }
        node = ldns_rbtree_previous(node);
    }
    return iter;
}

static char*
names_parent(const char* child)
{
    char* name = NULL;
    ldns_rdf* parent;
    ldns_rdf* dname;
    dname = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, child);
    parent = ldns_dname_left_chop(dname);
    if (parent) {
        name = ldns_rdf2str(parent);
        ldns_rdf_free(parent);
        if(!strcmp(name,".") || !strcmp(name,"")) {
            free(name);
            name = NULL;
        }
    }
    ldns_rdf_free(dname);
    return name;
}

names_iterator
names_iteratorancestors(names_index_type index, va_list ap)
{
    recordset_type record;
    ldns_rbnode_t* node;
    names_iterator iter;
    char* name;
    char* parent = NULL;

    name = va_arg(ap, char*);
    iter = names_iterator_createrefs();
    do {
        if(parent) {
            name = parent;
            parent = names_parent(name);
            free(name);
        } else
            parent = names_parent(name);
        if (parent) {
            record = names_recordcreatetemp(parent);
            node = ldns_rbtree_search(index->tree, record);
            names_recorddestroy(record);
            if (node && node != LDNS_RBTREE_NULL) {
                names_iterator_addptr(iter, node->data);
            }
        }
    } while(parent);
    return iter;
}

void
names_indexsearchfunction(names_index_type index, names_view_type view, const char* keyname)
{
    if(!strcmp(keyname,"namehierarchy")) {
        names_viewaddsearchfunction(view, index, names_iteratordescendants);
    } else if(!strcmp(keyname,"nameready")) {
        names_viewaddsearchfunction(view, index, names_iteratorancestors);
        names_viewaddsearchfunction(view, index, names_iteratorexpiring);
    }    
}
