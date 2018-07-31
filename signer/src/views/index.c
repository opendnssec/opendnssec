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
names_indexinsert(names_index_type index, recordset_type record, recordset_type* existing) {
    int cmp;
    ldns_rbnode_t* node;
    if (existing && *existing) {
        node = ldns_rbtree_delete(index->tree, *existing);
        free(node);
    }
    if (record) {
        if (index->acceptfunc(record, NULL, NULL)) {
            node = malloc(sizeof (ldns_rbnode_t));
            assert(record);
            node->key = record;
            node->data = record;
            if (!ldns_rbtree_insert(index->tree, node)) {
                free(node);
                node = ldns_rbtree_search(index->tree, record);
                assert(node);
                if (existing && *existing == NULL) {
                    *existing = (recordset_type) node->data;
                }
                switch (index->acceptfunc(record, (recordset_type) node->data, &cmp)) {
                    case 0:
                        logger_message(&names_logcommitlog, logger_noctx, logger_DEBUG, "      record ignored from %s no match after found\n", index->keyname);
                        *existing = NULL;
                        return 0;
                    case 1:
                        logger_message(&names_logcommitlog, logger_noctx, logger_DEBUG, "      record rewritten in %s matched after found\n", index->keyname);
                        node->key = record;
                        node->data = record;
                        return 1;
                    case 2:
                        logger_message(&names_logcommitlog, logger_noctx, logger_DEBUG, "      record deleted in %s dropped after found\n", index->keyname);
                        node = ldns_rbtree_delete(index->tree, node->key);
                        free(node);
                        return 0;
                    default:
                        abort(); // FIXME
                }
            } else {
                logger_message(&names_logcommitlog, logger_noctx, logger_DEBUG, "      record inserted in %s after not found\n", index->keyname);
                return 1;
            }
        } else {
            node = ldns_rbtree_search(index->tree, record);
            if (node != NULL) {
                if (index->acceptfunc(record, (recordset_type) node->data, &cmp) == 0 || (cmp == 0 && node->key == record)) {
                    logger_message(&names_logcommitlog, logger_noctx, logger_DEBUG, "      record not accepted and deleted from in %s\n", index->keyname);
                    node = ldns_rbtree_delete(index->tree, node->key);
                    free(node);
                } else {
                    logger_message(&names_logcommitlog, logger_noctx, logger_DEBUG, "      record not accepted but not found yet not deleted in %s\n", index->keyname);
                }
            } else {
                logger_message(&names_logcommitlog, logger_noctx, logger_DEBUG, "      record not accepted and not found in %s\n", index->keyname);
            }
            return 0;
        }
    } else
        return 0;
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
    ldns_rbnode_t* node;
    node = ldns_rbtree_delete(index->tree, d);
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
names_iteratordescendants(names_index_type index, va_list ap)
{
    const char* find;
    const char* found;
    int findlen;
    recordset_type record;
    ldns_rbnode_t* node;
    names_iterator iter;
    iter = names_iterator_createrefs(NULL);
    find = va_arg(ap, char*);
    findlen = strlen(find);
    record = names_recordcreatetemp(find);
    (void) ldns_rbtree_find_less_equal(index->tree, record, &node);
    names_recorddispose(record);
    while (node && node != LDNS_RBTREE_NULL) {
        record = (recordset_type) node->key;
        found = names_recordgetname(record);
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
        ldns_rdf_deep_free(parent);
        if(!strcmp(name,".") || !strcmp(name,"")) {
            free(name);
            name = NULL;
        }
    }
    ldns_rdf_deep_free(dname);
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
    iter = names_iterator_createrefs(NULL);
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
            names_recorddispose(record);
            if (node && node != LDNS_RBTREE_NULL) {
                names_iterator_addptr(iter, node->data);
            }
        }
    } while(parent);
    if(parent)
        free(parent);
    return iter;
}

names_iterator
names_iteratorchangedeletes(names_index_type index, va_list ap)
{
    recordset_type find;
    recordset_type found;
    int serial, since;
    ldns_rbnode_t* node;
    names_iterator iter;

    serial = va_arg(ap, int);
    find = names_recordcreatetemp(NULL);
    names_recordsetvalidupto(find, serial);
    iter = names_iterator_createrefs(NULL);

    if(!ldns_rbtree_find_less_equal(index->tree, find, &node)) {
        if(node == NULL || node == LDNS_RBTREE_NULL) {
            node = ldns_rbtree_first(index->tree);
        } else {
            node = ldns_rbtree_next(node);
        }
    }
    while (node && node != LDNS_RBTREE_NULL) {
        found = (recordset_type) node->key;
        if(names_recordvalidfrom(found,&since)) {
            if(since <= serial) {
                names_iterator_addptr(iter, found);
            }
        } else {
            abort(); // FIXME cannot happen
        }
        node = ldns_rbtree_next(node);
    }

    names_recorddispose(find);
    return iter;
}

names_iterator
names_iteratorchangeinserts(names_index_type index, va_list ap)
{
    recordset_type find;
    recordset_type found;
    int serial, since;
    ldns_rbnode_t* node;
    names_iterator iter;

    serial = va_arg(ap, int);
    find = names_recordcreatetemp(NULL);
    names_recordsetvalidfrom(find, serial);
    iter = names_iterator_createrefs(NULL);

    if(!ldns_rbtree_find_less_equal(index->tree, find, &node)) {
        if(node == NULL || node == LDNS_RBTREE_NULL) {
            node = ldns_rbtree_first(index->tree);
        } else {
            node = ldns_rbtree_next(node);
        }
    }
    while (node && node != LDNS_RBTREE_NULL) {
        found = (recordset_type) node->key;
        if(!names_recordvalidupto(found,NULL)) {
            names_iterator_addptr(iter, found);
        }
        node = ldns_rbtree_next(node);
    }

    names_recorddispose(find);
    return iter;
}

names_iterator
names_iteratorchanges(names_index_type index, va_list ap)
{
    recordset_type find;
    recordset_type found;
    const char* name;
    int serial;
    ldns_rbnode_t* node;
    names_iterator iter;

    name = va_arg(ap, const char*);
    serial = va_arg(ap, int);
    find = names_recordcreatetemp(name);
    names_recordsetvalidfrom(find, serial);
    iter = names_iterator_createrefs(NULL);
            char*t= NULL;

    if(!ldns_rbtree_find_less_equal(index->tree, find, &node)) {
        if(node == NULL || node == LDNS_RBTREE_NULL) {
            node = ldns_rbtree_first(index->tree);
        } else {
            node = ldns_rbtree_next(node);
        }
    }
    while (node && node != LDNS_RBTREE_NULL) {
        found = (recordset_type) node->key;
        if(strcmp(names_recordgetname(found), name)) {
            break;
        }
        names_iterator_addptr(iter, found);
        node = ldns_rbtree_next(node);
    }

    names_recorddispose(find);
    return iter;
}



void
names_indexsearchfunction(names_index_type index, names_view_type view, const char* keyname)
{
    if(!strcmp(keyname,"namehierarchy")) {
        names_viewaddsearchfunction(view, index, names_iteratordescendants);
    } else if(!strcmp(keyname,"nameready")) {
        names_viewaddsearchfunction(view, index, names_iteratorancestors);
    } else if(!strcmp(keyname,"expiry")) {
        names_viewaddsearchfunction(view, index, names_iteratorexpiring);
    } else if(!strcmp(keyname,"validchanges")) {
        names_viewaddsearchfunction(view, index, names_iteratorchanges);
    } else if(!strcmp(keyname,"validdeletes")) {
        names_viewaddsearchfunction(view, index, names_iteratorchangedeletes);
    } else if(!strcmp(keyname,"validinserts")) {
        names_viewaddsearchfunction(view, index, names_iteratorchangeinserts);
    }
}
