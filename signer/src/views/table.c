#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <ldns/ldns.h>
#include "uthash.h"
#include "proto.h"

#pragma GCC optimize ("O0")

struct names_table_struct {
    ldns_rbtree_t* tree;
    names_table_type next;
};

struct names_iterator_struct {
    int (*iterate)(names_iterator*iter, void**);
    int (*advance)(names_iterator*iter, void**);
    int (*end)(names_iterator*iter);
    ldns_rbnode_t* current;
};

static int
iterateimpl(names_iterator*i, void** item)
{
    struct names_iterator_struct** iter = i;
    if (item)
        *item = NULL;
    if (*iter) {
        if((*iter)->current != NULL && (*iter)->current != LDNS_RBTREE_NULL) {
            if(item)
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
                    *item = (void*) (*iter)->current->data;
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

names_table_type
names_tablecreate(void)
{
    struct names_table_struct* table;
    table = malloc(sizeof(struct names_table_struct));
    table->tree = ldns_rbtree_create(names_recordcompare_namerevision);
    table->next = NULL;
    return table;
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
names_tabledispose(names_table_type table, void (*userfunc)(void* arg, void* key, void* val), void* userarg)
{
    struct destroyinfo cargo;
    cargo.free = userfunc;
    cargo.arg = userarg;
    ldns_traverse_postorder(table->tree, disposenode, (userfunc?&cargo:NULL));
    ldns_rbtree_free(table->tree);
    free(table);
}

void*
names_tableget(names_table_type table, void* key)
{
    struct ldns_rbnode_t* node;
    node = ldns_rbtree_search(table->tree, key);
    if (node == NULL || node == LDNS_RBTREE_NULL) {
        return NULL;
    } else {
        return (void*) node->data;
    }
}

void**
names_tableput(names_table_type table, void* key)
{
    struct ldns_rbnode_t* node;

    node = ldns_rbtree_search(table->tree, key);
    if (node == NULL || node == LDNS_RBTREE_NULL) {
        node = malloc(sizeof (struct ldns_rbnode_t));
        node->key = key;
        node->data = NULL;
        ldns_rbtree_insert(table->tree, node);
    }
    return (void**) &(node->data);
}

names_iterator
names_tableitems(names_table_type table)
{
    struct names_iterator_struct* iter;
    iter = malloc(sizeof(struct names_iterator_struct));
    iter->iterate = iterateimpl;
    iter->advance = advanceimpl;
    iter->end = endimpl;
    iter->current = ldns_rbtree_first(table->tree);
    return iter;
}
