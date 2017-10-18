#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
    if(*iter) {
        if((*iter)->current != NULL && (*iter)->current != LDNS_RBTREE_NULL) {
            if(*item)
                *item = (*iter)->current;
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
    if(*iter) {
        if((*iter)->current != NULL && (*iter)->current != LDNS_RBTREE_NULL) {
            (*iter)->current = ldns_rbtree_next((*iter)->current);
            if((*iter)->current != NULL && (*iter)->current != LDNS_RBTREE_NULL) {
                if(*item)
                    *item = (*iter)->current;
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

static int
cmp(const void *a, const void *b)
{
    const char* x;
    const char* y;
    x = (const char*) a;
    y = (const char*) b;
    return strcmp(x, y);
}

names_table_type
names_tablecreate(void)
{
    struct names_table_struct* table;
    table = malloc(sizeof(struct names_table_struct));
    table->tree = ldns_rbtree_create(cmp);
    table->next = NULL;
    return table;
}

static void
disposenode(ldns_rbnode_t* node, void* cargo)
{
    (void)cargo;
    free(node);
}

void
names_tabledispose(names_table_type table)
{
    ldns_traverse_postorder(table->tree, disposenode, NULL);
    ldns_rbtree_free(table->tree);
    free(table);
}

void*
names_tableget(names_table_type table, char* name)
{
    struct ldns_rbnode_t* node;
    node = ldns_rbtree_search(table->tree, name);
    if (node == NULL || node == LDNS_RBTREE_NULL) {
        return NULL;
    } else {
        return (void*) node->data;
    }
}

int
names_tabledel(names_table_type table, char* name)
{
    struct ldns_rbnode_t* node;
    node = ldns_rbtree_delete(table->tree, name);
    if (node != NULL && node != LDNS_RBTREE_NULL) {
        free((void*)node->data);
        free(node);
        return 1;
    } else {
        return 0;
    }
}

void**
names_tableput(names_table_type table, char* name)
{
    struct ldns_rbnode_t* node;

    node = ldns_rbtree_search(table->tree, name);
    if (node == NULL || node == LDNS_RBTREE_NULL) {
        node = malloc(sizeof (struct ldns_rbnode_t));
        node->key = name;
        node->data = NULL;
        ldns_rbtree_insert(table->tree, node);
    }
    return (void**) &(node->data);
}

void
names_tableconcat(names_table_type* list, names_table_type item)
{
    assert(item->next == NULL);
    while(*list != NULL) {
        list = &(*list)->next;
    }
    *list = item;
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

struct names_changelogchain {
    int nviews;
    struct names_changelogchainentry {
        names_view_type view;
        names_table_type nextchangelog;
    } *views;
    names_table_type firstchangelog;
    names_table_type lastchangelog;
};


names_table_type
names_changelogpop(struct names_changelogchain* views, int viewid)
{
    names_table_type changelog;
    changelog = views->views[viewid].nextchangelog;
    if (changelog) {
        views->views[viewid].nextchangelog = changelog->next;
    }
    return changelog;
}

int
names_changelogsubscribe(names_view_type view, struct names_changelogchain** views)
{
    int viewid;
    if(*views == NULL) {
        *views = malloc(sizeof(struct names_changelogchain));
        (*views)->nviews = 1;
        (*views)->views = malloc(sizeof(struct names_changelogchainentry) * (*views)->nviews);
    } else {
        (*views)->nviews += 1;
        (*views)->views = realloc((*views)->views, sizeof(struct names_changelogchainentry) * (*views)->nviews);
    }
    viewid = (*views)->nviews - 1;
    (*views)->views[viewid].nextchangelog = NULL;
    (*views)->views[viewid].view = view;
    return viewid;
}

void
names_changelogsubmit(struct names_changelogchain* views, int viewid, names_table_type changelog)
{
    int i;
    views->views[viewid].nextchangelog = NULL;
    if(views->firstchangelog == NULL) {
        assert(views->lastchangelog != NULL);
        views->firstchangelog = views->lastchangelog = changelog;
    } else {
        views->lastchangelog->next = changelog;
        views->lastchangelog = changelog;
    }
    for (i = 0; i < views->nviews; i++) {
        if (i != viewid) {
            if (views->views[viewid].nextchangelog == NULL) {
                views->views[viewid].nextchangelog = changelog;
            }
        }
    }
}

void
names_changelogrelease(struct names_changelogchain* views, names_table_type changelog)
{
    int i;
    if(changelog == views->firstchangelog) {
        for(i=0; i<views->nviews; i++) {
            if(views->views[i].nextchangelog == changelog)
                break;
        }
        if(i == views->nviews) {
            views->firstchangelog = views->firstchangelog->next;
            if(views->firstchangelog == NULL) {
                views->lastchangelog = NULL;
            }
            names_tabledispose(changelog);
        }
    }
}
