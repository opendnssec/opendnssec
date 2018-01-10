#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

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
names_tableput(names_table_type table, const char* name)
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
    pthread_mutex_t lock;
    int nviews;
    struct names_changelogchainentry {
        names_view_type view;
        names_table_type nextchangelog;
    } *views;
    names_table_type firstchangelog;
    names_table_type lastchangelog;
    marshall_handle store;
};

static void
destroynode(void* arg, void* key, void* val)
{
    (void)arg;
    (void)key;
    free(val);
}

void
names_changelogdestroy(names_table_type table)
{
    names_tabledispose(table, destroynode, NULL);
}

void
names_changelogdestroyall(struct names_changelogchain* views, marshall_handle* store)
{
    names_table_type next;
    pthread_mutex_destroy(&views->lock);
    if(store)
        *store = views->store;
    while(views->firstchangelog) {
        next = views->firstchangelog->next;
        names_changelogdestroy(views->firstchangelog);
        views->firstchangelog = next;
    }
    free(views->views);
    free(views);
}

names_table_type
names_changelogpoppush(struct names_changelogchain* views, int viewid, names_table_type* mychangelog)
{
    int i;
    names_table_type poppedchangelog;
    names_table_type pushedchangelog;
    CHECK(pthread_mutex_lock(&views->lock));
    poppedchangelog = views->views[viewid].nextchangelog;
    if (poppedchangelog) {
        views->views[viewid].nextchangelog = poppedchangelog->next;
    } else {
        if(mychangelog) {
            pushedchangelog = *mychangelog;
            *mychangelog = names_tablecreate();
            views->views[viewid].nextchangelog = NULL;
            if (views->firstchangelog == NULL) {
                assert(views->lastchangelog == NULL);
                views->firstchangelog = views->lastchangelog = pushedchangelog;
            } else {
                assert(views->lastchangelog != pushedchangelog);
                views->lastchangelog->next = pushedchangelog;
                views->lastchangelog = pushedchangelog;
            }
            for (i=0; i<views->nviews; i++) {
                if (i != viewid) {
                    if (views->views[i].nextchangelog == NULL) {
                        views->views[i].nextchangelog = pushedchangelog;
                    }
                } else {
                    assert(views->views[viewid].nextchangelog == NULL);
                }
            }
            //names_changelogpersistincr(views, pushedchangelog);
        }
    }
    CHECK(pthread_mutex_unlock(&views->lock));
    return poppedchangelog;
}

int
names_changelogsubscribe(names_view_type view, struct names_changelogchain** views)
{
    int viewid;
    if(*views == NULL) {
        *views = malloc(sizeof(struct names_changelogchain));
        CHECK(pthread_mutex_init(&(*views)->lock, NULL));
        CHECK(pthread_mutex_lock(&(*views)->lock));
        (*views)->nviews = 1;
        (*views)->views = malloc(sizeof(struct names_changelogchainentry) * (*views)->nviews);
        (*views)->firstchangelog = NULL;
        (*views)->lastchangelog = NULL;
        (*views)->store = NULL;
    } else {
        CHECK(pthread_mutex_lock(&(*views)->lock));
        (*views)->nviews += 1;
        (*views)->views = realloc((*views)->views, sizeof(struct names_changelogchainentry) * (*views)->nviews);
    }
    viewid = (*views)->nviews - 1;
    (*views)->views[viewid].nextchangelog = NULL;
    (*views)->views[viewid].view = view;
    CHECK(pthread_mutex_unlock(&(*views)->lock));
    return viewid;
}

void
names_changelogrelease(struct names_changelogchain* views, names_table_type changelog)
{
    int i;
    CHECK(pthread_mutex_lock(&views->lock));
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
            names_changelogdestroy(changelog);
        }
    }
    CHECK(pthread_mutex_unlock(&views->lock));
}

void
names_changelogpersistincr(struct names_changelogchain* views, names_table_type changelog)
{
    int count = 1;
    names_iterator iter;
    dictionary record;
    if(views->store == NULL)
        return;
    for(iter=names_tableitems(changelog); names_iterate(&iter,&record); names_advance(&iter,NULL)) { // FIXME TOTALLY WRONG!!! THESE ARE CHANGELOGRECORDS
        marshalling(views->store, "domain", &record, &count, sizeof(dictionary), names_recordmarshall);
    }
    record = NULL;
    marshalling(views->store, "domain", &record, &count, sizeof(dictionary), names_recordmarshall);
}

void
names_changelogpersistsetup(struct names_changelogchain* views, marshall_handle store)
{
    CHECK(pthread_mutex_lock(&views->lock));
    views->store = store;
    CHECK(pthread_mutex_unlock(&views->lock));
}

int
names_changelogpersistfull(struct names_changelogchain* views, names_iterator* iter, int viewid, marshall_handle store, marshall_handle* oldstore)
{
    int count = 1;
    dictionary record;
    names_table_type changelog;
    names_iterator moreiter;

    if(names_iterate(iter, &record)) {
        do {
            marshalling(store, "domain", &record, &count, sizeof(dictionary), names_recordmarshall);
        } while(names_advance(iter,&record));
    }
    record = NULL;
    marshalling(store, "domain", &record, &count, sizeof(dictionary), names_recordmarshall);

    CHECK(pthread_mutex_lock(&views->lock));
    for(changelog = views->views[viewid].nextchangelog; changelog; changelog=changelog->next) {
        for(moreiter=names_tableitems(changelog); names_iterate(&moreiter,&record); names_advance(&moreiter,NULL)) {
            marshalling(views->store, "domain", &record, &count, sizeof(dictionary), names_recordmarshall);
        }
        record = NULL;
        marshalling(views->store, "domain", &record, &count, sizeof(dictionary), names_recordmarshall);
    }
    *oldstore = views->store;
    views->store = store;
    CHECK(pthread_mutex_unlock(&views->lock));
    return 0;
}
