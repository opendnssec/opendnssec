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
#include "utilities.h"
#include "proto.h"

#pragma GCC optimize ("O0")

struct names_table_struct {
    ldns_rbtree_t* tree;
    names_table_type next;
};

struct names_commitlog_struct {
    pthread_mutex_t lock;
    int nviews;
    struct names_changelogchainentry {
        names_view_type view;
        names_table_type nextchangelog;
    } *views;
    names_table_type firstchangelog;
    names_table_type lastchangelog;
    marshall_handle store;
    void (*storefn)(names_table_type, marshall_handle);
};

static void
destroynode(void* arg, void* key, void* val)
{
    (void)arg;
    (void)key;
    free(val);
}

void
names_commitlogdestroy(names_table_type table)
{
    names_tabledispose(table, destroynode, NULL);
}

void
names_commitlogdestroyall(names_commitlog_type commitlog, marshall_handle* store)
{
    names_table_type next;
    pthread_mutex_destroy(&commitlog->lock);
    if(store)
        *store = commitlog->store;
    while(commitlog->firstchangelog) {
        next = commitlog->firstchangelog->next;
        names_commitlogdestroy(commitlog->firstchangelog);
        commitlog->firstchangelog = next;
    }
    free(commitlog->views);
    free(commitlog);
}

int
names_commitlogpoppush(names_commitlog_type commitlog, int viewid, names_table_type* previouslog, names_table_type* submitlog)
{
    int rc;
    int i;
    names_table_type poppedlog;
    names_table_type pushedlog;
    CHECK(pthread_mutex_lock(&commitlog->lock));

    poppedlog = commitlog->views[viewid].nextchangelog;
    if(poppedlog) {
        if(*previouslog) {
            assert(*previouslog == poppedlog);
            commitlog->views[viewid].nextchangelog = poppedlog->next;
            poppedlog = commitlog->views[viewid].nextchangelog;
            if(submitlog && poppedlog == *submitlog) {
                poppedlog = NULL;
                *submitlog = names_tablecreate();
            }
            if (*previouslog == commitlog->firstchangelog) {
                for (i = 0; i < commitlog->nviews; i++) {
                    if (commitlog->views[i].nextchangelog == *previouslog)
                        break;
                }
                if (i == commitlog->nviews) {
                    commitlog->firstchangelog = commitlog->firstchangelog->next;
                    if (commitlog->firstchangelog == NULL) {
                        commitlog->lastchangelog = NULL;
                    }
                    names_commitlogdestroy(*previouslog);
                }
            }
        }
        *previouslog = poppedlog;
    } else {
        *previouslog = NULL;
    }
    if(*previouslog == NULL) {
        if(submitlog) {
            pushedlog = *submitlog;
            *submitlog = names_tablecreate();
            *previouslog = pushedlog;
            if (commitlog->firstchangelog == NULL) {
                assert(commitlog->lastchangelog == NULL);
                commitlog->firstchangelog = commitlog->lastchangelog = pushedlog;
            } else {
                assert(commitlog->lastchangelog != pushedlog);
                commitlog->lastchangelog->next = pushedlog;
                commitlog->lastchangelog = pushedlog;
            }
            for (i=0; i<commitlog->nviews; i++) {
                if (i != viewid) {
                    if (commitlog->views[i].nextchangelog == NULL) {
                        commitlog->views[i].nextchangelog = pushedlog;
                    }
                } else {
                    assert(commitlog->views[viewid].nextchangelog == NULL);
                    commitlog->views[i].nextchangelog = pushedlog;
                }
            }
            names_commitlogpersistincr(commitlog, pushedlog);
        }
        rc = 0;
    } else {
        rc = 1;
    }
    CHECK(pthread_mutex_unlock(&commitlog->lock));
    return rc;
}

int
names_commitlogsubscribe(names_view_type view, names_commitlog_type* commitlogptr)
{
    int viewid;
    if(*commitlogptr == NULL) {
        *commitlogptr = malloc(sizeof(struct names_commitlog_struct));
        CHECK(pthread_mutex_init(&(*commitlogptr)->lock, NULL));
        CHECK(pthread_mutex_lock(&(*commitlogptr)->lock));
        (*commitlogptr)->nviews = 1;
        (*commitlogptr)->views = malloc(sizeof(struct names_changelogchainentry) * (*commitlogptr)->nviews);
        (*commitlogptr)->firstchangelog = NULL;
        (*commitlogptr)->lastchangelog = NULL;
        (*commitlogptr)->store = NULL;
    } else {
        CHECK(pthread_mutex_lock(&(*commitlogptr)->lock));
        (*commitlogptr)->nviews += 1;
        (*commitlogptr)->views = realloc((*commitlogptr)->views, sizeof(struct names_changelogchainentry) * (*commitlogptr)->nviews);
    }
    viewid = (*commitlogptr)->nviews - 1;
    (*commitlogptr)->views[viewid].nextchangelog = NULL;
    (*commitlogptr)->views[viewid].view = view;
    CHECK(pthread_mutex_unlock(&(*commitlogptr)->lock));
    return viewid;
}

void
names_commitlogrelease(names_commitlog_type commitlog, names_table_type changelog)
{
    int i;
    CHECK(pthread_mutex_lock(&commitlog->lock));
    if(changelog == commitlog->firstchangelog) {
        for(i=0; i<commitlog->nviews; i++) {
            if(commitlog->views[i].nextchangelog == changelog)
                break;
        }
        if(i == commitlog->nviews) {
            commitlog->firstchangelog = commitlog->firstchangelog->next;
            if(commitlog->firstchangelog == NULL) {
                commitlog->lastchangelog = NULL;
            }
            names_commitlogdestroy(changelog);
        }
    }
    CHECK(pthread_mutex_unlock(&commitlog->lock));
}

void
names_commitlogpersistincr(names_commitlog_type views, names_table_type changelog)
{
    if(views->store == NULL)
        return;
    views->storefn(changelog, views->store);
}

void
names_commitlogpersistappend(names_commitlog_type commitlog, void (*persistfn)(names_table_type, marshall_handle), marshall_handle store)
{
    CHECK(pthread_mutex_lock(&commitlog->lock));
    commitlog->store = store;
    commitlog->storefn = persistfn;
    CHECK(pthread_mutex_unlock(&commitlog->lock));
}

int
names_commitlogpersistfull(names_commitlog_type commitlog, void (*persistfn)(names_table_type, marshall_handle), int viewid, marshall_handle store, marshall_handle* oldstore)
{
    names_table_type changelog;
    CHECK(pthread_mutex_lock(&commitlog->lock));
    for(changelog = commitlog->views[viewid].nextchangelog; changelog; changelog=changelog->next) {
        persistfn(changelog, store);
    }
    *oldstore = commitlog->store;
    commitlog->store = store;
    commitlog->storefn = persistfn;
    CHECK(pthread_mutex_unlock(&commitlog->lock));
    return 0;
}
