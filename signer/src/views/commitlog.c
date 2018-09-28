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
        names_table_type* nextchangelogptr;
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

static void
destroynodeandrecord(void* arg, void* key, void* val)
{
    (void)arg;
    (void)key;
    free(val);
    names_recorddisposal(key, 1);
}

void
names_commitlogdestroy(names_table_type table)
{
    names_tabledispose(table, destroynode, NULL);
}

void
names_commitlogdestroyfull(names_table_type table)
{
    names_tabledispose(table, destroynodeandrecord, NULL);
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
names_commitlogpoppush(names_commitlog_type logs, int viewid, names_table_type* commitlog, names_table_type* submitlog)
{
    int backlog;
    int i;
    names_table_type poppedlog;
    names_table_type previouslog = NULL;
    CHECK(pthread_mutex_lock(&logs->lock));
    
    poppedlog = *(logs->views[viewid].nextchangelogptr);
    if(poppedlog) {
        logs->views[viewid].nextchangelogptr = &(poppedlog->next);
        backlog = 1;
    } else
        backlog = 0;
    if(*commitlog) {
        if(*commitlog == logs->firstchangelog) {
            previouslog = *commitlog;
            for(i=0; i<logs->nviews; i++) {
                if(&(logs->firstchangelog) == logs->views[i].nextchangelogptr)
                    break;
            }
            if(i == logs->nviews) {
                for(i=0; i<logs->nviews; i++) {
                    if(logs->views[i].nextchangelogptr == &(previouslog->next))
                        logs->views[i].nextchangelogptr = &(logs->firstchangelog);
                }
                if(logs->lastchangelog == logs->firstchangelog)
                    logs->lastchangelog = logs->firstchangelog->next;
                logs->firstchangelog = logs->firstchangelog->next;
                *commitlog = NULL;
            } else {
                previouslog = NULL;
            }
        }
    }
    if(poppedlog == NULL && submitlog) {
        names_commitlogpersistincr(logs, *submitlog);
        if(logs->firstchangelog == NULL) {
            assert(logs->lastchangelog == NULL);
            logs->lastchangelog = logs->firstchangelog = *submitlog;
        } else {
            logs->lastchangelog->next = *submitlog;
            logs->lastchangelog = *submitlog;
        }
        *commitlog = *submitlog;
        *submitlog = names_tablecreate2(*submitlog);
    } else {
        *commitlog = poppedlog;
    }
    CHECK(pthread_mutex_unlock(&logs->lock));
    if(previouslog)
        names_commitlogdestroyfull(previouslog);
    return backlog;
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
    (*commitlogptr)->views[viewid].nextchangelogptr = &((*commitlogptr)->firstchangelog);
    (*commitlogptr)->views[viewid].view = view;
    CHECK(pthread_mutex_unlock(&(*commitlogptr)->lock));
    return viewid;
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
    for(changelog = *(commitlog->views[viewid].nextchangelogptr); changelog; changelog=changelog->next) {
        persistfn(changelog, store);
    }
    *oldstore = commitlog->store;
    commitlog->store = store;
    commitlog->storefn = persistfn;
    CHECK(pthread_mutex_unlock(&commitlog->lock));
    return 0;
}
