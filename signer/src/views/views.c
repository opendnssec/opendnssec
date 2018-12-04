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
#include <ldns/ldns.h>
#include "uthash.h"
#include "utilities.h"
#include "logging.h"
#include "proto.h"

#pragma GCC optimize ("O0")

const char* names_view_BASE[]    = { "base",    "namerevision", "outdated" };
const char* names_view_INPUT[]   = { "input",   "nameupcoming", "namehierarchy", NULL };
const char* names_view_PREPARE[] = { "prepare", "namerevision", "incomingset", "currentset", "relevantset", NULL };
const char* names_view_NEIGHB[]  = { "neighb",  "nameready", "denialname", NULL };
const char* names_view_SIGN[]    = { "sign",    "nameready", "expiry", "denialname", NULL };
const char* names_view_OUTPUT[]  = { "output",  "validnow", NULL };
const char* names_view_CHANGES[] = { "changes", "validchanges", "validinserts", "validdeletes", NULL };
const char* names_view_BACKUP[]  = { "backup",  "namerevision", "denialname", NULL };

logger_cls_type names_logcommitlog = LOGGER_INITIALIZE("commitlog");

struct searchfunc {
    names_index_type index;
    names_index_type index2;
    names_indexrange_func search;
};

struct names_view_struct {
    const char* viewname;
    names_view_type base;
    struct names_view_zone zonedata;
    names_table_type changelog;
    int viewid;
    names_commitlog_type commitlog;
    int nsearchfuncs;
    struct searchfunc* searchfuncs;
    int nindices;
    names_index_type indices[];
};

struct names_change_struct {
    recordset_type record;
    recordset_type oldrecord;
};
typedef struct names_change_struct* names_change_type;
enum changetype { ADD, DEL, MOD, UPD };

static void
changed(names_view_type view, recordset_type record, enum changetype type, recordset_type** target)
{
    const char* name;
    names_change_type change;
    names_change_type* changeptr;
    changeptr = (names_change_type*) names_tableput(view->changelog, record);
    if(target)
        *target = NULL;
    if(*changeptr == NULL) {
        change = malloc(sizeof(struct names_change_struct));
        *changeptr = change;
        switch(type) {
            case ADD:
                change->oldrecord = NULL;
                change->record = record;
                break;
            case DEL:
                change->oldrecord = record;
                change->record = NULL;
                break;
            case MOD:
                change->oldrecord = record;
                if(target) {
                    *target = &change->record;
                    change->record = NULL;
                } else
                    change->record = record;
                break;
            case UPD:
                change->oldrecord = record;
                if(target) {
                    *target = &change->record;
                    change->record = NULL;
                } else
                    change->record = record;
                break;
        }
    } else {
        change = *changeptr;
        switch(type) {
            case ADD:
                change->record = record;
                break;
            case DEL:
                change->record = NULL;
                break;
            case MOD:
                if(change->record != change->oldrecord) {
                    change->record = record;
                    if(target)
                        *target = &change->record;
                } else {
                    if(target) {
                        *target = &change->record;
                        change->record = NULL;
                    } else
                        change->record = record;
                }
                break;
            case UPD:
                if(target)
                    *target = &change->record;
                break;
        }
    }
}

void
names_underwrite(names_view_type view, recordset_type* record)
{
    recordset_type* dict;
    changed(view, *record, MOD, &dict);
    if(dict && *dict == NULL) {
        names_indexremove(view->indices[0], *record);
        *dict = names_recordcopy(*record, 1);
        names_indexinsert(view->indices[0], *dict, NULL);
    }
    *record = *dict;
}

void
names_overwrite(names_view_type view, recordset_type* record)
{
    recordset_type* dict;
    changed(view, *record, MOD, &dict);
    if(dict && *dict == NULL) {
        names_indexremove(view->indices[0], *record);
        *dict = names_recordcopy(*record, -1);
        names_indexinsert(view->indices[0], *dict, NULL);
    }
    *record = *dict;
}

void
names_update(names_view_type view, recordset_type* record)
{
    recordset_type* dict;
    changed(view, *record, UPD, &dict);
    if(dict && *dict == NULL) {
        names_indexremove(view->indices[0], *record);
        *dict = names_recordcopy(*record, 0);
        names_indexinsert(view->indices[0], *dict, NULL);
    }
    *record = *dict;
}

void
names_amend(names_view_type view, recordset_type record)
{
    changed(view, record, UPD, NULL);
}

void*
names_place(names_view_type view, const char* name)
{
    recordset_type content;
    char* newname;
    content = names_indexlookupkey(view->indices[0], name);
    if(content == NULL) {
        newname = (char*)name;
        content = names_recordcreate(&newname);
        names_recordannotate(content, &view->zonedata);
        names_indexinsert(view->indices[0], content, NULL);
        changed(view, content, ADD, NULL);
    }
    return content;
}

void*
names_take(names_view_type view, int index, const char* name)
{
    recordset_type found;
    if(name == NULL) {
        assert(view->zonedata.apex);
        name = view->zonedata.apex;
    }
    found = names_indexlookupkey(view->indices[index], name);
    return found;
}

void
names_remove(names_view_type view, recordset_type record)
{
    names_indexremove(view->indices[0], record);
    changed(view, record, DEL, NULL);
}

names_view_type
names_viewcreate(names_view_type base, const char* viewname, const char** keynames)
{
    names_view_type view;
    int i, nindices;
    names_iterator iter;
    recordset_type content;
    if(base && base->base) {
        base = base->base;
    }
    for(i=nindices=0; keynames[i]; i++)
        ++nindices;
    assert(nindices > 0);
    view = malloc(sizeof(struct names_view_struct)+sizeof(names_index_type)*(nindices));
    view->viewname = (viewname ? strdup(viewname) : NULL);
    view->base = base;
    view->zonedata.apex = (base ? base->zonedata.apex : NULL);
    view->zonedata.defaultttl = NULL;
    view->zonedata.signconf = (base ? base->zonedata.signconf : NULL);
    int (*comparfunc)(const void *, const void *);
    names_recordindexfunction(keynames[0], NULL, &comparfunc);
    view->changelog = names_tablecreate(comparfunc);
    view->nsearchfuncs = 0;
    view->searchfuncs = NULL;
    view->nindices = nindices;
    for(i=0; i<nindices; i++) {
        names_indexcreate(&view->indices[i], keynames[i]);
        names_indexsearchfunction(view->indices[i], view, keynames[i]);
    }
    // FIXME there should be better place to initialize these
    if(!strcmp(viewname,names_view_PREPARE[0])) {
        names_viewaddsearchfunction2(view, view->indices[1], view->indices[2], names_iteratorincoming);
    } else if(!strcmp(viewname,names_view_NEIGHB[0])) {
        names_viewaddsearchfunction2(view, view->indices[0], view->indices[1], names_iteratordenialchainupdates);
    } else if(!strcmp(viewname,names_view_SIGN[0])) {
        names_viewaddsearchfunction2(view, view->indices[0], view->indices[2], names_iteratordenialchainupdates);
    }
    if(base != NULL) {
        for(iter=names_indexiterator(base->indices[0]); names_iterate(&iter, &content); names_advance(&iter, NULL)) {
            names_indexinsert(view->indices[0], content, NULL);
        }
        for(iter=names_indexiterator(view->indices[0]); names_iterate(&iter, &content); names_advance(&iter, NULL)) {
            for(i=1; i<nindices; i++) {
                names_indexinsert(view->indices[i], content, NULL);
            }
        }
        view->commitlog = base->commitlog;
    } else {
        view->commitlog = NULL;
    }
    view->viewid = names_commitlogsubscribe(view, &view->commitlog);
    return view;
}

static void
disposedict(void* arg, void* key, void* val)
{
    recordset_type d = (recordset_type) val;
    (void)arg;
    (void)key;
    names_recorddispose(d);
}

void
names_viewdestroy(names_view_type view)
{
    int i;
    marshall_handle store = NULL;
    names_commitlogunsubscribe(view->viewid, view->commitlog);
    names_commitlogdestroy(view->changelog);
    for(i=1; i<view->nindices; i++) {
        names_indexdestroy(view->indices[i], NULL, NULL);
    }
    if(view->base == NULL || view->base == view) {
        names_commitlogdestroyall(view->commitlog, &store);
        names_indexdestroy(view->indices[0], disposedict, NULL);
    } else {
        names_indexdestroy(view->indices[0], NULL, NULL);
    }
    marshallclose(store);
    free((void*)view->viewname);
    if(view->zonedata.defaultttl)
        free((void*)view->zonedata.defaultttl);
    if(view->viewid == 0)
        free((void*)view->zonedata.apex);
    free(view->searchfuncs);
    free(view);
}

typedef int (*acceptfunction)(recordset_type newitem, recordset_type currentitem, int* cmp);
struct names_index_struct {
    const char* keyname;
    ldns_rbtree_t* tree;
    acceptfunction acceptfunc;
};

void
names_viewvalidate(names_view_type view)
{
    int fail = 0;
    int i;
    char* temp1 = NULL;
    char* temp2 = NULL;
    names_iterator iter;
    recordset_type record;
    recordset_type compare;
    for(i=1; i<view->nindices; i++) {
        for(iter=names_indexiterator(view->indices[i]); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
            compare = names_indexlookup(view->indices[0], record);
            if(compare == NULL) {
                fprintf(stderr,"RECORD IN INDEX %s NOT PRESENT IN MAIN INDEX: %s\n",*(char**)view->indices[i],names_recordgetsummary(record,&temp1));
                // names_dumprecord(stderr,record);
                fail = 1; // assert(compare != NULL);
            } else if(compare != record) {
                fprintf(stderr,"RECORD IN INDEX %s NOT SAME IN MAIN INDEX %s vs %s\n",*(char**)view->indices[i],names_recordgetsummary(record,&temp1),names_recordgetsummary(compare,&temp2));
                //names_dumprecord(stderr,record);
                //names_dumprecord(stderr,compare);
                fail = 1; // assert(compare == record);
            }
            if(view->indices[i]->acceptfunc(record,NULL,NULL) != 1) {
                fprintf(stderr,"RECORD IN INDEX %s SHOULD NOT BE IN INDEX %s\n",*(char**)view->indices[i],names_recordgetsummary(record,&temp1));
                //names_dumprecord(stderr,record);
                assert(view->indices[i]->acceptfunc(record,NULL,NULL) == 1);
            }
        }
    }
    names_recordgetsummary(NULL,&temp1);
    names_recordgetsummary(NULL,&temp2);
    if(fail) {
        names_dumpindex(stderr,view,0);
        abort();
    }
}

void
names_viewaddsearchfunction(names_view_type view, names_index_type index, names_indexrange_func searchfunc)
{
    view->nsearchfuncs += 1;
    view->searchfuncs = realloc(view->searchfuncs, sizeof(struct searchfunc) * view->nsearchfuncs);
    view->searchfuncs[view->nsearchfuncs-1].index = index;
    view->searchfuncs[view->nsearchfuncs-1].index2 = NULL;
    view->searchfuncs[view->nsearchfuncs-1].search = searchfunc;
}

void
names_viewaddsearchfunction2(names_view_type view, names_index_type primary, names_index_type secondary, names_indexrange_func searchfunc)
{
    view->nsearchfuncs += 1;
    view->searchfuncs = realloc(view->searchfuncs, sizeof(struct searchfunc) * view->nsearchfuncs);
    view->searchfuncs[view->nsearchfuncs-1].index = primary;
    view->searchfuncs[view->nsearchfuncs-1].index2 = secondary;
    view->searchfuncs[view->nsearchfuncs-1].search = searchfunc;
}

names_iterator
names_viewiterator(names_view_type view, names_indexrange_func func, ...)
{
    int i;
    va_list ap;
    names_iterator iter;
    if(func == NULL) {
        return names_indexiterator(view->indices[0]);
    } else {
        for(i=0; i<view->nsearchfuncs; i++) {
            if(view->searchfuncs[i].search == func) {
                va_start(ap, func);
                if(view->searchfuncs[i].index2 != NULL) {
                    iter = view->searchfuncs[i].search(view->searchfuncs[i].index, view->searchfuncs[i].index2, ap);
                } else {
                    iter = view->searchfuncs[i].search(view->searchfuncs[i].index, ap);
                }
                va_end(ap);
                return iter;
            }
        }
    }
    abort(); // FIXME?
    return NULL;
}

names_iterator
names_iteratorincoming(names_index_type primary, names_index_type secondary, va_list ap)
{
    struct dual entry;
    recordset_type record;
    names_iterator iter;
    names_iterator result;
    result = names_iterator_createdata(sizeof(struct dual));
    for (iter=names_indexiterator(primary); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
        entry.src = record;
        entry.dst = names_indexlookup(secondary, record);
        names_iterator_adddata(result,&entry);
    }
    return result;
}

names_iterator
names_iteratorexpiring(names_index_type index, va_list ap)
{
    recordset_type record;
    names_iterator iter;
    names_iterator result;
    time_t refreshtime;
    refreshtime = va_arg(ap,time_t);
    result = names_iterator_createrefs(NULL);
    for (iter=names_indexiterator(index); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
        if(names_recordhasexpiry(record) && names_recordgetexpiry(record) >= refreshtime) {
            names_end(&iter);
            break;
        } else {
            names_iterator_addptr(result, record);
        }
    }
    return result;
}

names_iterator
names_iteratordenialchainupdates(names_index_type primary, names_index_type secondary, va_list ap)
{
    struct dual entry;
    recordset_type record;
    names_iterator iter;
    names_iterator result;
    result = names_iterator_createdata(sizeof(struct dual));
    for (iter=names_indexiterator(primary); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
        if(names_recordgetdenial(record)) {
            entry.src = record;
            entry.dst = names_indexlookupnext(secondary, record);
            assert(entry.src);
            assert(entry.dst);
            names_iterator_adddata(result,&entry);
        }
    }
    return result;
}

static void
resetchangelog(names_view_type view)
{
    names_iterator iter;
    names_change_type change;
    names_table_type newchangelog;
    for(iter=names_tableitems(view->changelog); names_iterate(&iter, &change); names_advance(&iter, NULL)) {
        // FIXME we should assert(change->record != change->oldrecord); as we cannot handle updates like amends  but this assertion currently fails without known reason
        if(change->record != NULL) {
            names_indexremove(view->indices[0], change->record);
        }
        if(change->oldrecord != NULL) {
            names_indexinsert(view->indices[0], change->oldrecord, NULL);
        }
    }
    newchangelog = names_tablecreate2(view->changelog);
    names_commitlogdestroy(view->changelog);
    view->changelog = newchangelog;
}

static int
updateview(names_view_type view, names_table_type* mychangelog)
{
    int i, conflict = 0;
    names_iterator iter;
    names_change_type change;
    names_table_type changelog;
    char* temp1 = NULL;
    char* temp2 = NULL;
    int accepted;
    recordset_type existing;

    changelog = NULL;
    
    logger_message(&names_logcommitlog,logger_noctx,logger_DEBUG,"update view %s commit %p\n",view->viewname,(mychangelog?(void*)*mychangelog:NULL));
    while((names_commitlogpoppush(view->commitlog, view->viewid, &changelog, mychangelog))) {
        logger_message(&names_logcommitlog,logger_noctx,logger_DEBUG,"  process commit log %p into %s\n",(void*)changelog,view->viewname);
        for(iter = names_tableitems(changelog); names_iterate(&iter, &change); names_advance(&iter, NULL)) {
            if(names_tableget(view->changelog, change->record)) {
                if (conflict == 0) {
                    logger_message(&names_logcommitlog,logger_noctx,logger_DEBUG,"    conflict on %s %d\n",names_recordgetname(change->record),names_recordgetrevision(change->record));
                    resetchangelog(view);
                }
                conflict = 1;
                mychangelog = NULL;
            }
            existing = NULL;
            accepted = names_indexinsert(view->indices[0], change->record, &existing);
            logger_message(&names_logcommitlog,logger_noctx,logger_DEBUG,"    update %s %s%s%s\n",names_recordgetsummary(change->record,&temp1),(accepted?"accepted":"dropped"),(existing?" replaces ":""),names_recordgetsummary(existing,&temp2));
            for(i=1; i<view->nindices; i++) {
                recordset_type tmp = existing;
                names_indexinsert(view->indices[i], (accepted ? change->record : NULL), (existing ? &tmp : NULL));
            }
        }
    }
    if(!conflict && mychangelog) {
        logger_message(&names_logcommitlog,logger_noctx,logger_DEBUG,"  process submit commit log %p into %s\n",(void*)changelog,view->viewname);
        for(iter=names_tableitems(changelog); names_iterate(&iter, &change); names_advance(&iter, NULL)) {
            recordset_type existing = change->oldrecord;
            logger_message(&names_logcommitlog,logger_noctx,logger_DEBUG,"    update %s %s%s\n",names_recordgetsummary(change->record,&temp1),(existing?" replaces ":""),names_recordgetsummary(existing,&temp2));
            for(i=1; i<view->nindices; i++) {
                existing = change->oldrecord;
                names_indexinsert(view->indices[i], change->record, &existing);
            }
            if(change->record == NULL) {
                change->record = change->oldrecord;
                change->oldrecord = NULL;
                names_recorddisposal(change->record, 0);
            }
        }
        names_commitlogpoppush(view->commitlog, view->viewid, &changelog, mychangelog);
    }
    names_recordgetsummary(NULL,&temp1);
    names_recordgetsummary(NULL,&temp2);
    return conflict;
}

int
names_viewcommit(names_view_type view)
{
    int conflict;
    conflict = updateview(view, &view->changelog);
    assert(!conflict);
    return conflict;
}

void
names_viewreset(names_view_type view)
{
    resetchangelog(view);
    updateview(view, NULL);
}

static void
persistfn(names_table_type table, marshall_handle store)
{
    names_iterator iter;
    names_change_type change;
    for(iter=names_tableitems(table); names_iterate(&iter, &change); names_advance(&iter, NULL)) {
        if(change->record != change->oldrecord) /* ignore updates like amend */
            names_recordmarshall(&(change->record), store);
    }
    names_recordmarshall(NULL, store);
}

int
names_viewconfig(names_view_type view, signconf_type** signconf)
{
    view->zonedata.signconf = signconf;
    return 0;
}

static char filemagic[8] = "\0ODS-S1\n";

int
names_viewrestore(names_view_type view, const char* apex, int basefd, const char* filename)
{
    int fd;
    recordset_type record;
    marshall_handle input;
    marshall_handle output;
    char buffer[8];

    view->zonedata.apex = strdup(apex);

    if(filename != NULL) {
        if(basefd >= 0)
            fd = openat(basefd, filename, O_RDWR|O_LARGEFILE);
        else
            fd = open(filename, O_RDWR|O_LARGEFILE);
        if(fd >= 0) {
            read(fd,buffer,sizeof(buffer));
            assert(memcmp(buffer,filemagic,sizeof(filemagic))==0);
            input = marshallcreate(marshall_INPUT, fd);
            do {
                names_recordmarshall(&record, input);
                if(record) {
                    names_indexinsert(view->indices[0], record, NULL);
                }
            } while(record);
            output = marshallcreate(marshall_APPEND, input);
            marshallclose(input);
            names_commitlogpersistappend(view->commitlog, persistfn, output);
            return 0;
        } else {
            return 1;
        }
    } else {
        return 1;
    }
}

int
names_viewpersist(names_view_type view, int basefd, char* filename)
{
    char* tmpfilename = NULL;
    size_t tmpfilenamelen;
    int fd;
    marshall_handle marsh;
    marshall_handle oldmarsh;
    names_iterator iter;
    recordset_type record;

    tmpfilenamelen = snprintf(tmpfilename,0,"%s.tmp",filename);
    tmpfilename = malloc(tmpfilenamelen+1);
    tmpfilenamelen = snprintf(tmpfilename,tmpfilenamelen+1,"%s.tmp",filename);

    updateview(view, NULL);

    if(basefd >= 0)
        CHECK((fd = openat(basefd, tmpfilename, O_CREAT|O_WRONLY|O_LARGEFILE|O_TRUNC,0666)) < 0);
    else
        CHECK((fd = open(tmpfilename, O_CREAT|O_WRONLY|O_LARGEFILE|O_TRUNC,0666)) < 0);
    write(fd,filemagic,sizeof(filemagic));
    marsh = marshallcreate(marshall_OUTPUT, fd);

    iter = names_indexiterator(view->indices[0]);
    if(names_iterate(&iter, &record)) {
        do {
            names_recordmarshall(&record, marsh);
        } while(names_advance(&iter,&record));        
        names_recordmarshall(NULL, marsh);
    }
    names_end(&iter);
    names_commitlogpersistfull(view->commitlog, persistfn, view->viewid, marsh, &oldmarsh);

    marshallclose(oldmarsh);
    CHECK(renameat(basefd, tmpfilename, basefd, filename));

    free(tmpfilename);
    return 0;
}

int
names_viewgetdefaultttl(names_view_type view, int* defaultttl)
{
    if(view->zonedata.defaultttl) {
        *defaultttl = *view->zonedata.defaultttl;
        return 1;
    } else
        return 0;
}

int
names_viewgetapex(names_view_type view, ldns_rdf** apexptr)
{
    if(view->zonedata.apex) {
        *apexptr = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, view->zonedata.apex);
        return 1;
    } else
        return 0;
}

void
names_dumpviewfull(FILE* fp, names_view_type view)
{
    names_iterator iter;
    recordset_type record;
    marshall_handle marsh;
    marsh = marshallcreate(marshall_PRINT, fp);
    for(iter = names_viewiterator(view, NULL); names_iterate(&iter,&record); names_advance(&iter,NULL))
        names_recordmarshall(&record, marsh);
    marshallclose(marsh);
}


void
names_dumpviewinfo(FILE* fp, names_view_type view)
{
    int i, count;
    names_iterator iter;
    recordset_type record;
    uint32_t serial;
    ldns_rr_list* rrs;
    ldns_rr_list* rrs2;
    ldns_rr* rr;
        count = 0;
        rrs = ldns_rr_list_new();
        for(iter = names_viewiterator(view, NULL); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
            ++count;
            names_recordlookupall(record, LDNS_RR_TYPE_SOA, NULL, &rrs2, NULL);
            ldns_rr_list_push_rr_list(rrs,rrs2);
            ldns_rr_list_free(rrs2);
        }
        fprintf(stderr,"  %-10.10s :%7d   ",view->viewname,count);
        record = names_take(view, 0, NULL);
        if(record) {
            while((rr = ldns_rr_list_pop_rr(rrs))) {
                serial = ldns_rdf2native_int32(ldns_rr_rdf(rr, 2));
                fprintf(stderr," %d",(int)serial);
            }
            ldns_rr_list_free(rrs);
        }
        fprintf(stderr,"\n");
}


void
names__dumpindex(FILE* fp, names_index_type index)
{
    names_iterator iter;
    recordset_type record;
    marshall_handle marsh;
    char* temp = NULL;
    marsh = marshallcreate(marshall_PRINT, fp);
    for(iter = names_indexiterator(index); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
        printf("  %s\n",names_recordgetsummary(record,&temp));
        //names_recordmarshalsl(&record, marsh);
    }
    names_recordgetsummary(NULL,&temp);
    marshallclose(marsh);
}

void
names_dumpindex(FILE* fp, names_view_type view, int index)
{
    names__dumpindex(fp, view->indices[index]);
}

void
names_dumprecord(FILE* fp, recordset_type record)
{
    marshall_handle marsh;
    marsh = marshallcreate(marshall_PRINT, fp);
    names_recordmarshall(&record, marsh);
    marshallclose(marsh);
}


void
names_viewlookupall(names_view_type view, ldns_rdf* dname, ldns_rr_type type, ldns_rr_list** rrs, ldns_rr_list** rrsigs)
{
    recordset_type record;
    char* name;
    name = (dname ? ldns_rdf2str(dname) : NULL);
    record = names_take(view, 0, name);
    if(record) {
        names_recordlookupall(record, type, NULL, rrs, rrsigs);
    } else {
        *rrs = NULL;
        *rrsigs = NULL;
    }
    if(name)
        free(name);
}

void
names_viewlookupone(names_view_type view, ldns_rdf* dname, ldns_rr_type type, ldns_rr* template, ldns_rr** rr)
{
    recordset_type record;
    char* name;
    name = (dname ? ldns_rdf2str(dname) : NULL);
    record = names_take(view, 0, name);
    if(record) {
        names_recordlookupone(record, type, template, rr);
    } else {
        *rr = NULL;
    }
    if(name)
        free(name);
}
