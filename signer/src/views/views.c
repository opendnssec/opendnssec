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
#include "proto.h"

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
    name = names_recordgetid(record, NULL);
    changeptr = (names_change_type*) names_tableput(view->changelog, name);
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
                change->record = record;
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
                change->record = record;
                if(target)
                    *target = &change->record;
                break;
            case UPD:
                if(target)
                    *target = &change->record;
                break;
        }
    }
}

void
names_own(names_view_type view, recordset_type* record)
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
    if(name == NULL)
        name = view->zonedata.apex;
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
    for(i=nindices=0; keynames[i]; i++)
        ++nindices;
    assert(nindices > 0);
    view = malloc(sizeof(struct names_view_struct)+sizeof(names_index_type)*(nindices));
    view->viewname = (viewname ? strdup(viewname) : NULL);
    view->base = base;
    view->zonedata.apex = (base ? base->zonedata.apex : NULL);
    view->zonedata.defaultttl = NULL;
    view->zonedata.signconf = (base ? base->zonedata.signconf : NULL);
    view->changelog = names_tablecreate();
    view->nsearchfuncs = 0;
    view->searchfuncs = NULL;
    view->nindices = nindices;
    for(i=0; i<nindices; i++) {
        names_indexcreate(&view->indices[i], keynames[i]);
        names_indexsearchfunction(view->indices[i], view, keynames[i]);
    }
    if(!strcmp(viewname,"  input   ")) {
    } else if(!strcmp(viewname,"  prepare ")) {
        names_viewaddsearchfunction2(view, view->indices[1], view->indices[2], names_iteratorincoming);
    } else if(!strcmp(viewname,"  neighbr ")) {
        names_viewaddsearchfunction2(view, view->indices[0], view->indices[1], names_iteratordenialchainupdates);
    } else if(!strcmp(viewname,"  sign    ")) {
        names_viewaddsearchfunction2(view, view->indices[0], view->indices[2], names_iteratordenialchainupdates);
    } else if(!strcmp(viewname,"  output  ")) {
    }
    if(base != NULL) {
        /* swapping next two loops might get better performance */
        for(iter=names_indexiterator(base->indices[0]); names_iterate(&iter, &content); names_advance(&iter, NULL)) {
            recordset_type existing = NULL;
            if(names_indexinsert(view->indices[0], content, &existing)) {
                for(i=1; i<nindices; i++) {
                    names_indexinsert(view->indices[i], content, &existing);
                }
            }
        }
        view->commitlog = base->commitlog;
    } else {
        view->commitlog = NULL;
    }
    view->viewid = names_commitlogsubscribe(view, &view->commitlog);
    return view;
}

void
disposedict(void* arg, void* key, void* val)
{
    recordset_type d = (recordset_type) val;
    (void)arg;
    (void)key;
    names_recorddestroy(d);
}

void
names_viewdestroy(names_view_type view)
{
    int i;
    marshall_handle store = NULL;
    names_commitlogdestroy(view->changelog);
    for(i=1; i<view->nindices; i++) {
        names_indexdestroy(view->indices[i], NULL, NULL);
    }
    if(view->base == NULL) {
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
    free(view);
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
    result = names_iterator_createrefs();
    for (iter=names_indexiterator(index); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
        names_iterator_addptr(result, record);
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
        if(names_recordgetid(record,"denialname")) {
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
    for(iter=names_tableitems(view->changelog); names_iterate(&iter, &change); names_advance(&iter, NULL)) {
        assert(change->record != change->oldrecord); /* we cannot handle updates like amends */
        if(change->record != NULL) {
            names_indexremove(view->indices[0], change->record);
        }
        if(change->oldrecord != NULL) {
            names_indexinsert(view->indices[0], change->oldrecord, NULL);
        }
    }
    names_commitlogdestroy(view->changelog);
    view->changelog = names_tablecreate();
}

static int
updateview(names_view_type view, names_table_type* mychangelog)
{
    int i, conflict = 0;
    names_iterator iter;
    names_change_type change;
    names_table_type changelog;
    const char* name;

    changelog = NULL;
    while((names_commitlogpoppush(view->commitlog, view->viewid, &changelog, mychangelog))) {
        for(iter = names_tableitems(changelog); names_iterate(&iter, &change); names_advance(&iter, NULL)) {
            name = names_recordgetid(change->record, NULL);
            if(names_tableget(view->changelog, name)) {
                if (conflict == 0)
                    resetchangelog(view);
                conflict = 1;
                mychangelog = NULL;
            }
            if(change->record != NULL) {
                recordset_type existing = NULL;
                names_indexinsert(view->indices[0], change->record, &existing);
                for(i=1; i<view->nindices; i++)
                    names_indexinsert(view->indices[i], change->record, &existing);
            }
        }
    }
    if(!conflict && mychangelog) {
        for(iter=names_tableitems(changelog); names_iterate(&iter, &change); names_advance(&iter, NULL)) {
            recordset_type existing = change->oldrecord;
            for(i=1; i<view->nindices; i++) {
                if(change->record == NULL) {
                    change->record = change->oldrecord;
                    change->oldrecord = NULL;
                    names_recordsetmarker(change->record);
                }
                names_indexinsert(view->indices[i], change->record, &existing); // FIXME how does this one handle deletion
            }
        }
        names_commitlogpoppush(view->commitlog, view->viewid, &changelog, mychangelog);
    }
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

int
names_viewsync(names_view_type view)
{
    int i, conflict = 0;
    names_iterator iter;
    names_change_type change;
    names_table_type changelog;
    const char* name;

    changelog = NULL;
    while((names_commitlogpoppush(view->commitlog, view->viewid, &changelog, NULL))) {
        for(iter = names_tableitems(changelog); names_iterate(&iter, &change); names_advance(&iter, NULL)) {
            name = names_recordgetid(change->record, NULL);
            if(change->record != NULL) {
                recordset_type existing = NULL;
                names_indexinsert(view->indices[0], change->record, &existing);
                for(i=1; i<view->nindices; i++)
                    names_indexinsert(view->indices[i], change->record, &existing);
            }
        }
    }
    return conflict;
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

int
names_viewrestore(names_view_type view, const char* apex, int basefd, const char* filename)
{
    int fd;
    recordset_type record;
    marshall_handle input;
    marshall_handle output;

    view->zonedata.apex = strdup(apex);

    if(filename != NULL) {
        if(basefd >= 0)
            fd = openat(basefd, filename, O_RDWR|O_LARGEFILE);
        else
            fd = open(filename, O_RDWR|O_LARGEFILE);
        if(fd >= 0) {
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
        return 0;
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

    CHECK((fd = openat(basefd, tmpfilename, O_CREAT|O_WRONLY|O_LARGEFILE|O_TRUNC,0666)) < 0);
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
        *defaultttl = view->zonedata.defaultttl;
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
