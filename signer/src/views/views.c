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
#include <ldns/ldns.h>
#include "uthash.h"
#include "utilities.h"
#include "proto.h"

struct names_view_struct {
    const char* viewname;
    names_view_type base;
    const char* apex;
    const char* apexrr;
    int defaultttl;
    names_table_type changelog;
    int viewid;
    names_commitlog_type commitlog;
    int nindices;
    names_index_type indices[];
};

struct names_change_struct {
    dictionary record;
    dictionary oldrecord;
};
typedef struct names_change_struct* names_change_type;
enum changetype { ADD, DEL, MOD };

static void
changed(names_view_type view, dictionary record, enum changetype type, dictionary** target)
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
                change->record = NULL;
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
        }
    }
}

void
names_own(names_view_type view, dictionary* record)
{
    dictionary* dict;
    changed(view, *record, MOD, &dict);
    if(dict && *dict == NULL) {
        names_indexremove(view->indices[0], *record);
        *dict = names_recordcopy(*record);
        names_indexinsert(view->indices[0], *dict);
    }
    *record = *dict;
}

void
names_amend(names_view_type view, dictionary record)
{
    changed(view, record, MOD, NULL);
}

void*
names_place(names_view_type view, const char* name)
{
    dictionary content;
    char* newname;
    content = names_indexlookupkey(view->indices[0], name);
    if(content == NULL) {
        newname = (char*)name;
        content = names_recordcreate(&newname);
        annotate(content, (view->apex ? strdup(view->apex) : NULL));
        names_indexinsert(view->indices[0], content);
        changed(view, content, ADD, NULL);
    }
    return content;
}

void*
names_take(names_view_type view, int index, const char* name)
{
    dictionary found;
    found = names_indexlookupkey(view->indices[index], name);
    return found;
}

void
names_remove(names_view_type view, dictionary record)
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
    dictionary content;
    for(i=nindices=0; keynames[i]; i++)
        ++nindices;
    assert(nindices > 0);
    view = malloc(sizeof(struct names_view_struct)+sizeof(names_index_type)*(nindices));
    view->viewname = (viewname ? strdup(viewname) : NULL);
    view->base = base;
    view->apex = (base ? base->apex : NULL);
    view->changelog = names_tablecreate();
    view->nindices = nindices;
    for(i=0; i<nindices; i++) {
        names_indexcreate(&view->indices[i], keynames[i]);
    }
    if(base != NULL) {
        /* swapping next two loops might get better performance */
        for(iter=names_indexiterator(base->indices[0]); names_iterate(&iter, &content); names_advance(&iter, NULL)) {
            if(names_indexinsert(view->indices[0], content)) {
                for(i=1; i<nindices; i++) {
                    names_indexinsert(view->indices[i], content);
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
    dictionary d = (dictionary) val;
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
    if(view->viewid == 0)
        free((void*)view->apex);
    free(view);
}

names_iterator
names_viewiterator(names_view_type view, int index)
{
    return names_indexiterator(view->indices[index]);
}

int
ancestors(names_view_type view, char* name)
{
    ldns_rdf* apex;
    ldns_rdf* dname;
    ldns_rdf* parent;
    dictionary dict;

    apex = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, view->apex);
    dname = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, name);
    
    while(dict && ldns_dname_is_subdomain(dname, apex)) {
        parent = ldns_dname_left_chop(dname);
        if (parent) {
            dict = names_take(view, 0, parent);
            ldns_rdf_deep_free(parent);
        }
    }
    return 0;
}

names_iterator
names_viewiterate(names_view_type view, const char* selector, ...)
{
    va_list ap;
    char* name;
    names_iterator iter;
    va_start(ap, selector);
    if(!strcmp(selector, "allbelow")) {
        name = va_arg(ap, char*);
        iter = names_indexrange(view->indices[1], selector, name);
    } else {
        abort(); // FIXME
    }
    va_end(ap);
    return iter;
}

static void
resetchangelog(names_view_type view)
{
    names_iterator iter;
    names_change_type change;
    for(iter=names_tableitems(view->changelog); names_iterate(&iter, &change); names_advance(&iter, NULL)) {
        if(change->record != NULL) {
            names_indexremove(view->indices[0], change->record);
        }
        if(change->oldrecord != NULL) {
            names_indexinsert(view->indices[0], change->oldrecord);
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
                names_indexinsert(view->indices[0], change->record);
                for(i=1; i<view->nindices; i++)
                    names_indexinsert(view->indices[i], change->record);
            }
        }
    }
    if(!conflict && mychangelog) {
        for(iter=names_tableitems(changelog); names_iterate(&iter, &change); names_advance(&iter, NULL)) {
            for(i=0; i<view->nindices; i++) {
                if(change->record == NULL) {
                    change->record = change->oldrecord;
                    change->oldrecord = NULL;
                    names_recordsetmarker(change->record);
                }
                names_indexinsert(view->indices[i], change->record);
            }
        }
        names_commitlogpoppush(view->commitlog, view->viewid, &changelog, mychangelog);
    }
    return conflict;
}

int
names_viewcommit(names_view_type view)
{
    return updateview(view, &view->changelog);
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
        names_recordmarshall(&(change->record), store);
    }
    names_recordmarshall(NULL, store);
}

int
names_viewrestore(names_view_type view, const char* apex, int basefd, const char* filename)
{
    int fd;
    dictionary record;
    marshall_handle input;
    marshall_handle output;

    view->apex = strdup(apex);

    if(basefd >= 0)
        fd = openat(basefd, filename, O_RDWR|O_LARGEFILE);
    else
        fd = open(filename, O_RDWR|O_LARGEFILE);
    if(fd >= 0) {
        input = marshallcreate(marshall_INPUT, fd);
        do {
            names_recordmarshall(&record, input);
            if(record) {
                names_indexinsert(view->indices[0], record);
            }
        } while(record);
        output = marshallcreate(marshall_APPEND, input);
        marshallclose(input);
        names_commitlogpersistappend(view->commitlog, persistfn, output);
        return 0;
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
    dictionary record;

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
names_viewgetdefaultttl(names_view_type view)
{
    return view->defaultttl;
}

ldns_rr*
names_viewgetapex(names_view_type view)
{
    return view->apexrr;
}

void
names_dumpviewinfo(names_view_type view)
{
    names_iterator iter;
    int i, count;
    fprintf(stderr,"%s",view->viewname);
    for(i=0; i<view->nindices; i++) {
        count = 0;
        for(iter = names_viewiterator(view, count); names_iterate(&iter,NULL); names_advance(&iter,NULL))
            ++count;
        fprintf(stderr," %s=%d",*(char**)(view->indices[i]),count);
    }
    fprintf(stderr,"\n");
}

void
names_dumpviewfull(FILE* fp, names_view_type view)
{
    names_iterator iter;
    dictionary record;
    marshall_handle marsh;
    marsh = marshallcreate(marshall_PRINT, fp);
    for(iter = names_viewiterator(view, 0); names_iterate(&iter,&record); names_advance(&iter,NULL))
        names_recordmarshall(&record, marsh);
    marshallclose(marsh);
}

void
names_dumprecord(FILE* fp, dictionary record)
{
    marshall_handle marsh;
    marsh = marshallcreate(marshall_PRINT, fp);
    names_recordmarshall(&record, marsh);
    marshallclose(marsh);
}

names_iterator
noexpiry(names_view_type view)
{
    struct dual entry;
    dictionary record;
    names_iterator iter;
    names_iterator result;
    result = names_iterator_create(sizeof(struct dual));
    for (iter=names_indexiterator(view->indices[1]); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
        entry.dst = record;
        entry.src = names_indexlookup(view->indices[2], record);
        names_iterator_add(result,&entry);
    }
    return result;
}


names_iterator
neighbors(names_view_type view)
{
    struct dual entry;
    dictionary record;
    names_iterator iter;
    names_iterator result;
    result = names_iterator_create(sizeof(struct dual));
    for (iter=names_indexiterator(view->indices[1]); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
        entry.dst = record;
        entry.src = names_indexlookup(view->indices[2], record);
        names_iterator_add(result,&entry);
    }
    return result;
}

names_iterator
expiring(names_view_type view)
{
    dictionary record;
    names_iterator iter;
    names_iterator result;
    result = names_iterator_create(0);
    for (iter=names_indexiterator(view->indices[0]); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
        names_iterator_add(result, record);
    }
    return result;
}
