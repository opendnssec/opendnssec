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
#include "signer/names.h"
#include "proto.h"

struct names_view_struct {
    names_view_type base;
    const char* apex;
    const char* primarykey;
    names_table_type changelog;
    int viewid;
    struct names_changelogchain* views;
    int nindices;
    names_index_type indices[];
};

struct changelogrecord {
    dictionary oldrecord;
    dictionary newrecord;
};
enum changetype { ADD, DEL, MOD };

static void
changed(names_view_type view, dictionary record, enum changetype type, dictionary** target)
{
    int status;
    const char* name;
    struct changelogrecord* change;
    struct changelogrecord** changeptr;
    status = getset(record, view->primarykey, &name, NULL);
    assert(status);
    changeptr = (struct changelogrecord**) names_tableput(view->changelog, name);
    if(target)
        *target = NULL;
    if(*changeptr == NULL) {
        change = malloc(sizeof(struct changelogrecord));
        *changeptr = change;
        switch(type) {
            case ADD:
                change->oldrecord = NULL;
                change->newrecord = NULL;
                break;
            case DEL:
                change->oldrecord = record;
                change->newrecord = NULL;
                break;
            case MOD:
                change->oldrecord = record;
                if(target) {
                    *target = &change->newrecord;
                    change->newrecord = NULL;
                } else
                    change->newrecord = record;
                break;
        }
    } else {
        change = *changeptr;
        switch(type) {
            case ADD:
                change->newrecord = record;
                break;
            case DEL:
                change->newrecord = NULL;
                break;
            case MOD:
                change->newrecord = record;
                if(target)
                    *target = &change->newrecord;
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
        *dict = copy(*record);
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
names_place(names_view_type view, char* name)
{
    dictionary content;
    content = names_indexlookupkey(view->indices[0], name);
    if(content == NULL) {
        content = create(&name);
        annotate(content, (view->apex ? strdup(view->apex) : NULL));
        names_indexinsert(view->indices[0], content);
        changed(view, content, ADD, NULL);
    }
    return content;
}

void*
names_take(names_view_type view, int index, char* name)
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
names_viewcreate(names_view_type base, const char** keynames)
{
    names_view_type view;
    int i, nindices;
    names_iterator iter;
    dictionary content;
    for(i=nindices=0; keynames[i]; i++)
        ++nindices;
    assert(nindices > 0);
    view = malloc(sizeof(struct names_view_struct)+sizeof(names_index_type)*(nindices));
    view->base = base;
    view->apex = (base ? base->apex : NULL);
    view->primarykey = "namerevision"; // FIXME keynames[0];
    view->changelog = names_tablecreate();
    view->nindices = nindices;
    for(i=0; i<nindices; i++) {
        names_indexcreate(&view->indices[i], keynames[i]);
    }
    if(base != NULL) {
        /* swapping next two loops might gest better performance */
        for(iter=names_indexiterator(base->indices[0]); names_iterate(&iter, &content); names_advance(&iter, NULL)) {
            if(names_indexinsert(view->indices[0], content)) {
                for(i=1; i<nindices; i++) {
                    names_indexinsert(view->indices[i], content);
                }
            }
        }
        view->views = base->views;
    } else {
        view->views = NULL;
    }
    view->viewid = names_changelogsubscribe(view, &view->views);
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
    names_changelogdestroy(view->changelog);
    for(i=1; i<view->nindices; i++) {
        names_indexdestroy(view->indices[i], NULL, NULL);
    }
    if(view->base == NULL) {
        names_changelogdestroyall(view->views, &store);
        names_indexdestroy(view->indices[0], disposedict, NULL);
    } else {
        names_indexdestroy(view->indices[0], NULL, NULL);
    }
    marshallclose(store);
    // FIXME close store->fd
    if(view->viewid == 0)
        free((void*)view->apex);
    free(view);
}

names_iterator
names_viewiterator(names_view_type view, int index)
{
    return names_indexiterator(view->indices[index]);
}

static void
resetchangelog(names_view_type view)
{
    names_iterator iter;
    struct changelogrecord* record;
    for(iter=names_tableitems(view->changelog); names_iterate(&iter, &record); names_advance(&iter, NULL)) {
        if(record->newrecord != NULL) {
            names_indexremove(view->indices[0], record->newrecord);
        }
        if(record->oldrecord != NULL) {
            names_indexinsert(view->indices[0], record->oldrecord);
        }
    }
    names_changelogdestroy(view->changelog);
    view->changelog = names_tablecreate();
}

static int
updateview(names_view_type view, names_table_type* mychangelog)
{
    int i, conflict = 0;
    names_iterator iter;
    struct changelogrecord* record;
    names_table_type changelog;
    const char* name;

    while((changelog = names_changelogpoppush(view->views, view->viewid, mychangelog))) {
        if (changelog) {
            for (iter=names_tableitems(changelog); names_iterate(&iter,&record); names_advance(&iter, NULL)) {
                if(record->newrecord && !names_indexaccept(view->indices[0], record->newrecord))
                    continue;
                if (record->oldrecord != record->newrecord) {
                    if(record->oldrecord)
                        getset(record->oldrecord, view->primarykey, &name, NULL);
                    else
                        getset(record->newrecord, view->primarykey, &name, NULL);
                    if (names_tableget(view->changelog, name)) {
                        if (conflict == 0)
                            resetchangelog(view);
                        conflict = 1;
                    }
                    if (record->oldrecord != NULL) {
                        /* FIXME EXPERIMENT */
                        if(record->newrecord != NULL) {
                            for(i=0; i<view->nindices; i++)
                                names_indexremove(view->indices[i], record->newrecord);
                        } else {
                            for(i=0; i<view->nindices; i++)
                                names_indexremove(view->indices[i], record->oldrecord);
                        }
                    }
                    if (record->newrecord != NULL) {
                        if(names_indexinsert(view->indices[0], record->newrecord))
                            for(i=1; i<view->nindices; i++)
                                if(names_indexaccept(view->indices[i], record->newrecord))
                                    names_indexinsert(view->indices[i], record->newrecord);
                    }
                }
            }
            names_changelogrelease(view->views, changelog);
        }
    }
    return conflict;
}

int
names_viewcommit(names_view_type view)
{
    int i, conflict;
    names_iterator iter;
    struct changelogrecord* record;
    conflict = updateview(view, &view->changelog);
    if(!conflict) {
        for(iter=names_tableitems(view->changelog); names_iterate(&iter, &record); names_advance(&iter, NULL)) {
            for(i=1; i<view->nindices; i++) {
                if(record->oldrecord != NULL)
                    names_indexremove(view->indices[i], record->oldrecord);
                if(record->newrecord != NULL)
                    names_indexinsert(view->indices[i], record->newrecord);
            }
        }
        return 0;
    } else {
        return 1;
    }
}

void
names_viewreset(names_view_type view)
{
    resetchangelog(view);
    updateview(view, NULL);
}

int
names_viewrestore(names_view_type view, const char* apex, int basefd, char* filename)
{
    int count = 1;
    int fd;
    dictionary record;
    marshall_handle marsh;

    view->apex = strdup(apex);
    
    fd = openat(basefd, filename, O_RDWR|O_LARGEFILE);
    if(fd >= 0) {
        marsh = marshallinput(fd);
        do {
            marshalling(marsh, "domain", &record, &count, 128/*FIXME*/, names_recordmarshall);
            if(record) {
                names_indexinsert(view->indices[0], record);
            }
        } while(record);
        marshallclose(marsh);
        marsh = marshalloutput(fd);
        names_changelogpersistsetup(view->views, marsh);
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
    names_iterator iter;
    marshall_handle marsh;
    marshall_handle oldmarsh;

    tmpfilenamelen = snprintf(tmpfilename,0,"%s.tmp",filename);
    tmpfilename = malloc(tmpfilenamelen+1);
    tmpfilenamelen = snprintf(tmpfilename,tmpfilenamelen+1,"%s.tmp",filename);

    updateview(view, NULL);

    CHECK((fd = openat(basefd, tmpfilename, O_CREAT|O_WRONLY|O_LARGEFILE|O_TRUNC,0666)) < 0);
    marsh = marshalloutput(fd);
    iter = names_indexiterator(view->indices[0]);
    names_changelogpersistfull(view->views, &iter, view->viewid, marsh, &oldmarsh);
    marshallclose(oldmarsh);
    CHECK(renameat(basefd, tmpfilename, basefd, filename));
    names_end(&iter);

    free(tmpfilename);
    return 0;
}

void
names_dumpviewinfo(names_view_type view, char* preamble)
{
    names_iterator iter;
    int i, count;
    fprintf(stderr,"%s",preamble);
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
    marsh = marshallprint(fp);
    for(iter = names_viewiterator(view, 0); names_iterate(&iter,&record); names_advance(&iter,NULL))
        marshalling(marsh, "domain", record, NULL, 0, names_recordmarshall);
    marshallclose(marsh);
}

void
names_dumprecord(FILE* fp, dictionary record)
{
    marshall_handle marsh;
    marsh = marshallprint(fp);
    marshalling(marsh, "domain", record, NULL, 0, names_recordmarshall);
    marshallclose(marsh);
}

names_iterator
noexpiry(names_view_type view)
{
    struct dual entry;
    dictionary record;
    names_iterator iter;
    names_iterator result;
    result = generic_iterator(sizeof(struct dual));
    for (iter=names_indexiterator(view->indices[1]); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
        entry.dst = record;
        entry.src = names_indexlookup(view->indices[2], record);
        generic_add(result,&entry);
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
    result = generic_iterator(sizeof(struct dual));
    for (iter=names_indexiterator(view->indices[1]); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
        entry.dst = record;
        entry.src = names_indexlookup(view->indices[2], record);
        generic_add(result,&entry);
    }
    return result;
}

names_iterator
expiring(names_view_type view)
{
    names_iterator iter;
    iter = generic_iterator(sizeof (struct dual));
    // FIXME
    return iter;
}
int
names_firstdenials(names_view_type view,names_iterator*iter)
{
    assert(!"TODO NOT IMPLEMENTED");
}

int
names_reversedenials(names_view_type view,names_iterator*iter)
{
    assert(!"TODO NOT IMPLEMENTED");
}

int
names_alldomains(names_view_type view, names_iterator*iter)
{
    assert(!"TODO NOT IMPLEMENTED");
}

void
names_delete(names_iterator* iter)
{
    assert(!"TODO NOT IMPLEMENTED");
}

domain_type*
names_lookupname(names_view_type view, ldns_rdf* name)
{
    assert(!"TODO NOT IMPLEMENTED");
}

domain_type*
names_lookupapex(names_view_type view)
{
    assert(!"TODO NOT IMPLEMENTED");
}

uint32_t
names_getserial(names_view_type view)
{
    assert(!"TODO NOT IMPLEMENTED");
}

void
names_setserial(names_view_type view, uint32_t serial)
{
    assert(!"TODO NOT IMPLEMENTED");
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

int
names_viewobtain(void* ptr, enum names_viewtypes_enum which, names_view_type* view)
{
    names_view_type baseview = (names_view_type) ptr;
    switch(which) {
        case names_BASEVIEW:
            *view = baseview->views->views[0].view;
            break;
        case names_INPUTVIEW:
            *view = baseview->views->views[1].view;
            break;
        case names_SIGNVIEW:
            *view = baseview->views->views[3].view;
            break;
        case names_AXFROUTVIEW:
            *view = baseview->views->views[4].view;
            break;
    }
    return 0;
}
