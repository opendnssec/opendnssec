#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ldns/ldns.h>
#include "uthash.h"
#include "signer/names.h"
#include "proto.h"

struct names_view_struct {
    names_view_type base;
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

static int
changed(names_view_type view, dictionary record, enum changetype type, dictionary** target)
{
    char* name;
    struct changelogrecord* change;
    struct changelogrecord** changeptr;
    name = getname(record, view->primarykey);
    changeptr = (struct changelogrecord**) names_tableput(view->changelog, name);
    if(*changeptr == NULL) {
        *changeptr = change = malloc(sizeof(struct changelogrecord));
        change->oldrecord = record;
        change->newrecord = record;
        switch(type) {
            case ADD:
                change->oldrecord = NULL;
                change->newrecord = record;
                if(target)
                    *target = NULL;
                break;
            case DEL:
                change->oldrecord = record;
                change->newrecord = NULL;
                if(target)
                    *target = NULL;
                break;
            case MOD:
                change->oldrecord = record;
                change->newrecord = record;
                if(target)
                    *target = &change->newrecord;
                break;
        }
        return 0;
    } else {
        change = *changeptr;
        if(change->oldrecord == change->newrecord) {
            if(target)
                *target = &change->newrecord;
            return 0;
        } else {
            if(target)
                *target = NULL;
            return 1;
        }
    }
}


void
names_own(names_view_type view, dictionary* record)
{
    dictionary* dict;
    changed(view, *record, MOD, &dict);
    if(dict && *record == *dict) {
        *dict = *record = copy(*record);
    }
}

void*
names_place(names_view_type view, char* name)
{
    dictionary content;
    content = names_indexlookup(view->indices[0], name);
    if(content == NULL) {
        content = create(&name);
        set(content,"name",name);
        names_indexinsert(view->indices[0], content);
        changed(view, content, ADD, NULL);
    }
    return content;
}

void*
names_take(names_view_type view, int index, char* name)
{
    dictionary found;
    found = names_indexlookup(view->indices[index], name);
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
    view->primarykey = keynames[0];
    view->changelog = names_tablecreate();
    view->nindices = nindices;
    for(i=0; i<nindices; i++) {
        names_indexcreate(&view->indices[i], keynames[i]);
    }
    if(base != NULL) {
        /* swapping next two loops might get better performance */
        for(iter=names_indexiterator(base->indices[0]); names_iterate(&iter, &content); names_advance(&iter, NULL)) {
            for(i=0; i<nindices; i++) {
                names_indexinsert(view->indices[i], content);
            }
        }
        view->views = base->views;
    } else {
        view->views = NULL;
    }
    view->viewid = names_changelogsubscribe(view, &view->views);
    return view;
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
    names_tabledispose(view->changelog);
    view->changelog = names_tablecreate();
}

static int
updateview(names_view_type view)
{
    int i, conflict = 0;
    names_iterator iter;
    struct changelogrecord* record;
    names_table_type changelog;

    while((changelog = names_changelogpop(view->views, view->viewid))) {
        for (iter = names_tableitems(changelog); names_iterate(&iter, &record); names_advance(&iter, NULL)) {
            /* TODO check for acceptable, if not continue */
            if (names_tableget(view->changelog, getname((record->oldrecord ? record->oldrecord : record->newrecord), view->primarykey))) {
                if (conflict == 0)
                    resetchangelog(view);
                conflict = 1;
            }
            if (record->oldrecord == record->newrecord) {
                /* TODO verify not modified in our changelog */
            } else {
                /* TODO verify not accessed in our changelog */
                if (record->oldrecord != NULL) {
                    for (i = 0; i < view->nindices; i++)
                        names_indexremove(view->indices[i], record->oldrecord);
                }
                if (record->newrecord != NULL) {
                    for (i = 0; i < view->nindices; i++)
                        names_indexinsert(view->indices[i], record->newrecord);
                }
            }
        }
        names_changelogrelease(view->views, changelog);
    }
    return conflict;
}

int
names_viewcommit(names_view_type view)
{
    int i, conflict;
    names_iterator iter;
    struct changelogrecord* record;
    names_table_type changelog;
    conflict = updateview(view);
    if(!conflict) {
        for(iter=names_tableitems(view->changelog); names_iterate(&iter, &record); names_advance(&iter, NULL)) {
            for(i=1; i<view->nindices; i++) {
                if(record->oldrecord != NULL)
                    names_indexremove(view->indices[i], record->oldrecord);
                if(record->newrecord != NULL)
                    names_indexinsert(view->indices[i], record->newrecord);
            }
        }
        changelog = view->changelog;
        view->changelog = names_tablecreate();
        names_changelogsubmit(view->views, view->viewid, changelog);
        return 0;
    } else {
        return 1;
    }
}

void
names_viewreset(names_view_type view)
{
    resetchangelog(view);
    updateview(view);
}

void
names_setup(void* baseviewptr, ldns_rdf* zonename)
{
    const char* baseviewkeys[] = {"nameserial", NULL};
    const char* inputviewkeys[] = {"name", NULL};
    const char* prepareviewkeys[] = {"name", NULL};
    const char* signviewkeys[] = {"name", "expire", "denialname", NULL};
    const char* outputviewkeys[] = {"nameserial", "validfrom", "replacedin", NULL};

    names_view_type baseview;
    names_view_type inputview;
    names_view_type prepareview;
    names_view_type signview;
    names_view_type outputview;
    baseview = names_viewcreate(NULL, baseviewkeys);
    inputview = names_viewcreate(baseview, inputviewkeys);
    prepareview = names_viewcreate(baseview, prepareviewkeys);
    signview = names_viewcreate(baseview, signviewkeys);
    outputview = names_viewcreate(baseview, outputviewkeys);

    (void)inputview;
    (void)prepareview;
    (void)signview;
    (void)outputview;
}

int
names_clear(void* source)
{
    assert(!"TODO NOT IMPLEMENTED");
}

/* TODO reimplement viewobtain chain as this structure does not belong here */
struct names_changelogchain {
    int nviews;
    struct {
        names_view_type view;
        names_table_type nextchangelog;
    } *views;
    names_table_type firstchangelog;
    names_table_type lastchangelog;
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

#ifdef NOTDEFINED
int
names_parentdomains(names_view_type view,domain_type* ,names_iterator*iter)
{
    assert(!"TODO NOT IMPLEMENTED");
}
#endif

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

int
names_dispose(names_view_type view)
{
    names_viewreset(view);
    return 0;
}

int
names_rollback(names_view_type view)
{
    names_viewreset(view);
    return 0;
}
