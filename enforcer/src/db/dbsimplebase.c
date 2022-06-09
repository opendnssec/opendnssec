/*
 * Copyright (c) 2021 A.W. van Halderen
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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "utilities.h"
#include "tree.h"
#include "dbsimple.h"
#include "dbsimplebase.h"

struct backpatch {
    struct object* source;
    struct dbsimple_fieldimpl* field;
    struct backpatch* next;
};

static int
pointermapcompare(const void* a, const void* b, __attribute__((unused)) void* user)
{
    struct object* o1 = (struct object*) a;
    struct object* o2 = (struct object*) b;
    return o1->data - o2->data;
}

static int
objectmapcompare(const void* a, const void* b, __attribute__((unused)) void* user)
{
    int result;
    struct object* o1 = (struct object*) a;
    struct object* o2 = (struct object*) b;
    result = (o1->type ? *(o1->type) : NULL) - (o2->type ? *(o2->type) : NULL);
    if(result == 0) {
        if(o1->keyname) {
            if(o2->keyname)
                result = strcmp(o1->keyname, o2->keyname);
            else
                result = -1;
        } else if(o2->keyname)
            result = 1;
        else
            result = o1->keyid - o2->keyid;
    }
    return result;
}

static int
deleteobject(struct object* object, __attribute__((unused)) dbsimple_session_type session)
{
    void*** refarray;
    struct dbsimple_definitionimpl* def = *(object->type);
    if(object->data) {
        for(int i=0; i<def->nfields; i++) {
            switch (def->fields[i].type) {
                case dbsimple_INT:
                case dbsimple_UINT:
                case dbsimple_LONGINT:
                case dbsimple_ULONGINT:
                    break;
                case dbsimple_STRING:
                    free(*(char**)&(object->data[def->fields[i].fieldoffset]));
                    break;
                case dbsimple_REFERENCE:
                case dbsimple_STUBREFERENCES:
                case dbsimple_BACKREFERENCE:
                    break;
                case dbsimple_OPENREFERENCES:
                case dbsimple_MASTERREFERENCES:
                    refarray = (void***) &(object->data[def->fields[i].fieldoffset]);
                    free(*refarray);
                    break;
                default:
                    abort();
            }
        }
        free(object->data);
        free(object);
    }
    return 0; /* continue */
}

struct object*
dbsimple__referencebyptr(struct dbsimple_sessionbase* session, struct dbsimple_definitionimpl** def, void* ptr)
{
    struct object lookup;
    struct object* object;
    lookup.data = ptr;
    object = tree_lookup(session->pointermap, &lookup);
    if(object == NULL) {
        object = malloc(sizeof (struct object));
        object->type = def;
        object->data = ptr;
        object->state = OBJNEW;
        object->keyname = NULL;
        object->keyid = 0;
        object->revision = 0;
        object->next = NULL;
        object->backpatches = NULL;
        tree_insert(session->pointermap, object);
    }
    return object;
}

void
dbsimple__committraverse(struct dbsimple_sessionbase* session, struct object* object)
{
    void* targetptr;
    struct object* targetobj;
    int* refarraycount;
    void*** refarray;
    struct dbsimple_definitionimpl* def = *(object->type);
    if(object->next != NULL)
        return;
    switch(object->state) {
        case OBJUNKNOWN:
        case OBJNULL:
            return;
        case OBJNEW:
        case OBJMODIFIED:
        case OBJREMOVED:
            object->next = (session->firstmodified ? session->firstmodified : object);
            session->firstmodified = object;
            break;
        case OBJCLEAN:
            object->next = object;
            break;
    }
    for(int i=0; i<def->nfields; i++) {
        switch(def->fields[i].type) {
            case dbsimple_INT:
            case dbsimple_UINT:
            case dbsimple_LONGINT:
            case dbsimple_ULONGINT:
            case dbsimple_STRING:
                break;
            case dbsimple_REFERENCE:
                targetptr = *(void**)&(object->data[def->fields[i].fieldoffset]);
                if(targetptr) {
                    targetobj = dbsimple__referencebyptr(session, def->fields[i].def, targetptr);
                    if(targetobj->type == NULL)
                        targetobj->type = def->fields[i].def;
                    dbsimple__committraverse(session, targetobj);
                }
                break;
            case dbsimple_BACKREFERENCE:
            case dbsimple_STUBREFERENCES:
                break;
            case dbsimple_MASTERREFERENCES:
                assert(def->fields[i].countoffset >= 0);
                assert(def->fields[i].fieldoffset >= 0);
                refarraycount = (int*)&(object->data[def->fields[i].countoffset]);
                refarray = (void***)&(object->data[def->fields[i].fieldoffset]);
                for(int j=0; j<*refarraycount; j++) {
                    targetptr = (*refarray)[j];
                    if(targetptr) {
                        targetobj = dbsimple__referencebyptr(session, def->fields[i].def, targetptr);
                        if(targetobj->type == NULL)
                            targetobj->type = def->fields[i].def;
                        dbsimple__committraverse(session, targetobj);
                    }
                }
                break;
            case dbsimple_OPENREFERENCES:
                break;
            default:
                abort();
        }
    }
}

struct object*
dbsimple__getobject(struct dbsimple_sessionbase* session, enum objectstate state, struct dbsimple_definitionimpl** def, long id, const char* name)
{
    tree_reference_type cursor;
    struct object lookup;
    struct object* object;
    struct object* ptr;
    lookup.type = def;
    lookup.keyid = id;
    lookup.keyname = name;
    object = tree_lookupref(session->objectmap, &lookup, &cursor);
    if (object == NULL) {
        if(state != OBJNULL) {
            object = malloc(sizeof (struct object));
            object->state = state;
            object->type = def;
            if(state != OBJUNKNOWN) {
                object->data = calloc(1, (*def)->size);
            } else {
                object->data = NULL;
            }
            object->keyid = id;
            object->keyname = name;
            object->revision = -1;
            object->next = NULL;
            object->backpatches = NULL;
            ptr = tree_insertref(session->objectmap, object, &cursor);
            assert(!ptr);
            tree_insert(session->pointermap, object);
        }
    } else if(object->data == NULL && state != OBJUNKNOWN) {
        object->data = calloc(1, (*def)->size);
        object->state = state;
        tree_insert(session->pointermap, object);
    }
    return object;
}

static void
subscribereference(struct dbsimple_fieldimpl* field, struct object* source, struct object* subject)
{
    struct backpatch* patch = malloc(sizeof(struct backpatch));
    patch->source = source;
    patch->field = field;
    patch->next = subject->backpatches;
    subject->backpatches = patch;
}

void
dbsimple__assignreference(struct dbsimple_sessionbase* session, struct dbsimple_fieldimpl* field, long id, const char* name, struct object* source)
{
    struct object* targetoject;
    void** destination = (void**)&(source->data[field->fieldoffset]);
    targetoject = dbsimple__getobject(session, OBJUNKNOWN, field->def, id, name);
    if(targetoject->data) {
        *destination = targetoject->data;
    } else {
        subscribereference(field, source, targetoject);
    }
}

void
dbsimple__assignbackreference(struct dbsimple_sessionbase* session, struct dbsimple_definitionimpl** def, int id, const char* name, struct dbsimple_fieldimpl* field, struct object* object)
{
    struct object* targetobject;
    char* target;
    int* refarraycount;
    void*** refarray;
    targetobject = dbsimple__getobject(session, OBJUNKNOWN, def, id, name);
    target = targetobject->data;
    if(target) {
        refarraycount = (int*)&(target[field->countoffset]);
        refarray = (void***)&(target[field->fieldoffset]);
        *refarray = realloc(*refarray, sizeof (void*) * (1+ *refarraycount));
        (*refarray)[*refarraycount] = object->data;
        *refarraycount += 1;
    } else {
        subscribereference(field, object, targetobject);
    }
}

static int
resolvebackpatches(struct object* object, __attribute__((unused)) void* user)
{
    char* target;
    int* refarraycount;
    void*** refarray;
    while(object->backpatches) {
        struct backpatch* patch = object->backpatches;
        switch(patch->field->type) {
            case dbsimple_REFERENCE:
                target = patch->source->data;
                *(void**)&(target[patch->field->fieldoffset]) = object->data;
                break;
            case dbsimple_BACKREFERENCE:
                target = object->data;
                if(target) {
                    refarraycount = (int*)&(target[patch->field->countoffset]);
                    refarray = (void***)&(target[patch->field->fieldoffset]);
                    *refarray = realloc(*refarray, sizeof (void*) * (1+ *refarraycount));
                    (*refarray)[*refarraycount] = patch->source->data;
                    *refarraycount += 1;
                }
                break;
            default:
                break;
        }
        object->backpatches = patch->next;
        free(patch);
    }
    return 0; // continue foreach items
}

static int
commitobject(struct object* object, struct dbsimple_sessionbase* session)
{
    struct dbsimple_definitionimpl* def = *(object->type);
    if((def->flags & dbsimple_FLAG_SINGLETON) == dbsimple_FLAG_SINGLETON)
        return 0;

    if(object->next == NULL) {
        /* this object isn't reachable */
        switch(object->state) {
            case OBJMODIFIED:
                if((def->flags & dbsimple_FLAG_EXPLICITREMOVE) != dbsimple_FLAG_EXPLICITREMOVE)
                    object->state = OBJREMOVED;
                break;
            case OBJCLEAN:
                if(def->flags & dbsimple_FLAG_AUTOREMOVE)
                    object->state = OBJREMOVED;
                break;
            case OBJREMOVED:
                break;
            case OBJUNKNOWN:
            default:
                // Object was transient
                break;
        }
    }
    return session->module->persistobject(object, (dbsimple_session_type)session);
}

void
dbsimple__commit(struct dbsimple_sessionbase* session)
{
    tree_foreach(session->pointermap, (tree_visitor_type) commitobject, (void*) session);
    tree_foreach(session->objectmap, (tree_visitor_type) deleteobject, (void*) session);
    tree_destroy(session->objectmap);
    tree_destroy(session->pointermap);
    session->objectmap = NULL;
    session->pointermap = NULL;
}

void
dbsimple_free(dbsimple_session_type session)
{
    struct dbsimple_sessionbase* basesession = (struct dbsimple_sessionbase*)session;
    tree_foreach(basesession->objectmap, (tree_visitor_type) deleteobject, (void*) session);
    tree_destroy(basesession->objectmap);
    tree_destroy(basesession->pointermap);
}

void
dbsimple_delete(dbsimple_session_type session, void *ptr)
{
    struct object lookup;
    struct object* object;
    assert(ptr != NULL);
    lookup.data = ptr;
    object = tree_lookup(((struct dbsimple_sessionbase*)session)->pointermap, &lookup);
    if(object != NULL) {
        object->state = OBJREMOVED;
    }
}

void
dbsimple_dirty(dbsimple_session_type session, void *ptr)
{
    tree_reference_type cursor;
    struct object lookup;
    struct object* object;
    assert(ptr != NULL);
    lookup.data = ptr;
    object = tree_lookupref(((struct dbsimple_sessionbase*)session)->pointermap, &lookup, &cursor);
    if(object == NULL) {
        object = malloc(sizeof (struct object));
        object->type = NULL;
        object->state = OBJNEW;
        object->data = ptr;
        object->keyid = -1;
        object->keyname = NULL;
        object->revision = 0;
        object->next = NULL;
        object->backpatches = NULL;
        tree_insert(((struct dbsimple_sessionbase*)session)->pointermap, object);
    } else {
        object->state = OBJMODIFIED;
    }
}

void*
dbsimple__fetch(struct dbsimple_sessionbase* session, int ndefinitions, struct dbsimple_definitionimpl** definitions)
{
    struct object* object = NULL;

    session->pointermap = tree_create(pointermapcompare, NULL);
    session->objectmap = tree_create(objectmapcompare, NULL);
    session->firstmodified = NULL;
    for(int i=0; i<ndefinitions; i++) {
        if((definitions[i]->flags & dbsimple_FLAG_SINGLETON) == dbsimple_FLAG_SINGLETON) {
            object = dbsimple__getobject(session, OBJCLEAN, &(definitions[i]), 0, NULL);
        } else {
            session->module->fetchobject(&(definitions[i]), (dbsimple_session_type)session);
        }
    }
    tree_foreach(session->objectmap, (tree_visitor_type) resolvebackpatches, NULL);
    assert(object->data); // BERRY
    return object->data;
}
