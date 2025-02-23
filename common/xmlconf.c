/*
 * Copyright (c) 2022 Berry van Halderen <berry@nlnetlabs.nl>
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
 *
 */

#include "config.h"
#include <string.h>
#include <assert.h>
#include <libxml/parser.h>
#include "duration.h"
#include "log.h"

#include "xmlconf.h"

static int
accessfield(xmlconf_type h, const char* path, char** contentPtr, xmlNode** lastPtr)
{
    int rcode = 0;
    xmlNode* child;
    char* end;
    int len;
    xmlNode* node = h->node;
    if(!path)
        return -2;
    if(*path == '/') {
        node = h->root;
        ++path;
        end = strchr(path, '/');
        if(end) {
            len = end - path;
        } else {
            len = strlen(path);
        }
        if(!node)
            return 1;
        if(strncmp((char*)node->name, path, len) && node->name[len] == '\0') {
            return -1;
        }
        path += len;
        while(*path && *path == '/')
            ++path;
    }
    while(*path && *path != '@') {
        end = strchr(path, '/');
        if(end) {
            len = end - path;
        } else {
            len = strlen(path);
        }
        for (child = node->children; child; child = child->next) {
            if(!strncmp((char*)child->name, path, len) && child->name[len] == '\0')
                break;
        }
        if(!child) {
            if(!end) {
                if(lastPtr)
                    *lastPtr = node;
                return 1;
            } else
                return -1;
        }
        node = child;
        path += len;
        while(*path && *path == '/')
            ++path;
    }
    if(lastPtr)
        *lastPtr = node;
    if(*path && *path=='@') {
        ++path;
        if(xmlHasProp(node, (xmlChar*)path)) {
            if(contentPtr) {
                *contentPtr = (char*) xmlGetProp(node, (xmlChar*)path);
                if(!*contentPtr)
                    rcode = 1;
            }
        } else {
            rcode = 1;
            if(contentPtr)
                *contentPtr = NULL;
        }
    } else if(*path) {
        if(contentPtr)
            *contentPtr = NULL;
        if(lastPtr)
            *lastPtr = NULL;
        rcode = 1;
    } else {
        if(contentPtr)
            *contentPtr = (char*) xmlNodeGetContent(node);
        if(lastPtr)
            *lastPtr = node;
    }
    return rcode;
}

int
xmlconf_create(xmlconf_type* ptr)
{
    *ptr = malloc(sizeof(struct xmlconf_struct));
    if(!*ptr)
        goto failure;
    (*ptr)->root = NULL;
    (*ptr)->node = NULL;
    (*ptr)->doc  = xmlNewDoc((xmlChar*)"1.0");;
    (*ptr)->mode = xmlconf_OUTPUT;
    return 0;
failure:
    if(ptr && *ptr && (*ptr)->doc) {
        xmlFreeDoc((*ptr)->doc);
    }
    return -1;
}

int
xmlconf_input(xmlconf_type h, const char* filename)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr root = NULL;

    h->mode = xmlconf_INPUT;

    if(!(doc = xmlParseFile(filename))) {
        goto failure;
    }
    if(!(root = xmlDocGetRootElement(doc))) {
        goto failure;
    }
    if(h->doc) {
        xmlFreeDoc(h->doc);
    }
    h->doc  = doc;
    h->root = root;
    h->node = root;
    return 0;
failure:
    if(doc) {
        xmlFreeDoc(doc);
    }
    return -1;
}

int
xmlconf_merge(xmlconf_type h, char* filename)
{
    int rcode;
    rcode = xmlconf_input(h, filename);
    if(!rcode)
        h->mode = xmlconf_INMERGE;
    return rcode;
}

int
xmlconf_output(xmlconf_type h, char* filename)
{
    int rcode = 0;
    FILE* fp = fopen(filename,"w");
    rcode = xmlDocFormatDump(fp, h->doc, 1);
    fclose(fp);
    return rcode;
}

int
xmlconf_dispose(xmlconf_type* ptr)
{
    if(ptr) {
        xmlFreeDoc((*ptr)->doc);
        free(*ptr);
        *ptr = NULL;
    }
    return 0;
}

int
xml_generic(xmlconf_type handle, const char* path, void *ptr, int (*dataAssign)(char*,void*,void*), char* dataToString(void*,void*), void* dataUser)
{
    int rcode = 0;
    int status;
    const char* name;
    char* content = NULL;
    xmlNode* child;
    xmlNode* parent;
    xmlChar* value;
    if(!handle)
        return -1;
    switch(handle->mode) {
        case xmlconf_INPUT:
            status = accessfield(handle, path, (dataAssign?&content:ptr), NULL);
            if(dataAssign) {
                rcode = dataAssign(content, ptr, dataUser);
                xmlFree(content);
            }
            if(status < 0) {
                return -1;
            } else if(status > 0) {
                rcode = 1;
            } else
                rcode = 0;
            break;
        case xmlconf_INMERGE:
            status = accessfield(handle, path, &content, NULL);
            if(dataAssign) {
                rcode = dataAssign(content, ptr, dataUser);
                xmlFree(content);
            } else {
                if(strcmp(*(char**)ptr, content)) {
                    free(*(char**)ptr);
                    *(char**)ptr = content;
                    rcode = 1;
                } else {
                    xmlFree(content);
                    rcode = 0;
                }
            }
            break;
        case xmlconf_OUTPUT:
            status = accessfield(handle, path, NULL, &parent);
            if(status >= 0) {
                if((name = strrchr(path,'/'))) {
                    ++name;
                } else {
                    name = path;
                }
                if(*name == '@') {
                    ++name;
                    if(dataToString) {
                        value = (xmlChar*)dataToString(ptr, dataUser);
                        if(value)
                            xmlSetProp(parent, (xmlChar*)name, value);
                    } else
                        xmlSetProp(parent, (xmlChar*)name, *(xmlChar**)ptr);
                } else {
                    if(status == 0) {
                        if(dataToString) {
                            value = (xmlChar*)dataToString(ptr, dataUser);
                            if(value)
                                xmlNodeSetContent(parent, value);
                        } else
                            xmlNodeSetContent(parent, *(xmlChar**)ptr);
                    } else {
                        if(handle->root == NULL) {
                            child = xmlNewNode(NULL, (xmlChar*)name);
                            xmlDocSetRootElement(handle->doc, child);
                            handle->node = handle->root = child;
                        } else {
                            if(!strcmp(name,"Policy")) {
                            }
                            if(dataToString) {
                                value = (xmlChar*)dataToString(ptr, dataUser);
                                if(value) {
                                    child = xmlNewChild(parent, NULL, (xmlChar*)name, value);
				}
                            } else {
                                child = xmlNewChild(parent, NULL, (xmlChar*)name, (xmlChar*)(ptr ? *(char**)ptr : ""));
			    }
                        }
                    }
                }
            } else {
                rcode = 1;
            }
            break;
    }
    return rcode;
}

int
xmlconf_string(xmlconf_type handle, const char* path, char** ptr)
{
    return xml_generic(handle, path, ptr, NULL, NULL, NULL);
}

static int uintAssign(char* s, void* p, __attribute__((unused)) void* user) {
    if(!s)
        return -1;
    if(*(unsigned int*)p != atoi(s)) {
        *(unsigned int*)p = atoi(s);
        return 1;
    } else
        return 0;
}
static char* uintString(void* p, __attribute__((unused)) void* user) {
    char* s = NULL;
    asprintf(&s,"%u",*(unsigned int*)p);
    return s;
}

int
xmlconf_uint(xmlconf_type handle, const char* path, unsigned int* ptr)
{
    return xml_generic(handle, path, (void*)ptr, uintAssign, uintString, NULL);
}

static int optuintAssign(char* s, void* p, __attribute__((unused)) void* user) {
    if(s) {
        if(*(unsigned int*)p != atoi(s)) {
            *(unsigned int*)p = atoi(s);
            return 1;
        } else
            return 0;
    } else
        return -1;
}
static char* optuintString(void* p, __attribute__((unused)) void* user) {
    char* s = NULL;
    asprintf(&s,"%u",*(unsigned int*)p);
    return s;
}

int
xmlconf_optuint(xmlconf_type handle, const char* path, unsigned int* ptr, unsigned int defaultValue)
{
    if(handle->mode == xmlconf_INPUT) {
        *(unsigned int*)ptr = defaultValue;
    }
    return xml_generic(handle, path, (void*)ptr, optuintAssign, optuintString, NULL);
}

int
xmlconf_defuint(xmlconf_type handle, const char* path, unsigned int* ptr, unsigned int value)
{
    switch(handle->mode) {
        case xmlconf_INPUT:
        case xmlconf_INMERGE:
            *(unsigned int*)ptr = value;
            break;
        case xmlconf_OUTPUT:
            // xmlconf_compound(handle, path);
            assert(*(unsigned int*)ptr == value);
    }
    return 0;
}

static int booleanAssign(char* s, void* p, __attribute__((unused)) void* user) {
    if(!p) {
        *(unsigned int*)p = 0;
        return -1;
    } else if(*(unsigned int*)p != (s ? 1 : 0)) {
        *(unsigned int*)p = (s ? 1 : 0);
        return 1;
    } else
        return 0;
}
static char* booleanString(void* p, __attribute__((unused)) void* user) {
    if(*(unsigned int*)p) {
        return strdup("");
    } else {
        return NULL;
    }
}

int
xmlconf_boolean(xmlconf_type handle, const char* path, unsigned int* valuePtr)
{
    return xml_generic(handle, path, valuePtr, booleanAssign, booleanString, NULL);
}

int
xmlconf_compound(xmlconf_type handle, const char* path)
{
    return xml_generic(handle, path, NULL, NULL, NULL, NULL);
}

int
xmlconf_conditional(xmlconf_type handle, const char* path, int* valuePtr, int value)
{
    unsigned int exists;
    switch(handle->mode) {
        case xmlconf_INPUT:
            xmlconf_boolean(handle, path, &exists);
            if(exists > 0) {
                *valuePtr = value;
                return 1;
            } else
                return 0;
        case xmlconf_INMERGE:
            xmlconf_boolean(handle, path, &exists);
            if(exists > 0) {
                if(*valuePtr != value) {
                    *valuePtr = value;
                    return 1;
                } else
                    return 0;
            } else {
                if(*valuePtr == value) {
                    return 1;
                } else
                    return 0;
            }
        case xmlconf_OUTPUT:
            if(*valuePtr == value)
                xmlconf_compound(handle, path);
            return 0;
    }
    return 0;
}

static int durationAssign(char* s, void* p, __attribute__((unused)) void* user) {
    unsigned int newValue;
    unsigned int oldValue = *(unsigned int*)p;
    duration_type* newDuration = duration_create_from_string(s);
    if(!newDuration)
        return -1;
    newValue = duration2time(newDuration);
    duration_cleanup(newDuration);
    if(oldValue != newValue) {
        *(unsigned int*)p = newValue;
        return 1;
    } else
        return 0;
}
static char* durationString(void* p, __attribute__((unused)) void* user) {
    duration_type duration;
    duration_set_time(&duration, *(int*)p);
    return duration2string(&duration);
}

int
xmlconf_duration(xmlconf_type handle, const char* path, unsigned int* valuePtr)
{
    return xml_generic(handle, path, valuePtr, durationAssign, durationString, NULL);
}

static int enumAssign(char* s, void* p, void* user) {
    struct xmlconf_enum_struct* enums = (struct xmlconf_enum_struct*) user;
    while(enums && enums->name && s && strcmp(enums->name, s))
        enums = &(enums[1]);
    if(enums && enums->name) {
        if(*(unsigned int*)p != enums->value) {
            *(unsigned int*)p = enums->value;
            return 1;
        } else
            return 0;
    } else
        return -1;
}
static char* enumString(void* p, void* user) {
    int value = *(int*)p;
    struct xmlconf_enum_struct* enums = (struct xmlconf_enum_struct*) user;
    while(enums && enums->name && enums->value != value)
        enums = &(enums[1]);
    if(enums && enums->name)
        return strdup(enums->name);
    else
        return uintString(p, user);
}

int
xmlconf_optenum(xmlconf_type handle, const char* path, unsigned int* valuePtr, struct xmlconf_enum_struct* enums, int defaultValue)
{
    if(handle->mode == xmlconf_INPUT)
        *valuePtr = defaultValue;
    return xml_generic(handle, path, valuePtr, enumAssign, enumString, (void*)enums);
}

int
xmlconf_enum(xmlconf_type handle, const char* path, int* valuePtr, struct xmlconf_enum_struct* enums)
{
    return xml_generic(handle, path, valuePtr, enumAssign, enumString, (void*)enums);
}

xmlconf_iterator_type
xmlconf_iterate(xmlconf_type handle, const char* path, int* nitems, void* items)
{
    int status;
    xmlNode* node;
    xmlconf_iterator_type iter;
    iter.current = NULL;
    iter.handle = handle;
    iter.items = items;
    iter.nitems = nitems;
    iter.nodestack = handle->node;
    status = accessfield(handle, path, NULL, &node);
    if(status == 0) {
        iter.current = node;
        iter.parent = node->parent;
    } else if(status > 1) {
        iter.current = NULL;
        iter.parent = node;
    } else {
        iter.current = NULL;
        iter.parent = node;
    }
    if((iter.name = strrchr(path, '/'))) {
        iter.name = &iter.name[1];
    } else {
        iter.name = path;
    }
    return iter;
}

int
xmlconf_next(xmlconf_iterator_type* iter)
{
    switch(iter->handle->mode) {
        case xmlconf_INPUT:
        case xmlconf_INMERGE:
            iter->item = NULL;
            if(iter->current) {
                iter->handle->node = iter->current;
                do {
                    iter->current = ((xmlNode*)iter->current)->next;
                } while(iter->current && strcmp(iter->name,(char*)((xmlNode*)iter->current)->name));
                return 1;
            }
            break;
        case xmlconf_OUTPUT:
            if(*(iter->nitems)) {
                iter->item = iter->items[0];
                iter->items = &(iter->items[1]);
                *(iter->nitems) -= 1;
                iter->handle->node = xmlNewChild((xmlNode*)(iter->parent), NULL, (xmlChar*)iter->name, (xmlChar*)"");
                return 1;
            }
    }
    iter->handle->node = iter->nodestack;
    return 0;
}

int
xmlconf_match(xmlconf_iterator_type* iter, void* template, void* item, int (*compare)(void*,void*))
{
    int i;
    switch(iter->handle->mode) {
        case xmlconf_INPUT:
            return 0;
        case xmlconf_INMERGE:
            if(iter->current) {
                iter->handle->node = iter->current;
                iter->current = NULL;
                return 1;
            } else {
                iter->current = iter->handle->node;
                for(i=0; i<*(iter->nitems); i++) {
                    if(!compare(template, iter->items[i]))
                        break;
                }
                if(i<*(iter->nitems)) {
                    *(void**)item = iter->items[i];
                    if(i+1 < *(iter->nitems))
                        memmove(&(iter->items[i]), &(iter->items[i+1]), sizeof(void*)*(*(iter->nitems))-i-1);
                    *(iter->nitems) -= 1;
                } else
                    *(void**)item = NULL;
                return 0;
            }
            break;
        case xmlconf_OUTPUT:
            *(void**)item = iter->item;
            return 0;
    }
    return 0;
}
