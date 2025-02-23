/*
 * Copyright (c) 2023 Berry van Halderen <berry@nlnetlabs.nl>
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

#ifndef XMLCONF_H
#define XMLCONF_H

struct xmlconf_struct {
    enum { xmlconf_INPUT, xmlconf_OUTPUT, xmlconf_INMERGE } mode;
    int updated;
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr node;
};
typedef struct xmlconf_struct* xmlconf_type;

typedef struct xmlconf_iterator_struct {
    xmlconf_type handle;
    void* current;
    void* parent;
    int* nitems;
    void** items;
    void* item;
    const char* name;
    void* nodestack;
} xmlconf_iterator_type;

struct xmlconf_enum_struct {
    char* name;
    int value;
};

extern int xmlconf_create(xmlconf_type* ptr);
extern int xmlconf_input(xmlconf_type h, const char* filename);
extern int xmlconf_merge(xmlconf_type h, char* filename);
extern int xmlconf_output(xmlconf_type h, char* filename);
extern int xmlconf_dispose(xmlconf_type* ptr);

extern int xml_generic(xmlconf_type handle, const char* path, void *ptr, int (*dataAssign)(char*,void*,void*), char* dataToString(void*,void*), void* dataUser);

extern int xmlconf_string(xmlconf_type handle, const char* path, char** ptr);

extern int xmlconf_uint(xmlconf_type handle, const char* path, unsigned int* ptr);
extern int xmlconf_optuint(xmlconf_type handle, const char* path, unsigned int* ptr, unsigned int defaultValue);
extern int xmlconf_defuint(xmlconf_type handle, const char* path, unsigned int* ptr, unsigned int value);

extern int xmlconf_boolean(xmlconf_type handle, const char* path, unsigned int* valuePtr);

extern int xmlconf_compound(xmlconf_type handle, const char* path);

extern int xmlconf_conditional(xmlconf_type handle, const char* path, int* valuePtr, int value);

extern int xmlconf_duration(xmlconf_type handle, const char* path, unsigned int* valuePtr);

extern int xmlconf_enum(xmlconf_type handle, const char* path, int* valuePtr, struct xmlconf_enum_struct* enums);
extern int xmlconf_optenum(xmlconf_type handle, const char* path, unsigned int* valuePtr, struct xmlconf_enum_struct* enums, int defaultValue);

extern xmlconf_iterator_type xmlconf_iterate(xmlconf_type handle, const char* path, int* nitems, void* items);
extern int xmlconf_next(xmlconf_iterator_type* iter);
extern int xmlconf_match(xmlconf_iterator_type* iter, void* template, void* item, int (*compare)(void*,void*));

#endif
