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

#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "utilities.h"
typedef void* document_type;
typedef void* node_type;
#define settings__INTERNAL
#include "settings.h"
#include "duration.h"

struct settings_struct {
    char* (*getscalar)(node_type node);
    int (*nodecount)(node_type node);
    document_type (*access)(document_type document, int fd);
    node_type (*parselocate)(document_type document, node_type node, const char* fmt, va_list ap, const char** lastp);
    document_type document;
    node_type root;
};

static settings_handle defaulthandle = NULL;
void* settings_value_NULL = NULL;

typedef int (*namedtranslatetype)(const char*,long*resultvalue);

static int
parsefuncbool(void* user, const char* str, void* resultvalue)
{
    int* resultint = (int*) resultvalue;
    (void)user;
    errno = 0;
    *resultint = 1;
    return 0;
}

static int
parsefuncint(void* user, const char* str, void* resultvalue)
{
    char* end;
    int* resultint = (int*) resultvalue;
    (void)user;
    errno = 0;
    *resultint = strtol(str, &end, 0);
    if (errno) {
        return 1;
    } else {
        return 0;
    }
}

static int
parsefunclong(void* user, const char* str, void* resultvalue)
{
    char* end;
    long* resultlong = (long*) resultvalue;
    (void)user;
    errno = 0;
    *resultlong = strtol(str, &end, 0);
    if (errno) {
        return 1;
    } else {
        return 0;
    }
}

static int
parsefuncstring(void* user, const char* str, void* resultvalue)
{
    char** resultstring = (char**) resultvalue;
    (void)user;
    errno = 0;
    if (str) {
        *resultstring = strdup(str);
        return 0;
    } else
        return 1;
}

struct parsefuncenum {
    const char** enumstrings;
    const int* enumvalues;
};

static int
parsefuncenum(void* user, const char* str, void* resultvalue)
{
    int i;
    char* end;
    int* resultint = (int*) resultvalue;
    struct parsefuncenum* enums = (struct parsefuncenum*)user;
    errno = 0;
    *resultint = strtol(str, &end, 0);
    if ((errno || end == str) && enums) {
        for(i=0; enums->enumstrings[i] != NULL; i++) {
            if (!strcasecmp(enums->enumstrings[i], str)) {
                if(enums->enumvalues) {
                    *resultint = enums->enumvalues[i];
                } else {
                    *resultint = i;
                }
                return 0;
            }
        }
        return 1;
    } else
        return 0;
}

static int
parsefunccount(void* user, const char* str, void* resultvalue)
{
    char* end;
    long* resultlong = (long*) resultvalue;
    (void)user;
    errno = 0;
    if (*str == '#') {
        ++str;
        while(isspace(*str))
            ++str;
    }
    *resultlong = strtol(str, &end, 0);
    if (errno || str==end) {
        return 1;
    } else {
        return 0;
    }
}

static int
parsefuncnamed(void* user, const char* str, void* resultvalue)
{
    char* end;
    const char* last;
    long* resultlong = (long*) resultvalue;
    namedtranslatetype translate = (namedtranslatetype) *(functioncast_type*)user;
    errno = 0;
    while(isspace(*str))
      ++str;
    if (*str == '#') {
        ++str;
        while(isspace(*str))
            ++str;
        *resultlong = strtol(str, &end, 0);
        if (errno || str==end) {
            return 1;
        } else {
            return 0;
        }
    }
    for (last=str; *last && !isspace(*last); ++last)
        ;
    if (*last) {
        str = strndupa(str, last-str);
    }
    return translate(str, resultvalue);
}

static node_type
parselocate(settings_handle handle, document_type document, node_type node, const char* fmt, ...)
{
    va_list ap;
    const char* last = "unknown";
    va_start(ap, fmt);
    node = handle->parselocate(document, node, fmt, ap, &last);
    va_end(ap);
    return node;
}

static int
parsescalar(settings_handle handle, document_type document, node_type root, size_t resultsize, void* resultvalue, const void* defaultvalue,
            int (*parsefunc)(void*,const char*,void*), void* parsedata, const char* fmt, va_list ap)
{
    const char* last = "unknown";
    const char* str;
    int result;
    node_type node;
    node = handle->parselocate(document, root, fmt, ap, &last);
    if (node) {
        if((str = handle->getscalar(node))) {
            if (parsefunc(parsedata,str,resultvalue)) {
                if (defaultvalue) {
                    memcpy(resultvalue,defaultvalue,resultsize);
                }
                result = -1;
            } else {
                result = 0;
            }
            free((void*)str);
        } else {
            if (defaultvalue) {
                memcpy(resultvalue,defaultvalue,resultsize);
            }
            result = -1;
        }
    } else {
        if (defaultvalue) {
            memcpy(resultvalue,defaultvalue,resultsize);
            result = 0;
        } else {
            result = 1;
        }
    }
    return result;
}

static int
parsecompound(settings_handle handle, document_type document, node_type root, int* resultvalue, const char* fmt, va_list ap)
{
    int count;
    const char* last = "unknown";
    node_type node;
    node = handle->parselocate(document, root, fmt, ap, &last);
    if (node) {
        count = handle->nodecount(node);
    } else {
        count = -1;
    }
    *resultvalue = count;
    return 0;
}

int
settings_setcontext(settings_handle handle, const char* fmt, ...)
{
    const char* last = "unknown";
    node_type node;
    va_list ap;
    va_start(ap, fmt);
    node = handle->parselocate(handle->document, 0, fmt, ap, &last);
    va_end(ap);
    if(node) {
        handle->root = node;
        return 0;
    } else {
        return -1;
    }
}

int
settings_clone(settings_handle handle, settings_handle* copy)
{
    if(!handle)
        handle = defaulthandle;
    *copy = malloc(sizeof(struct settings_struct));
    if(!*copy)
        return -1;
    (*copy)->document = handle->document;
    (*copy)->root     = handle->root;
    return 0;
}

void
settings_free(settings_handle handle)
{
    if(handle->document) {
        handle->access(handle->document, -1);
    }
    free(handle);
}

int
settings_getstringdefault(settings_handle handle, char** resultvalue, const char* defaultvalue, const char* fmt, ...)
{
    int rc;
    va_list ap;
    handle = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    *resultvalue = NULL;
    rc = parsescalar(handle, handle->document, handle->root, sizeof(char*), resultvalue, NULL, parsefuncstring, NULL, fmt, ap);
    if(*resultvalue == NULL && defaultvalue)
        *resultvalue = strdup(defaultvalue);
    va_end(ap);
    return rc;
}

int
settings_getstring(settings_handle handle, char** resultvalue, const char** defaultvalue, const char* fmt, ...)
{
    int rc;
    va_list ap;
    handle = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    *resultvalue = NULL;
    rc = parsescalar(handle, handle->document, handle->root, sizeof(char*), resultvalue, NULL, parsefuncstring, NULL, fmt, ap);
    if(*resultvalue == NULL && defaultvalue)
        *resultvalue = dupstr(*defaultvalue);
    va_end(ap);
    return rc;
}

int
settings_getbool(settings_handle handle, int* resultvalue, const char* fmt, ...)
{
    int rc;
    va_list ap;
    handle = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    *resultvalue = 0;
    rc = parsescalar(handle, handle->document, handle->root, sizeof(long), resultvalue, settings_value_NULL, parsefuncbool, NULL, fmt, ap);
    va_end(ap);
    return rc;
}

int
settings_getint(settings_handle handle, int* resultvalue, const int* defaultvalue, const char* fmt, ...)
{
    int rc;
    va_list ap;
    handle = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    rc = parsescalar(handle, handle->document, handle->root, sizeof(long), resultvalue, defaultvalue, parsefuncint, NULL, fmt, ap);
    va_end(ap);
    return rc;
}

int
settings_getlong(settings_handle handle, long* resultvalue, const long* defaultvalue, const char* fmt, ...)
{
    int rc;
    va_list ap;
    handle = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    rc = parsescalar(handle, handle->document, handle->root, sizeof(long), resultvalue, defaultvalue, parsefunclong, NULL, fmt, ap);
    va_end(ap);
    return rc;
}

int
settings_getenum(settings_handle handle, int* resultvalue, const int* defaultvalue, const char** enums, const char* fmt, ...)
{
    int rc;
    va_list ap;
    struct parsefuncenum enummapping;
    enummapping.enumstrings = enums;
    enummapping.enumvalues = NULL;
    handle = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    rc = parsescalar(handle, handle->document, handle->root, sizeof(long), resultvalue, defaultvalue, parsefuncenum, &enummapping, fmt, ap);
    va_end(ap);
    return rc;
}

int
settings_getenum2(settings_handle handle, int* resultvalue, const int* defaultvalue, const char** enumstrings, const int* enumvalues, const char* fmt, ...)
{
    int rc;
    va_list ap;
    struct parsefuncenum enummapping;
    enummapping.enumstrings = enumstrings;
    enummapping.enumvalues = enumvalues;
    handle = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    rc = parsescalar(handle, handle->document, handle->root, sizeof(long), resultvalue, defaultvalue, parsefuncenum, &enummapping, fmt, ap);
    va_end(ap);
    return rc;
}

int
settings_getcompound(settings_handle handle, int* resultvalue, const char* fmt, ...)
{
    int rc;
    va_list ap;
    handle = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    rc = parsecompound(handle, handle->document, handle->root, resultvalue, fmt, ap);
    va_end(ap);
    return rc;
}

int
settings_getcount(settings_handle handle, long* resultvalue, const long* defaultvalue, const char* fmt, ...)
{
    int rc;
    va_list ap;
    handle = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    rc = parsescalar(handle, handle->document, handle->root, sizeof(long), resultvalue, defaultvalue, parsefunccount, NULL, fmt, ap);
    va_end(ap);
    return rc;
}

int
settings_getnamed(settings_handle handle, long* resultvalue, const long* defaultvalue, int (*translate)(const char*,long*resultvalue), const char* fmt, ...)
{
    int rc;
    va_list ap;
    functioncast_type funcptr = (functioncast_type)translate;
    handle = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    rc = parsescalar(handle, handle->document, handle->root, sizeof(long), resultvalue, defaultvalue, parsefuncnamed, &funcptr, fmt, ap);
    va_end(ap);
    return rc;
}

int
settings_access(settings_handle* handleptr, int basefd, const char* filename)
{
    int fd, returncode;
    document_type olddocument = NULL;
    document_type document;
    node_type root;
    if(handleptr == NULL) {
        if(defaulthandle) {
            olddocument = defaulthandle->document;
            free((void*)defaulthandle);
            defaulthandle = NULL;
        }
        handleptr = &defaulthandle;
    } else if(filename == NULL && *handleptr != NULL) {
        olddocument = (*handleptr)->document;
    }

    *handleptr = malloc(sizeof(struct settings_struct));
    if(filename == NULL) {
        (*handleptr)->getscalar   = NULL;
        (*handleptr)->nodecount   = NULL;
        (*handleptr)->parselocate = NULL;
        (*handleptr)->access      = NULL;
    } else {
        (*handleptr)->getscalar   = settings__getscalar_xml;
        (*handleptr)->nodecount   = settings__nodecount_xml;
        (*handleptr)->parselocate = settings__parselocate_xml;
        (*handleptr)->access      = settings__access_xml;
    }
    
    if(filename != NULL) {
        if(basefd < 0 || !strncmp(filename,"/",strlen("/")))
            fd = open(filename, O_RDONLY);
        else
            fd = openat(basefd, filename, O_RDONLY);
    } else
        fd = -1;
    if(filename != NULL && fd >= 0) {
        document = (*handleptr)->access(olddocument, fd);
        root = parselocate(*handleptr, document, NULL, NULL, NULL);
        returncode = 0;
    } else {
        document = NULL;
        root = NULL;
        returncode = -1;
    }
    (*handleptr)->document = document;
    (*handleptr)->root = root;
    return returncode;
}

int
settings_getduration(settings_handle handle, time_t* resultvalue, const int defaultvalue, const char* fmt,...)
{
    int rc;
    char* s = NULL;
    va_list ap;
    handle = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    rc = parsescalar(handle, handle->document, handle->root, sizeof(char*), &s, NULL, parsefuncstring, NULL, fmt, ap);
    if(rc == 0) {
        duration_type* duration = duration_create_from_string(s);
        *resultvalue = duration2time(duration);
        duration_cleanup(duration);
        free(s);
    } else
        *resultvalue = defaultvalue;
    va_end(ap);
    return rc;
}

int
settings_getduration2(settings_handle handle, duration_type** resultvalue, const char* fmt,...)
{
    int rc;
    char* s = NULL;
    va_list ap;
    handle = (handle ? handle : defaulthandle);
    va_start(ap, fmt);
    rc = parsescalar(handle, handle->document, handle->root, sizeof(char*), &s, NULL, parsefuncstring, NULL, fmt, ap);
    if(rc == 0) {
        *resultvalue = duration_create_from_string(s);
        free(s);
    } else
        *resultvalue = NULL;
    va_end(ap);
    return rc;
}
 