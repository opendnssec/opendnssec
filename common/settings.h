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

#ifndef SETTINGS_H
#define SETTINGS_H

#include "duration.h"

struct settings_struct;
typedef struct settings_struct* settings_handle;

extern int settings_access(settings_handle*, int basefd, const char* filename);
extern int settings_setcontext(settings_handle handle, const char* fmt, ...);
extern int settings_clone(settings_handle handle, settings_handle* copy);
extern void settings_free(settings_handle handle);
extern int settings_getlong(settings_handle, long* resultvalue, const long* defaultvalue, const char* fmt,...);
extern int settings_getint(settings_handle, int* resultvalue, const int* defaultvalue, const char* fmt,...);
extern int settings_getbool(settings_handle, int* resultvalue, const char* fmt,...);
extern int settings_getenum(settings_handle, int* resultvalue, const int* defaultvalue, const char** enums, const char* fmt, ...);
extern int settings_getenum2(settings_handle, int* resultvalue, const int* defaultvalue, const char** enumstrings, const int* enumvalues, const char* fmt, ...);
extern int settings_getcount(settings_handle, long* resultvalue, const long* defaultvalue, const char* fmt,...);
extern int settings_getnamed(settings_handle handle, long* resultvalue, const long* defaultvalue, int (*translate)(const char*,long*resultvalue), const char* fmt, ...);
extern int settings_getstringdefault(settings_handle handle, char** resultvalue, const char* defaultvalue, const char* fmt, ...);
extern int settings_getstring(settings_handle, char** resultvalue, const char** defaultvalue, const char* fmt, ...);
extern int settings_getcompound(settings_handle, int* resultvalue, const char* fmt, ...);

extern int settings_configure(settings_handle* cfghandleptr, char* sysconfdir, char* sysconffile, int cmdline_verbosity);

extern void* settings_value_NULL;

#ifdef settings__INTERNAL
extern char* settings__getscalar_yaml(node_type node);
extern int settings__nodecount_yaml(node_type node);
extern document_type settings__access_yaml(document_type document, int fd);
extern node_type settings__parselocate_yaml(document_type document, node_type node, const char* fmt, va_list ap, const char** lastp);

extern char* settings__getscalar_xml(node_type node);
extern int settings__nodecount_xml(node_type node);
extern document_type settings__access_xml(document_type document, int fd);
extern node_type settings__parselocate_xml(document_type document, node_type node, const char* fmt, va_list ap, const char** lastp);
#endif

extern int settings_getduration(settings_handle, time_t* resultvalue, const int defaultvalue, const char* fmt,...);
extern int settings_getduration2(settings_handle handle, duration_type** resultvalue, const char* fmt, ...);

#endif
