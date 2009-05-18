/*
 * $Id$
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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

#ifndef KSM_STRING_UTIL2_H
#define KSM_STRING_UTIL2_H

/*+
 * Filename: string_util2.h
 *
 * Description:
 *      Additional string function definitions.
-*/

#include "system_includes.h"
#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Structure definition for StrKeywordSearch function */

typedef struct {
    const char* string;
    int         value;
} STR_KEYWORD_ELEMENT;

/* Function definitions */

void StrAppend(char** str1, const char* str2);
void StrArglistAdd(char*** argv, const char* string);
void StrArglistFree(char*** argv);
char** StrArglistCreate(const char* string);
int StrKeywordSearch(const char* search, STR_KEYWORD_ELEMENT* keywords, int* value);
int StrStrtol(const char* string, long* value);
int StrStrtoul(const char* string, unsigned long* value);
int StrStrtoi(const char* string, int* value);
int StrIsDigits(const char* string);

#ifdef __cplusplus
}
#endif

#endif /* KSM_STRING_UTIL2_H */
