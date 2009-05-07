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

#ifndef STRING_UTIL_H
#define STRING_UTIL_H

/*+
 * Filename: string_util.h
 *
 * Description:
 *      Definitions of the string utilities used by all the whois programs.
-*/

#include "system_includes.h"
#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COMMENT_CHAR ("#")

void StrUncomment(char* line);
void StrWhitespace(char* line);
char* StrStrdup(const char* string);
void StrStrncpy(char* dest, const char* src, size_t destlen);
void StrStrncat(char* dest, const char* src, size_t destlen);
void StrTrimR(char* text);
char* StrTrimL(char* text);
char* StrTrim(char* text);
size_t StrToLower(char* text);
size_t StrToUpper(char* text);
size_t StrReplaceCharN(char* string, size_t len, char search, char replace);
size_t StrReplaceChar(char* string, char search, char replace);
size_t StrTrimmedLength(const char* string);

/*
 * The next definition allows for possible alternative memory strategies to
 * be used for string routines.  At any rate, StrFree() should be used to free
 * a string allocated by StrStrdup().
 */

#define StrFree(x) MemFree(x)

/*
 * A simple macro (the idea comes from the memcached code) that allows the
 * compile-time determination of the length of a literal string.  Note that
 * the string must be declared by:
 *
 *          char    string[] = "this is a literal string"
 *
 * rather than
 * 
 *          char*   string = "this is a literal string"
 *
 * Use of the macro on the former gives the correct string length.  On the
 * latter it gives "sizeof(char*) - 1".
 */

#define STR_LENGTH(x)   (sizeof(x) - 1)

#ifdef __cplusplus
}
#endif

#endif
