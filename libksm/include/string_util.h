#ifndef STRING_UTIL_H
#define STRING_UTIL_H

/*+
 * Filename: string_util.h
 *
 * Description:
 *      Definitions of the string utilities used by all the whois programs.
 *
 *
 * Copyright:
 *      Copyright 2008 Nominet
 *      
 * Licence:
 *      Licensed under the Apache Licence, Version 2.0 (the "Licence");
 *      you may not use this file except in compliance with the Licence.
 *      You may obtain a copy of the Licence at
 *      
 *          http://www.apache.org/licenses/LICENSE-2.0
 *      
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the Licence is distributed on an "AS IS" BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the Licence for the specific language governing permissions and
 *      limitations under the Licence.
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
