#ifndef STRING_UTIL2_H
#define STRING_UTIL2_H

/*+
 * Filename: string_util2.h
 *
 * Description:
 *      Additional string function definitions.
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

#endif
