#ifndef MEMORY_H
#define MEMORY_H

/*+
 * Filename: memory.h
 *
 * Description:
 *      Definition of the memory allocation routines used in the whois suite of
 *      programs.  These are just wrappers around the similarly-named Unix
 *      routines.
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

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

void* MemMalloc(size_t size);
void* MemCalloc(size_t nmemb, size_t size);
void* MemRealloc(void* ptr, size_t size);
#define MemFree(ptr) {free(ptr); (ptr) = NULL;}

#ifdef __cplusplus
}
#endif

#endif

