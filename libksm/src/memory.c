/*+
 * Filename: memory.c
 *
 * Description:
 *      Wrappers around memory allocation routines.  If any fail,
 *      the program will write a memory exhaustion error to stderr
 *      and terminate.
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

#include <stdio.h>
#include <stdlib.h>

#include "memory.h"


/*+
 * MemMalloc - Allocate Memory
 * MemCalloc - Allocate Contiguous Memory
 * MemRealloc - Reallocate Memory
 *
 * Description:
 *      Wrapper routines around the Unix memory allocation routines.  If
 *      an allocation routine returns null, an error is logged and the
 *      program exits.
 *
 *      MemFree is also defined, but as a macro to allow the passed element
 *      to be zeroed.  The definition can be found in the header file.
-*/

void* MemMalloc(size_t size)
{
    void *ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "malloc: Out of swap space");
		exit(1);
    }
    return ptr;
}

void* MemCalloc(size_t nmemb, size_t size)
{
    void *ptr = calloc(nmemb, size);
    if (ptr == NULL) {
        fprintf(stderr, "calloc: Out of swap space");
		exit(1);
    }
    return ptr;
}

void* MemRealloc(void *ptr, size_t size)
{
    void *ptr1 = realloc(ptr, size);
    if (ptr1 == NULL) {
        fprintf(stderr, "realloc: Out of swap space");
        exit(1);
    }
    return ptr1;
}
