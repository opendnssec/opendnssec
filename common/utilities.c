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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "utilities.h"

functioncast_type
functioncast(void*generic) {
    functioncast_type* function = (functioncast_type*)&generic;
    return *function;
}

int
clamp(int value, int lbnd, int ubnd)
{
    if(value < lbnd)
        return lbnd;
    else if(value > ubnd)
        return ubnd;
    else
        return value;
}
#ifdef __amd64
unsigned long long int
rnd(void)
{
  unsigned long long int foo;
  int cf_error_status;

  asm("rdrand %%rax; \
        mov $1,%%edx; \
        cmovae %%rax,%%rdx; \
        mov %%edx,%1; \
        mov %%rax, %0;":"=r"(foo),"=r"(cf_error_status)::"%rax","%rdx");
  return  (!cf_error_status ? 0 : foo);
}
#endif

int
alloc(void* p, size_t size, int* countptr, int newcount)
{
    char** ptr = (char**)p;
    char* newptr;
    if(*ptr == NULL) {
	*ptr = malloc(size * newcount);
	if(*ptr) {
	    if(countptr)
		*countptr = newcount;
            return 0;
	} else {
	    if(countptr)
		*countptr = 0;
            return -1;
	}
    } else {
	newptr = realloc(*ptr, size * newcount);
	if(newptr) {
	    if(countptr) {
	        if(newcount > *countptr)
                    memset(&newptr[size*(*countptr)], 0, size * (newcount - *countptr));
	        *countptr = newcount;
	    }
	    *ptr = newptr;
	    return 0;
	} else
            return -1;
    }
}

char*
dupstr(const char* ptr)
{
    return (ptr ? strdup(ptr) : NULL);
}
