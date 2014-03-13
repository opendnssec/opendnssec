/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
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

#ifndef __mm_h
#define __mm_h

#include <stdlib.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MM_ALLOC_T_STATIC_NEW(x) { NULL, x, PTHREAD_MUTEX_INITIALIZER }

typedef struct mm_alloc mm_alloc_t;
struct mm_alloc
{
	void *next;
	size_t size;
	pthread_mutex_t lock;
};

extern mm_alloc_t mm_char_16;
extern mm_alloc_t mm_char_32;
extern mm_alloc_t mm_char_64;
extern mm_alloc_t mm_char_128;
extern mm_alloc_t mm_char_256;
extern mm_alloc_t mm_char_512;
extern mm_alloc_t mm_char_1024;

void mm_init(void);
void* mm_alloc_new(mm_alloc_t*);
void* mm_alloc_new0(mm_alloc_t*);
void mm_alloc_delete(mm_alloc_t*, void*);

#ifdef __cplusplus
}
#endif

#endif
