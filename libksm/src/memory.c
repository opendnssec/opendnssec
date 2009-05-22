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

/*+
 * Filename: memory.c
 *
 * Description:
 *      Wrappers around memory allocation routines.  If any fail,
 *      the program will write a memory exhaustion error to stderr
 *      and terminate.
-*/

#include <stdio.h>
#include <stdlib.h>

#include "ksm/memory.h"
#include "ksm/ksmdef.h"
#include "ksm/message.h"

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
		MsgLog(KSM_STMTALLOC, "malloc: Out of swap space");
        fprintf(stderr, "malloc: Out of swap space");
		exit(1);
    }
    return ptr;
}

void* MemCalloc(size_t nmemb, size_t size)
{
    void *ptr = calloc(nmemb, size);
    if (ptr == NULL) {
		MsgLog(KSM_STMTALLOC, "calloc: Out of swap space");
        fprintf(stderr, "calloc: Out of swap space");
		exit(1);
    }
    return ptr;
}

void* MemRealloc(void *ptr, size_t size)
{
    void *ptr1 = realloc(ptr, size);
    if (ptr1 == NULL) {
		MsgLog(KSM_STMTALLOC, "realloc: Out of swap space");
        fprintf(stderr, "realloc: Out of swap space");
        exit(1);
    }
    return ptr1;
}
