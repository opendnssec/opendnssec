/*
 * $Id: allocator.c 3817 2010-08-27 08:43:00Z matthijs $
 *
 * Copyright (c) 2010-2011 NLNet Labs. All rights reserved.
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

/**
 * Memory management.
 *
 */

#include "config.h"
#include "shared/allocator.h"
#include "shared/log.h"

#include <stdlib.h>
#include <string.h>

static const char* allocator_str = "allocator";

/**
 * Create allocator.
 *
 */
allocator_type*
allocator_create(void *(*allocator)(size_t size), void (*deallocator)(void *))
{
    allocator_type* result =
        (allocator_type*) allocator(sizeof(allocator_type));
    if (!result) {
        ods_log_error("[%s] failed to create allocator", allocator_str);
        return NULL;
    }
    result->allocator = allocator;
    result->deallocator = deallocator;
    return result;
}


/**
 * Allocate memory.
 *
 */
void*
allocator_alloc(allocator_type* allocator, size_t size)
{
    void* result;

    ods_log_assert(allocator);
    /* align size */
    if (size == 0) {
        size = 1;
    }
    result = allocator->allocator(size);
    if (!result) {
        ods_fatal_exit("[%s] allocator failed: out of memory", allocator_str);
        return NULL;
    }
    return result;
}


/**
 * Allocate memory and initialize to zero.
 *
 */
void*
allocator_alloc_zero(allocator_type *allocator, size_t size)
{
    void *result = allocator_alloc(allocator, size);
    if (!result) {
        return NULL;
    }
    memset(result, 0, size);
    return result;
}


/**
 * Allocate memory and initialize with data.
 *
 */
void*
allocator_alloc_init(allocator_type *allocator, size_t size, const void *init)
{
    void *result = allocator_alloc(allocator, size);
    if (!result) {
        return NULL;
    }
    memcpy(result, init, size);
    return result;
}


/**
 * Duplicate string.
 *
 */
char*
allocator_strdup(allocator_type *allocator, const char *string)
{
    if (!string) {
        return NULL;
    }
    return (char*) allocator_alloc_init(allocator, strlen(string) + 1, string);
}


/**
 * Deallocate memory.
 *
 */
void
allocator_deallocate(allocator_type *allocator, void* data)
{
    ods_log_assert(allocator);

    if (!data) {
        return;
    }
    allocator->deallocator(data);
    return;
}


/**
 * Cleanup allocator.
 *
 */
void
allocator_cleanup(allocator_type *allocator)
{
    void (*deallocator)(void *);
    if (!allocator) {
        return;
    }
    deallocator = allocator->deallocator;
    deallocator(allocator);
    return;
}

