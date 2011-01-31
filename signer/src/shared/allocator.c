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
    result->max_cleanup_count = DEFAULT_INITIAL_CLEANUP_COUNT;
    result->cleanups = (cleanup_type *) allocator(
        result->max_cleanup_count * sizeof(cleanup_type));
    if (!result->cleanups) {
        deallocator(result);
        ods_log_error("[%s] failed to create cleanups", allocator_str);
        return NULL;
    }

    result->total_allocated = 0;
    result->small_objects = 0;
    result->large_objects = 0;
    result->unused_space = 0;
    result->chunk_size = DEFAULT_CHUNK_SIZE;
    result->large_object_size = DEFAULT_LARGE_OBJECT_SIZE;
    result->cleanup_count = 0;
    result->allocated = 0;
    result->allocator = allocator;
    result->deallocator = deallocator;

    /* initial data */
    result->data = (char *) allocator(result->chunk_size);
    if (!result->data) {
        deallocator(result->cleanups);
        deallocator(result);
        ods_log_error("[%s] failed to allocate initial data", allocator_str);
        return NULL;
    }
    result->initial_data = result->data;
    return result;
}


/**
 *
 *
 */
static size_t
allocator_add_cleanup(allocator_type* allocator, void* data)
{
    if (allocator->cleanup_count >= allocator->max_cleanup_count) {
       cleanup_type* cleanups = (cleanup_type*) allocator->allocator(
           2 * allocator->max_cleanup_count * sizeof(cleanup_type));
       if (!cleanups) {
           return 0;
       }
       memcpy(cleanups, allocator->cleanups,
           allocator->cleanup_count * sizeof(cleanup_type));
       allocator->deallocator(allocator->cleanups);
       allocator->cleanups = cleanups,
       allocator->max_cleanup_count *= 2;
    }

    allocator->cleanups[allocator->cleanup_count].data = data;
    ++allocator->cleanup_count;
    return allocator->cleanup_count;
}


/**
 * Allocate memory.
 *
 */
void*
allocator_alloc(allocator_type* allocator, size_t size)
{
    size_t aligned_size;
    void* result;

    ods_log_assert(allocator);

    /* align size */
    if (size == 0) {
        size = 1;
    }
    aligned_size = ALIGN_UP(size, ALIGNMENT);

    /* large objects */
    if (aligned_size >= allocator->large_object_size) {
        result = allocator->allocator(size);
        if (!result) {
            return NULL;
        }
        if (!allocator_add_cleanup(allocator, result)) {
            allocator->deallocator(result);
            return NULL;
        }
        allocator->total_allocated += size;
        ++allocator->large_objects;
        return result;
    }

    /* new chunk? */
    if (allocator->allocated + aligned_size > allocator->chunk_size) {
        void* chunk = allocator->allocator(allocator->chunk_size);
        size_t wasted;
        if (!chunk) {
            return NULL;
        }
        wasted =
            (allocator->chunk_size - allocator->allocated) & (~(ALIGNMENT-1));
        if (wasted >= ALIGNMENT) {
            /* recycle wasted space */
            ods_log_debug("[%s] wasted space: %u bytes", allocator_str,
                wasted);
        }
        if (!allocator_add_cleanup(allocator, chunk)) {
            allocator->deallocator(chunk);
            return NULL;
        }
        ++allocator->chunk_count;
        allocator->unused_space +=
            allocator->chunk_size - allocator->allocated;
        allocator->allocated = 0;
        allocator->data = (char*) chunk;
    }

    result = allocator->data + allocator->allocated;
    allocator->allocated += aligned_size;
    allocator->total_allocated += aligned_size;
    allocator->unused_space += aligned_size - size;
    ++allocator->small_objects;
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
    return (char*) allocator_alloc_init(allocator, strlen(string) + 1, string);
}


/**
 * Deallocate memory.
 *
 */
void allocator_deallocate(allocator_type *allocator)
{
    size_t i;

    ods_log_assert(allocator);
    ods_log_assert(allocator->cleanups);

    i = allocator->cleanup_count;
    while (i > 0) {
        --i;
        allocator->deallocator(allocator->cleanups[i].data);
    }
    allocator->data = allocator->initial_data;
    allocator->cleanup_count = 0;
    allocator->allocated = 0;
    allocator->total_allocated = 0;
    allocator->small_objects = 0;
    allocator->large_objects = 0;
    allocator->chunk_count = 1;
    allocator->unused_space = 0;
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
    allocator_deallocate(allocator);
    deallocator(allocator->cleanups);
    deallocator(allocator->initial_data);
    deallocator(allocator);
    return;
}

