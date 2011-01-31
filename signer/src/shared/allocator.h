/*
 * $Id: allocator.h 3695 2010-08-10 09:00:55Z jakob $
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

#ifndef SHARED_ALLOCATOR_H
#define SHARED_ALLOCATOR_H

#include "config.h"

#include <stdlib.h>

#define DEFAULT_CHUNK_SIZE 4096
#define DEFAULT_LARGE_OBJECT_SIZE (DEFAULT_CHUNK_SIZE / 8)
#define DEFAULT_INITIAL_CLEANUP_COUNT 16
#define ALIGN_UP(x, s) (((x) + s - 1) & (~(s - 1)))
#define ALIGNMENT (sizeof(void *))


typedef struct cleanup_struct cleanup_type;
struct cleanup_struct {
    void* data;
};

typedef struct allocator_struct allocator_type;
struct allocator_struct {
    size_t total_allocated;
    size_t small_objects;
    size_t large_objects;
    size_t unused_space;
    size_t chunk_count;
    size_t chunk_size;
    size_t large_object_size;
    size_t cleanup_count;
    size_t max_cleanup_count;
    size_t allocated;
    char* data;
    char* initial_data;
    void* (*allocator)(size_t);
    void  (*deallocator)(void *);
    cleanup_type* cleanups;
};

/**
 * Create allocator.
 * \param[in] allocator function for allocating
 * \param[in] deallocator function for deallocating
 * \return allocator_type* allocator
 */
allocator_type* allocator_create(void *(*allocator)(size_t size),
    void (*deallocator)(void *));

/**
 * Allocate memory.
 * \param[in] allocator the allocator
 * \param[in] size size to allocate
 * \return void* pointer to allocated memory
 */
void* allocator_alloc(allocator_type* allocator, size_t size);

/**
 * Allocate memory and initialize to zero.
 * \param[in] allocator the allocator
 * \param[in] size size to allocate
 * \return void* pointer to allocated memory
 */
void* allocator_alloc_zero(allocator_type* allocator, size_t size);

/**
 * Allocate memory and initialize with data.
 * \param[in] allocator the allocator
 * \param[in] size size to allocate
 * \param[in] init initialized data
 * \return void* pointer to allocated memory
 *
 */
void* allocator_alloc_init(allocator_type *allocator, size_t size,
    const void* init);

/**
 * Duplicate string.
 * \param[in] allocator the allocator
 * \param[in] string
 * \return char* duplicated string
 *
 */
char* allocator_strdup(allocator_type *allocator, const char *string);

/**
 * Deallocate memory.
 * \param[in] allocator the allocator
 *
 */
void allocator_deallocate(allocator_type* allocator);

/**
 * Cleanup allocator.
 * \param[in] allocator the allocator
 *
 */
void allocator_cleanup(allocator_type* allocator);


#endif /* SHARED_ALLOCATOR_H */
