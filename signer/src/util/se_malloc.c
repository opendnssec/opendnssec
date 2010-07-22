/*
 * $Id$
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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
 * Memory management wrapper.
 *
 */

#include "config.h"
#include "util/se_malloc.h"
#include "util/log.h"

#include <stdlib.h> /* malloc(), calloc(), realloc(), free() */
#include <string.h> /* strdup() */

/**
 * Assert that the memory has been allocated.
 *
 */
static void*
se_assert_data(void* data)
{
    if (!data) {
        se_fatal_exit("memory allocation failed (se): out of memory");
    }
    return data;
}

/**
 * Calculate and allocate memory.
 *
 */
void*
se_calloc(size_t nmemb, size_t size)
{
    void* data = calloc(nmemb, size);
    return se_assert_data(data);
}

/**
 * Allocate memory.
 *
 */
void* se_malloc(size_t size)
{
    void* data = malloc(size);
    return se_assert_data(data);
}

/**
 * Free memory.
 *
 */
void
se_free(void* ptr)
{
    if (ptr) {
        free(ptr);
    }
}

/**
 * Reallocate memory.
 *
 */
void*
se_realloc(void* ptr, size_t size)
{
    void* data = realloc(ptr, size);
    return se_assert_data(data);
}

/**
 * Remove a node and all childs from a redblack tree.
 *
 */
void
se_rbnode_free(ldns_rbnode_t* node)
{
    if (node != LDNS_RBTREE_NULL) {
        se_rbnode_free(node->left);
        se_rbnode_free(node->right);
        free((void*)node);
    }
}

/**
 * Our own strdup.
 *
 */
char*
se_strdup(const char *s)
{
    char* dup = strdup(s);
    if (!dup) {
        se_fatal_exit("memory allocation failed (strdup): out of memory");
    }
    return dup;
}
