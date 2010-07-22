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

#ifndef UTIL_SE_MALLOC_H
#define UTIL_SE_MALLOC_H

#include "config.h"

#include <stdlib.h>
#include <stdint.h>
#include <ldns/rbtree.h>

/**
 * Our own malloc.
 * \param[in] size the size to allocate
 * \return void* pointer to the allocated data
 *
 */
void* se_malloc(size_t size);

/**
 * Our own calloc.
 * \param[in] nmemb number of memory blocks.
 * \param[in] size the size to allocate
 * \return void* pointer to the allocated data
 */
void* se_calloc(size_t nmemb, size_t size);

/**
 * Our own realloc.
 * \param[in] pointer to be reallocated.
 * \param[in] size the size to allocate
 * \return void* pointer to the allocated data
 */
void* se_realloc(void* ptr, size_t size);

/**
 * Our own free.
 * \param[in] pointer to be free'd
 */
void se_free(void* ptr);

/**
 * Free a ldns rbnode.
 * \param[in] rbnode to be free'd
 */
void se_rbnode_free(ldns_rbnode_t* node);

/**
 * Our own strdup.
 * \param[in] s string to duplicate
 * \return char* duplicated string
 *
 */
char* se_strdup(const char* s);

#endif /* UTIL_SE_MALLOC_H */
