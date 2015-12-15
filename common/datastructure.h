/*
 * Copyright (c) 2015 NLNet Labs. All rights reserved.
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

#ifndef UTIL_DATASTRUCTURE_H
#define UTIL_DATASTRUCTURE_H

#include "config.h"

struct collection_class_struct;
typedef struct collection_class_struct* collection_class;

struct collection_instance_struct;
typedef struct collection_instance_struct* collection_t;

/**
 * Creates and initialized an empty collection
 * \param[out] collection a reference to the collection to be initialized
 * \param[in] membsize the size as returned by sizeof() of the data elements stored
 */
void collection_create_array(collection_t* collection, size_t membsize, collection_class klass);

void collection_class_allocated(collection_class* klass, void *cargo,
        int (*member_destroy)(void* cargo, void* member));

void collection_class_backed(collection_class* klass, char* fname, void *cargo,
        int (*member_destroy)(void* cargo, void* member),
        int (*member_dispose)(void* cargo, void* member, FILE*),
        int (*member_restore)(void* cargo, void* member, FILE*));

void collection_class_destroy(collection_class* klass);

void collection_destroy(collection_t* collection);
void collection_add(collection_t collection, void* data);
void collection_del_index(collection_t collection, int index);
void collection_del_cursor(collection_t collection);
void* collection_iterator(collection_t collection);

#endif /* UTIL_DATASTRUCTURE_H */
