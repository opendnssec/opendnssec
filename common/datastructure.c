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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "status.h"
#include "datastructure.h"

struct collection_class_struct {
    FILE* store;
    void* cargo;
    int (*member_destroy)(void* cargo, void* member);
    int (*member_dispose)(void* cargo, void* member, FILE*);
    int (*member_restore)(void* cargo, void* member, FILE*);
};

struct collection_instance_struct {
    struct collection_class_struct* method;
    char* array; /** array with members */
    size_t size; /** member size */
    int iterator;
    int count; /** number of members in array */
    long location;
};

static int
swapin(collection_t collection)
{
    int i;
    if(collection->count > 0) {
        if(fseek(collection->method->store, collection->location, SEEK_SET))
            return 1;
        for(i=0; i<collection->count; i++) {
            if(collection->method->member_restore(collection->method->cargo,
                    collection->array + collection->size * i, collection->method->store))
                return 1;
        }
    }
    return 0;
}

static int
swapout(collection_t collection)
{
    int i;
    if(collection->count > 0) {
        if(fseek(collection->method->store, 0, SEEK_END))
            return 1;
        collection->location = ftell(collection->method->store);
        for(i=0; i<collection->count; i++) {
            if(collection->method->member_dispose(collection->method->cargo,
                    collection->array + collection->size * i, collection->method->store))
                return 1;
        }
    }
    return 0;
}

void
collection_class_allocated(collection_class* klass, void *cargo,
        int (*member_destroy)(void* cargo, void* member))
{
    CHECKALLOC(*klass = malloc(sizeof(struct collection_class_struct)));
    (*klass)->cargo = cargo;
    (*klass)->member_destroy = member_destroy;
    (*klass)->member_dispose = NULL;
    (*klass)->member_restore = NULL;
    (*klass)->store = NULL;
}

void
collection_class_backed(collection_class* klass, char* fname, void *cargo,
        int (*member_destroy)(void* cargo, void* member),
        int (*member_dispose)(void* cargo, void* member, FILE*),
        int (*member_restore)(void* cargo, void* member, FILE*))
{
    CHECKALLOC(*klass = malloc(sizeof(struct collection_class_struct)));
    (*klass)->cargo = cargo;
    (*klass)->member_destroy = member_destroy;
    (*klass)->member_dispose = member_dispose;
    (*klass)->member_restore = member_restore;
    (*klass)->store = fopen(fname, "w+");
}

void
collection_class_destroy(collection_class* klass)
{
    if (klass == NULL)
        return;
    free(*klass);
    *klass = NULL;
}

void
collection_create_array(collection_t* collection, size_t membsize,
        collection_class klass)
{
    CHECKALLOC(*collection = malloc(sizeof(struct collection_instance_struct)));
    (*collection)->size = membsize;
    (*collection)->count = 0;
    (*collection)->array = NULL;
    (*collection)->iterator = -1;
    (*collection)->method = klass;
}

void
collection_destroy(collection_t* collection)
{
    int i;
    if(collection == NULL)
        return;
    for (i=0; i < (*collection)->count; i++) {
        (*collection)->method->member_destroy((*collection)->method->cargo,
                &(*collection)->array[(*collection)->size * i]);
    }
    if((*collection)->array)
        free((*collection)->array);
    free(*collection);
    *collection = NULL;
}

void
collection_add(collection_t collection, void *data)
{
    void* ptr;
    if(collection->method->store)
        swapin(collection);
    CHECKALLOC(ptr = realloc(collection->array, (collection->count+1)*collection->size));
    collection->array = ptr;
    memcpy(&collection->array[collection->size * collection->count], data, collection->size);
    collection->count += 1;
    if(collection->method->store)
        swapout(collection);
}

void
collection_del_index(collection_t collection, int index)
{
    void* ptr;
    if (index<0 || index >= collection->count)
        return;
    if(collection->method->store)
        swapin(collection);
    collection->method->member_destroy(collection->method->cargo, &collection->array[collection->size * index]);
    collection->count -= 1;
    memmove(&collection->array[collection->size * index], &collection->array[collection->size * (index + 1)], (collection->count - index) * collection->size);
    if (collection->count > 0) {
        CHECKALLOC(ptr = realloc(collection->array, collection->count * collection->size));
        collection->array = ptr;
    } else {
        free(collection->array);
        collection->array = NULL;
    }
    if(collection->method->store)
        swapout(collection);
}

void
collection_del_cursor(collection_t collection)
{
    collection_del_index(collection, collection->iterator);
}

void*
collection_iterator(collection_t collection)
{
    if(collection->iterator < 0) {
        if(collection->method->store)
            swapin(collection);
        collection->iterator = collection->count;
    }
    collection->iterator -= 1;
    if(collection->iterator >= 0) {
        return &collection->array[collection->iterator * collection->size];
    } else {
        if(collection->method->store)
            swapout(collection);
        return NULL;
    }
}
