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
#include "status.h"
#include "datastructure.h"


struct collection_struct {
    void* array; /** array with members */
    size_t size; /** member size */
    int iterator;
    int count; /** number of members in array */
    void* cargo;
    void (*member_destroy)(void* cargo, void* member);
};

void
collection_create_array(collection_t* collection, size_t membsize, void* cargo, void (*member_destroy)(void* cargo, void* member))
{
    CHECKALLOC(*collection = malloc(sizeof(struct collection_struct)));
    (*collection)->size = membsize;
    (*collection)->count = 0;
    (*collection)->array = NULL;
    (*collection)->iterator = -1;
    (*collection)->cargo = cargo;
    (*collection)->member_destroy = member_destroy;
}

void
collection_destroy(collection_t* collection)
{
    int i;
    if(collection == NULL)
        return 0;
    for (i=0; i < (*collection)->count; i++) {
        (*collection)->member_destroy((*collection)->cargo, (*collection)->array + (*collection)->size * i);
    }
    free(*collection);
    *collection = NULL;
    return 0;
}

void
collection_add(collection_t collection, void *data)
{
    void* ptr;
    CHECKALLOC(ptr = realloc(collection->array, (collection->count+1)*collection->size));
    collection->array = ptr;
    memcpy(collection->array + collection->size * collection->count, data, collection->size);
    collection->count += 1;
}

void
collection_del_index(collection_t collection, int index)
{
    void* ptr;
    if (index<0 || index >= collection->count)
        return;
    collection->member_destroy(collection->cargo, collection->array + collection->size * index);
    memmove(collection->array + collection->size * index, &collection->array + collection->size * (index + 1), (collection->count - index) * collection->size);
    collection->count -= 1;
    if (collection->count > 0) {
        CHECKALLOC(ptr = realloc(collection->array, collection->count * collection->size));
        if (ptr == NULL) {
            return ENOMEM;
        }
        collection->array = ptr;
    } else {
        free(collection->array);
        collection->array = NULL;
    }
}

void
collection_del_cursor(collection_t collection)
{
    return collection_del_index(collection, collection->iterator);
}

void*
collection_iterator(collection_t collection)
{
    if(collection->iterator < 0) {
        collection->iterator = collection->count;
    }
    collection->iterator -= 1;
    if(collection->iterator >= 0) {
        return &collection->array[collection->iterator];
    } else {
        return NULL;
    }
}
