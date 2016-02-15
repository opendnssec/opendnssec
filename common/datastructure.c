/*
 * Copyright (c) 2015-2016 NLNet Labs. All rights reserved.
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
#include <assert.h>
#include <pthread.h>
#include "status.h"
#include "datastructure.h"

/*
 * By setting an environment variable OPENDNSSEC_OPTION_sigstore
 * this implementation will switch from old previous behavior
 * to a behavior where only the most recent collections (rrsets)
 * are kept in memory, and others are evicted to a file storage.
 *
 * The file is normally located in /var/opendnssec/signer/<zonename>.sigs
 * 
 * There are two major problems with this implementation, one is the 
 * fact that an environment variable is used as switch.  There is no
 * easy access to a configuration, from which to determine a cache size.
 * The cache size is also pretty insignificant.  As long as it is a number
 * of magnitude higher than the number of signer threads (e.g. 96 for 4
 * signer threads), it will function fine, where setting it higher, even a
 * lot higher does not significantly increase performance.  So it is possible
 * to hard code it to a reasonable high value (e.g. 1000).
 * 
 * Another problem is that the backing storage file will keep growing, and keep
 * getting sparser.  It would be a good idea to periodically (e.g. when
 * evaluating which signatures to keep and remove) re-create the file.
 * 
 * Some additional notes:
 * - items not on the linked list are presumed to be on disk.  These can also
 *   be recognized because the next and prev pointers of the structure point
 *   to the structure itself.
 * - note that an entire collection is in-memory or on-disk, even though it
 *   is a collection of items.
 * - In contrast however the member_{destroy,dispose,restore} methods are
 *   called on the individual items in the collection even though they are
 *   always all swapped in or out.
 */

struct collection_class_struct {
    FILE* store;
    pthread_mutex_t mutex;
    int (*member_destroy)(void* member);
    int (*member_dispose)(void* member, FILE*);
    int (*member_restore)(void* member, FILE*);
    int (*obtain)(collection_t);
    int (*release)(collection_t);
    /* double linked list of items that are in memory ("cached"), the
     * list must be non-circular and is LRU sorted */
    struct collection_instance_struct* first;
    struct collection_instance_struct* last;
    int count; /* current number of items in linked list */
    int cachesize; /* maximum size of number of elements in linked list */
};

struct collection_instance_struct {
    struct collection_class_struct* method;
    char* array; /* array with members */
    size_t size; /* member size in bytes */
    int iterator; /* index to current element when iterating */
    int count; /* number of members in array */
    long location; /* file offset where items in correction are stored when swapped out */
    /* double linked list when */
    struct collection_instance_struct* next;
    struct collection_instance_struct* prev;
};


/*
 * swap in a collection from on-disk storage to in-memory.
 */
static int
swapin(collection_t collection)
{
    int i;
    collection_class method = collection->method;
    if(fseek(method->store, collection->location, SEEK_SET))
        return 1;
    for(i=0; i<collection->count; i++) {
        if(method->member_restore(&collection->array[collection->size * i], method->store))
            return 1;
    }
    return 0;
}

/**
 *  swap out a collection to disk
 */
static int
swapout(collection_t collection)
{
    int i;
    collection_class method = collection->method;
    if(fseek(method->store, 0, SEEK_END)) {
        return 1;
    }
    collection->location = ftell(method->store);
    for(i=0; i<collection->count; i++) {
        if(method->member_dispose(&collection->array[collection->size * i], method->store)) {
            return 1;
        }
    }
    return 0;
}

/* Assure that the collection is entirely in-memory and not swapped out */
static int
obtain(collection_t collection)
{
    int needsswapin = 1;
    struct collection_instance_struct* least;
    collection_class method = collection->method;
    if(collection->count == 0)
        needsswapin = 0;
    if(method->first == collection) {
        /* most recent item optimization, nothing to do, shortcut */
        return;
    }
    pthread_mutex_lock(&method->mutex);
    if(collection != collection->next && collection->prev != NULL && collection->next != NULL) {
        /* item in contained in chain, hence already swapped in, but we need to update the
         * chain such it is still an LRU chain.  First remove from current position */
        method->count--;
        if(collection->next == NULL) {
            assert(method->last == collection);
            method->last = collection->prev;
        } else
            collection->next->prev = collection->prev;
        if(collection->prev == NULL) {
            assert(method->first == collection);
            method->first = collection->next;
        } else
            collection->prev->next = collection->next;
        needsswapin = 0; /* we do not need to retrieve from disk */
    }
    /* insert item in front of LRU chain */
    collection->next = method->first;
    if(method->first != NULL)
        method->first->prev = collection;
    method->first = collection;
    if(method->last == NULL)
        method->last = collection;
    collection->prev = NULL;
    method->count++;
    /* look whether threshold is exceeded, if so evict items from cache */
    while(method->count > method->cachesize) {
        least = method->last;
        swapout(least);
        method->count--;
        if(least->prev == NULL) {
            assert(method->first == least);
            method->first = NULL;
        } else
            least->prev->next = NULL;
        method->last = least->prev;
        least->prev = least;
        least->next = least;
    }
    pthread_mutex_unlock(&method->mutex);
    if(needsswapin) {
        swapin(collection);
    }
}

static int
release(collection_t collection)
{
    (void)collection;
    return 0;
}

/* Do nothing procedure as dummy for either obtain or release */
static int
noop(collection_t collection)
{
    (void)collection;
    return 0;
}

void
collection_class_create(collection_class* method, char* fname,
        int (*member_destroy)(void* member),
        int (*member_dispose)(void* member, FILE*),
        int (*member_restore)(void* member, FILE*))
{
    char* configoption;
    char* endptr;
    long cachesize;
    CHECKALLOC(*method = malloc(sizeof(struct collection_class_struct)));
    (*method)->member_destroy = member_destroy;
    (*method)->member_dispose = member_dispose;
    (*method)->member_restore = member_restore;
    (*method)->obtain = noop;
    (*method)->release = noop;
    (*method)->cachesize = -1;
    (*method)->count = 0;
    (*method)->first = NULL;
    (*method)->last = NULL;
    (*method)->store = NULL;
    configoption = getenv("OPENDNSSEC_OPTION_sigstore");
    if(configoption != NULL) {
        cachesize = strtol(configoption, &endptr, 0);
        if(endptr != configoption && cachesize > 0) {
            (*method)->store = fopen(fname, "w+");
            (*method)->cachesize = cachesize;
            pthread_mutex_init(&(*method)->mutex, NULL);
            (*method)->obtain = obtain;
            (*method)->release = release;
        }
    }
}

void
collection_class_destroy(collection_class* klass)
{
    if (klass == NULL)
        return;
    if((*klass)->store != NULL) {
        fclose((*klass)->store);
        if((*klass)->cachesize > 0)
            pthread_mutex_destroy(&(*klass)->mutex);
    }
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
    (*collection)->next = (*collection)->prev = *collection;
}

void
collection_destroy(collection_t* collection)
{
    int i;
    if(collection == NULL)
        return;
    for (i=0; i < (*collection)->count; i++) {
        (*collection)->method->member_destroy(&(*collection)->array[(*collection)->size * i]);
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
    collection_class method = collection->method;
    method->obtain(collection);
    CHECKALLOC(ptr = realloc(collection->array, (collection->count+1)*collection->size));
    collection->array = ptr;
    memcpy(collection->array + collection->size * collection->count, data, collection->size);
    collection->count += 1;
    method->release(collection);
}

void
collection_del_index(collection_t collection, int index)
{
    void* ptr;
    collection_class method = collection->method;
    if (index<0 || index >= collection->count)
        return;
    method->obtain(collection);
    method->member_destroy(&collection->array[collection->size * index]);
    collection->count -= 1;
    memmove(&collection->array[collection->size * index], &collection->array[collection->size * (index + 1)], (collection->count - index) * collection->size);
    if (collection->count > 0) {
        CHECKALLOC(ptr = realloc(collection->array, collection->count * collection->size));
        collection->array = ptr;
    } else {
        free(collection->array);
        collection->array = NULL;
    }
    method->release(collection);
}

void
collection_del_cursor(collection_t collection)
{
    collection_del_index(collection, collection->iterator);
}

void*
collection_iterator(collection_t collection)
{
    collection_class method = collection->method;
    if(collection->iterator < 0) {
        method->obtain(collection);
        collection->iterator = collection->count;
    }
    collection->iterator -= 1;
    if(collection->iterator >= 0) {
        return &collection->array[collection->iterator * collection->size];
    } else {
        method->release(collection);
        return NULL;
    }
}
