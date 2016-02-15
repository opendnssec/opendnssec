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
 * Create a class of collections.  Collection classes define how collections
 * manage their internal storage.  Collections in the same class share storage
 * space.  In the current implementation the items stored in a single collection
 * are either all in memory or swapped out to an external file.
 * Which part of the items is swapped out to external memory can be controlled
 * by the given dispose and restore functions which are called on the individual
 * members of a collection.  When a collection is destroyed the given destroy
 * method is called in order to dispose of the linked memory.
 */
void collection_class_create(collection_class* klass, char* fname,
        int (*member_destroy)(void* member),
        int (*member_dispose)(void* member, FILE*),
        int (*member_restore)(void* member, FILE*));

/**
 * Destroyes the underlying collection class.  This also makes the collections
 * created with it unusable, but these should have been destroyed earlier.
 */
void collection_class_destroy(collection_class* klass);

/**
 * Creates and initialized an empty collection
 * \param[out] collection a reference to the collection to be initialized
 * \param[in] membsize the size as returned by sizeof() of the data elements stored
 * \param[in] klass the larger collection class this collection should be part of.
 */
void collection_create_array(collection_t* collection, size_t membsize, collection_class klass);

/**
 * Destroys a collection and calls the destructor method destroy on each of the
 * members in the collection.
 */
void collection_destroy(collection_t* collection);

/**
 * Adds an element to the collection by copying the data pointed to by the data pointer.
 */
void collection_add(collection_t collection, void* data);

/**
 * Removes the item number given by the index argument.  The items are implicitly numbered
 * in the order of being added.  When items are removed, the items are renumbered to again
 * form a consecutive list starting from 0.
 */
void collection_del_index(collection_t collection, int index);

/**
 * In case the collection_iterator() function is being used, deletes the current (latest
 * retrieved) member from the collection.
 */
void collection_del_cursor(collection_t collection);

/**
 * Iterate over the elements in a collection.  Upon the first call the first element in
 * the collection is returned.  After the final element NULL will be returned and the
 * iteration is reset such that the next time the iterator is called it behaves like it
 * was called from the first time.  It is save to add elements or delete the current item
 * using collection_del_cursor.  Usage of collection_del_index is not permitted.
 * It is also mandatory to iterate over the entire list, and it is not possible to short cut
 * the iteration.
void* collection_iterator(collection_t collection);

#endif /* UTIL_DATASTRUCTURE_H */
