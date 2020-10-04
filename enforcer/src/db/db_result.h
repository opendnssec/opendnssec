/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
 * All rights reserved.
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

#ifndef __db_result_h
#define __db_result_h

struct db_result;
struct db_result_list;
typedef struct db_result db_result_t;
typedef struct db_result_list db_result_list_t;

/**
 * Function pointer for walking a db_result_list. The backend handle specific
 * data is supplied in `data` and setting `finish` to non-zero tells the backend
 * that we are finished with the db_result_list.
 * \param[in] data a void pointer for the backend specific data.
 * \param[in] finish an integer that if non-zero will tell the backend that we
 * are finished with the result list.
 * \return A pointer to the next db_result_t or NULL on error.
 */
typedef db_result_t* (*db_result_list_next_t)(void* data, int finish);

#include "db_value.h"
#include "db_backend.h"

/**
 * A container for a database result, the data in the result is represented by
 * a fixed size db_value_set_t.
 */
struct db_result {
    db_result_t* next;
    db_value_set_t* value_set;
};

/**
 * Create a new database result.
 * \return a db_result_t pointer or NULL on error.
 */
extern db_result_t* db_result_new(void);

/**
 * Create a new database result that is a copy of another.
 * \param[in] from_result a db_result_t pointer.
 * \return a db_result_t pointer or NULL on error.
 */
extern db_result_t* db_result_new_copy(const db_result_t* from_result);

/**
 * Delete a database result and the backend meta data list if set.
 * \param[in] result a db_result_t pointer.
 */
extern void db_result_free(db_result_t* result);

/**
 * Copy the content of another database result.
 * \param[in] result a db_result_t pointer.
 * \param[in] from_result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_result_copy(db_result_t* result, const db_result_t* from_result);

/**
 * Get the value set of a database result.
 * \param[in] result a db_result_t pointer.
 * \return a db_value_set_t pointer or NULL on error or if no value set has
 * been set.
 */
extern const db_value_set_t* db_result_value_set(const db_result_t* result);

/**
 * Set the value set of a database result.
 * \param[in] result a db_result_t pointer.
 * \param[in] value_set a db_value_set_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_result_set_value_set(db_result_t* result, db_value_set_t* value_set);

/**
 * Check if a database result is not empty.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* if empty, otherwise DB_OK.
 */
extern int db_result_not_empty(const db_result_t* result);

/**
 * A list of database results.
 */
struct db_result_list {
    db_result_t* begin;
    db_result_t* end;
    db_result_t* current;
    db_result_list_next_t next_function;
    void* next_data;
    size_t size;
    int begun;
};

/**
 * Create a new database result list.
 * \return a db_result_list_t pointer or NULL on error.
 */
extern db_result_list_t* db_result_list_new(void);

/**
 * Create a new database result list that is a copy of another.
 * \param[in] from_result_list a db_result_list_t pointer.
 * \return a db_result_list_t pointer or NULL on error.
 */
extern db_result_list_t* db_result_list_new_copy(const db_result_list_t* from_result_list);

/**
 * Delete a database result list and all database results within the list.
 * \param[in] result_list a db_result_list_t pointer.
 */
extern void db_result_list_free(db_result_list_t* result_list);

/**
 * free global allocator. 
 * db_result_list_free MUST be called for all its contents.
 */
/**
 * Copy the content of another database result list.
 * \param[in] result_list a db_result_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_result_list_copy(db_result_list_t* result_list, const db_result_list_t* from_result_list);

/**
 * Set the function pointer for fetching the next database result for a database
 * result list. The backend handle specific data is supplied in `next_data`
 * along with the total size of the result list in `size`.
 * \param[in] result_list a db_result_list_t pointer.
 * \param[in] next_function a db_result_list_next_t function pointer.
 * \param[in] next_data a void pointer.
 * \param[in] size a size_t.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_result_list_set_next(db_result_list_t* result_list, db_result_list_next_t next_function, void* next_data, size_t size);

/**
 * Add a database result to a database result list, this will takes over the
 * ownership of the database result.
 * \param[in] result_list a db_result_list_t pointer.
 * \param[in] result a db_result_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_result_list_add(db_result_list_t* result_list, db_result_t* result);

/**
 * Return the first database result in a database result list and reset the
 * position of the list.
 * \param[in] result_list a db_result_list_t pointer.
 * \return a db_result_t pointer or NULL on error or if the list is empty.
 */
extern const db_result_t* db_result_list_begin(db_result_list_t* result_list);

/**
 * Return the next database result in a database result list.
 * \param[in] result_list a db_result_list_t pointer.
 * \return a db_result_t pointer or NULL on error or if the end of the list has
 * been reached.
 */
extern const db_result_t* db_result_list_next(db_result_list_t* result_list);

/**
 * Return the size of the database result list.
 * \param[in] result_list a db_result_list_t pointer.
 * \return a size_t with the size of the database result list or zero on error
 * , if the database result list is empty or if the backend does not support
 * returning the size.
 */
extern size_t db_result_list_size(const db_result_list_t* result_list);

/**
 * Make sure that all objects in this database result list is loaded into memory
 * so that db_result_list_begin() can be used to iterate over the list multiple
 * times.
 * \param[in] result_list a db_result_list_t pointer.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int db_result_list_fetch_all(db_result_list_t* result_list);

#endif
