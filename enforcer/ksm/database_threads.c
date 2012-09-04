/*
 * $Id: database_connection_mysql.c 6326 2012-05-11 13:44:31Z jerry $
 *
 * Copyright (c) 2012 Jerry
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

#include "ksm/database.h"
#include "ksm/memory.h"

#ifdef KSM_DB_USE_THREADS

#include <pthread.h>

static int _db_setup = 0;
pthread_mutex_t _db_setup_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_key_t _key_db_handle;
static pthread_key_t _key_db_in_transaction;

int
DbThreadSetup(void)
{
	if (!_db_setup) {
		if (pthread_mutex_lock(&_db_setup_mutex)) {
			return -1;
		}

		if (!_db_setup) {
			if (pthread_key_create(&_key_db_handle, NULL)) {
				return -2;
			}
            if (pthread_key_create(&_key_db_in_transaction, NULL)) {
                return -2;
            }
			_db_setup = 1;
		}

		if (pthread_mutex_unlock(&_db_setup_mutex)) {
			return -3;
		}
	}

	return 0;
}

DB_HANDLE
DbThreadGetHandle(void)
{
	DB_HANDLE* ptr;

	if (DbThreadSetup()) {
		return NULL;
	}

	if ((ptr = pthread_getspecific(_key_db_handle)) == NULL) {
		return NULL;
	}

	return *ptr;
}

int
DbThreadSetHandle(DB_HANDLE handle)
{
	DB_HANDLE* ptr;

	if (DbThreadSetup()) {
		return -1;
	}

	if ((ptr = pthread_getspecific(_key_db_handle)) == NULL) {
		if ((ptr = MemMalloc(sizeof(DB_HANDLE))) == NULL) {
			return -2;
		}

		if (pthread_setspecific(_key_db_handle, ptr)) {
			MemFree(ptr);
			return -3;
		}
	}

	*ptr = handle;

	return 0;
}

int
DbThreadRemoveHandle(void)
{
	DB_HANDLE* ptr;

	if (DbThreadSetup()) {
		return -1;
	}

	ptr = pthread_getspecific(_key_db_handle);

	if (ptr) {
		*ptr = NULL;
	}

	return 0;
}

int
DbThreadGetInTransaction(void)
{
    int* ptr;

    if (DbThreadSetup()) {
        return NULL;
    }

    if ((ptr = pthread_getspecific(_key_db_in_transaction)) == NULL) {
        return NULL;
    }

    return *ptr;
}

int
DbThreadSetInTransaction(int in_transaction)
{
    int* ptr;

    if (DbThreadSetup()) {
        return -1;
    }

    if ((ptr = pthread_getspecific(_key_db_in_transaction)) == NULL) {
        if ((ptr = MemMalloc(sizeof(int))) == NULL) {
            return -2;
        }

        if (pthread_setspecific(_key_db_in_transaction, ptr)) {
            MemFree(ptr);
            return -3;
        }
    }

    *ptr = in_transaction;

    return 0;
}

int
DbThreadRemoveInTransaction(void)
{
    int* ptr;

    if (DbThreadSetup()) {
        return -1;
    }

    ptr = pthread_getspecific(_key_db_in_transaction);

    if (ptr) {
        *ptr = 0;
    }

    return 0;
}

#endif
