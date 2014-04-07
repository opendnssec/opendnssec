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

#include "db_result.h"
#include "db_error.h"

#include "mm.h"

/* DB RESULT */

static mm_alloc_t __result_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_result_t));

db_result_t* db_result_new(void) {
    db_result_t* result =
        (db_result_t*)mm_alloc_new0(&__result_alloc);

    return result;
}

void db_result_free(db_result_t* result) {
    if (result) {
        if (result->value_set) {
            db_value_set_free(result->value_set);
        }
        if (result->backend_meta_data_list) {
            db_backend_meta_data_list_free(result->backend_meta_data_list);
        }
        mm_alloc_delete(&__result_alloc, result);
    }
}

const db_value_set_t* db_result_value_set(const db_result_t* result) {
    if (!result) {
        return NULL;
    }

    return result->value_set;
}

const db_backend_meta_data_list_t* db_result_backend_meta_data_list(const db_result_t* result) {
    if (!result) {
        return NULL;
    }

    return result->backend_meta_data_list;
}

int db_result_set_value_set(db_result_t* result, db_value_set_t* value_set) {
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }
    if (!value_set) {
        return DB_ERROR_UNKNOWN;
    }
    if (result->value_set) {
        return DB_ERROR_UNKNOWN;
    }

    result->value_set = value_set;
    return DB_OK;
}

int db_result_set_backend_meta_data_list(db_result_t* result, db_backend_meta_data_list_t* backend_meta_data_list) {
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_meta_data_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (result->backend_meta_data_list) {
        return DB_ERROR_UNKNOWN;
    }

    result->backend_meta_data_list = backend_meta_data_list;
    return DB_OK;
}

int db_result_not_empty(const db_result_t* result) {
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result->value_set) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

/* DB RESULT LIST */

static mm_alloc_t __result_list_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_result_list_t));

db_result_list_t* db_result_list_new(void) {
    db_result_list_t* result_list =
        (db_result_list_t*)mm_alloc_new0(&__result_list_alloc);

    return result_list;
}

void db_result_list_free(db_result_list_t* result_list) {
    if (result_list) {
        if (result_list->begin) {
            db_result_t* this = result_list->begin;
            db_result_t* next = NULL;

            while (this) {
                next = this->next;
                db_result_free(this);
                this = next;
            }
        }
        if (result_list->next_function) {
            (void)result_list->next_function(result_list->next_data, 1);
            if (result_list->current) {
                db_result_free(result_list->current);
            }
        }
        mm_alloc_delete(&__result_list_alloc, result_list);
    }
}

int db_result_list_set_next(db_result_list_t* result_list, db_result_list_next_t next_function, void* next_data) {
    if (!result_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (result_list->begin) {
        return DB_ERROR_UNKNOWN;
    }
    if (result_list->next_function) {
        return DB_ERROR_UNKNOWN;
    }
    if (!next_data) {
        return DB_ERROR_UNKNOWN;
    }
    if (result_list->next_data) {
        return DB_ERROR_UNKNOWN;
    }

    result_list->next_function = next_function;
    result_list->next_data = next_data;
    return 0;
}

int db_result_list_add(db_result_list_t* result_list, db_result_t* result) {
    if (!result_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!result) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_result_not_empty(result)) {
        return DB_ERROR_UNKNOWN;
    }
    if (result->next) {
        return DB_ERROR_UNKNOWN;
    }
    if (result_list->next_function) {
        return DB_ERROR_UNKNOWN;
    }

    if (result_list->begin) {
        if (!result_list->end) {
            return DB_ERROR_UNKNOWN;
        }
        result_list->end->next = result;
        result_list->end = result;
    }
    else {
        result_list->begin = result;
        result_list->end = result;
    }

    return DB_OK;
}

const db_result_t* db_result_list_begin(db_result_list_t* result_list) {
    if (!result_list) {
        return NULL;
    }

    if (result_list->next_function) {
        if (result_list->current) {
            db_result_free(result_list->current);
        }
        result_list->current = result_list->next_function(result_list->next_data, 0);
        return result_list->current;
    }

    result_list->current = result_list->begin;
    return result_list->current;
}

const db_result_t* db_result_list_next(db_result_list_t* result_list) {
    if (!result_list) {
        return NULL;
    }

    if (result_list->next_function) {
        if (result_list->current) {
            db_result_free(result_list->current);
        }
        result_list->current = result_list->next_function(result_list->next_data, 0);
        return result_list->current;
    }

    if (result_list->current) {
        result_list->current = result_list->current->next;
    }
    return result_list->current;
}
