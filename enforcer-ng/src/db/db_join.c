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

#include "db_join.h"
#include "db_error.h"

#include <stdlib.h>
#include <string.h>

/* DB CLAUSE */

db_join_t* db_join_new(void) {
    db_join_t* join =
        (db_join_t*)calloc(1, sizeof(db_join_t));

    return join;
}

void db_join_free(db_join_t* join) {
    if (join) {
        if (join->from_table) {
            free(join->from_table);
        }
        if (join->from_field) {
            free(join->from_field);
        }
        if (join->to_table) {
            free(join->to_table);
        }
        if (join->to_field) {
            free(join->to_field);
        }
        free(join);
    }
}

const char* db_join_from_table(const db_join_t* join) {
    if (!join) {
        return NULL;
    }

    return join->from_table;
}

const char* db_join_from_field(const db_join_t* join) {
    if (!join) {
        return NULL;
    }

    return join->from_field;
}

const char* db_join_to_table(const db_join_t* join) {
    if (!join) {
        return NULL;
    }

    return join->to_table;
}

const char* db_join_to_field(const db_join_t* join) {
    if (!join) {
        return NULL;
    }

    return join->to_field;
}

int db_join_set_from_table(db_join_t* join, const char* from_table) {
    char* new_from_table;

    if (!join) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_from_table = strdup(from_table))) {
        return DB_ERROR_UNKNOWN;
    }

    if (join->from_table) {
        free(join->from_table);
    }
    join->from_table = new_from_table;
    return DB_OK;
}

int db_join_set_from_field(db_join_t* join, const char* from_field) {
    char* new_from_field;

    if (!join) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_from_field = strdup(from_field))) {
        return DB_ERROR_UNKNOWN;
    }

    if (join->from_field) {
        free(join->from_field);
    }
    join->from_field = new_from_field;
    return DB_OK;
}

int db_join_set_to_table(db_join_t* join, const char* to_table) {
    char* new_to_table;

    if (!join) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_to_table = strdup(to_table))) {
        return DB_ERROR_UNKNOWN;
    }

    if (join->to_table) {
        free(join->to_table);
    }
    join->to_table = new_to_table;
    return DB_OK;
}

int db_join_set_to_field(db_join_t* join, const char* to_field) {
    char* new_to_field;

    if (!join) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_to_field = strdup(to_field))) {
        return DB_ERROR_UNKNOWN;
    }

    if (join->to_field) {
        free(join->to_field);
    }
    join->to_field = new_to_field;
    return DB_OK;
}

int db_join_not_empty(const db_join_t* join) {
    if (!join) {
        return DB_ERROR_UNKNOWN;
    }
    if (!join->from_table) {
        return DB_ERROR_UNKNOWN;
    }
    if (!join->from_field) {
        return DB_ERROR_UNKNOWN;
    }
    if (!join->to_table) {
        return DB_ERROR_UNKNOWN;
    }
    if (!join->to_field) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

const db_join_t* db_join_next(const db_join_t* join) {
    if (!join) {
        return NULL;
    }

    return join->next;
}

/* DB CLAUSE LIST */

db_join_list_t* db_join_list_new(void) {
    db_join_list_t* join_list =
        (db_join_list_t*)calloc(1, sizeof(db_join_list_t));

    return join_list;
}

void db_join_list_free(db_join_list_t* join_list) {
    if (join_list) {
        if (join_list->begin) {
            db_join_t* this = join_list->begin;
            db_join_t* next = NULL;

            while (this) {
                next = this->next;
                db_join_free(this);
                this = next;
            }
        }
        free(join_list);
    }
}

int db_join_list_add(db_join_list_t* join_list, db_join_t* join) {
    if (!join_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!join) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_join_not_empty(join)) {
        return DB_ERROR_UNKNOWN;
    }
    if (join->next) {
        return DB_ERROR_UNKNOWN;
    }

    if (join_list->begin) {
        if (!join_list->end) {
            return DB_ERROR_UNKNOWN;
        }
        join_list->end->next = join;
        join_list->end = join;
    }
    else {
        join_list->begin = join;
        join_list->end = join;
    }

    return DB_OK;
}

const db_join_t* db_join_list_begin(const db_join_list_t* join_list) {
    if (!join_list) {
        return NULL;
    }

    return join_list->begin;
}
