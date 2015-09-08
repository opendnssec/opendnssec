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
#include <assert.h>

/* DB JOIN */

void db_join_free(db_join_t* join)
{
    if (!join) return;
    free(join->from_table);
    free(join->from_field);
    free(join->to_table);
    free(join->to_field);
    free(join);
}

int db_join_set_from_table(db_join_t* join, const char* from_table)
{
    char *new_from_table;

    assert(join);
    assert(from_table);

    if(!(new_from_table = strdup(from_table)))
        return DB_ERROR_UNKNOWN;

    free(join->from_table);
    join->from_table = new_from_table;
    return DB_OK;
}

int db_join_set_from_field(db_join_t* join, const char* from_field)
{
    char *new_from_field;

    assert(join);
    assert(from_field);

    if(!(new_from_field = strdup(from_field)))
        return DB_ERROR_UNKNOWN;

    free(join->from_field);
    join->from_field = new_from_field;
    return DB_OK;
}

int db_join_set_to_table(db_join_t* join, const char* to_table)
{
    char *new_to_table;

    assert(join);
    assert(to_table);

    if(!(new_to_table = strdup(to_table)))
        return DB_ERROR_UNKNOWN;

    free(join->to_table);
    join->to_table = new_to_table;
    return DB_OK;
}

int db_join_set_to_field(db_join_t* join, const char* to_field)
{
    char *new_to_field;

    assert(join);
    assert(to_field);

    if(!(new_to_field = strdup(to_field)))
        return DB_ERROR_UNKNOWN;

    free(join->to_field);
    join->to_field = new_to_field;
    return DB_OK;
}

int db_join_not_empty(const db_join_t* join)
{
    return join && join->from_table && join->from_field
            && join->to_table && join->to_field;
}

/* DB JOIN LIST */

void db_join_list_free(db_join_list_t* join_list)
{
    if (!join_list) return;
    while (join_list->begin) {
        db_join_t* next = join_list->begin->next;
        db_join_free(join_list->begin);
        join_list->begin = next;
    }
    free(join_list);
}

int db_join_list_add(db_join_list_t* join_list, db_join_t* join)
{
    if (!join_list || !join || db_join_not_empty(join) || join->next)
        return DB_ERROR_UNKNOWN;

    if (join_list->begin) {
        if (!join_list->end) {
            return DB_ERROR_UNKNOWN;
        }
        join_list->end->next = join;
        join_list->end = join;
    } else {
        join_list->begin = join;
        join_list->end = join;
    }

    return DB_OK;
}
