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

/* DB JOIN */



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

const db_join_t* db_join_next(const db_join_t* join) {
    if (!join) {
        return NULL;
    }

    return join->next;
}

/* DB JOIN LIST */



const db_join_t* db_join_list_begin(const db_join_list_t* join_list) {
    if (!join_list) {
        return NULL;
    }

    return join_list->begin;
}
