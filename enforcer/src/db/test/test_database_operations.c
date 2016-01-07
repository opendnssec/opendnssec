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

#include "config.h"

#include "../db_configuration.h"
#include "../db_connection.h"
#include "../db_object.h"

#include "CUnit/Basic.h"
#include <string.h>

typedef struct {
    db_object_t* dbo;
    db_value_t* id;
    char* name;
} test_t;

typedef struct {
    db_object_t* dbo;
    db_result_list_t* result_list;
    test_t* test;
} test_list_t;

static db_configuration_list_t* configuration_list = NULL;
static db_configuration_t* configuration = NULL;
static db_connection_t* connection = NULL;
static test_t* test = NULL;
static test_list_t* test_list = NULL;
static db_value_t object2_id, object3_id;

db_object_t* __test_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    CU_ASSERT_PTR_NOT_NULL_FATAL((object = db_object_new()));

    CU_ASSERT_FATAL(!db_object_set_connection(object, connection));
    CU_ASSERT_FATAL(!db_object_set_table(object, "test"));
    CU_ASSERT_FATAL(!db_object_set_primary_key_name(object, "id"));

    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field_list = db_object_field_list_new()));

    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field = db_object_field_new()));
    CU_ASSERT_FATAL(!db_object_field_set_name(object_field, "id"));
    CU_ASSERT_FATAL(!db_object_field_set_type(object_field, DB_TYPE_PRIMARY_KEY));
    CU_ASSERT_FATAL(!db_object_field_list_add(object_field_list, object_field));

    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field = db_object_field_new()));
    CU_ASSERT_FATAL(!db_object_field_set_name(object_field, "name"));
    CU_ASSERT_FATAL(!db_object_field_set_type(object_field, DB_TYPE_TEXT));
    CU_ASSERT_FATAL(!db_object_field_list_add(object_field_list, object_field));

    CU_ASSERT_FATAL(!db_object_set_object_field_list(object, object_field_list));

    return object;
}

test_t* test_new(const db_connection_t* connection) {
    test_t* test =
        (test_t*)calloc(1, sizeof(test_t));

    if (test) {
        CU_ASSERT_PTR_NOT_NULL_FATAL((test->dbo = __test_new_object(connection)));
        CU_ASSERT_PTR_NOT_NULL_FATAL((test->id = db_value_new()));
    }

    return test;
}

void test_free(test_t* test) {
    if (test) {
        if (test->dbo) {
            db_object_free(test->dbo);
        }
        if (test->id) {
            db_value_free(test->id);
        }
        if (test->name) {
            free(test->name);
        }
        free(test);
    }
}

const db_value_t* test_id(const test_t* test) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(test);

    return test->id;
}

const char* test_name(const test_t* test) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(test);

    return test->name;
}

int test_set_name(test_t* test, const char *name) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(test);
    CU_ASSERT_PTR_NOT_NULL_FATAL(name);

    if (test->name) {
        free(test->name);
    }
    test->name = strdup(name);
    CU_ASSERT_PTR_NOT_NULL_FATAL(test->name);
    return 0;
}

int test_from_result(test_t* test, const db_result_t* result) {
    const db_value_set_t* value_set;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test);
    CU_ASSERT_PTR_NOT_NULL_FATAL(result);

    db_value_reset(test->id);
    if (test->name) {
        free(test->name);
    }
    test->name = NULL;

    value_set = db_result_value_set(result);

    CU_ASSERT_PTR_NOT_NULL_FATAL(value_set);
    CU_ASSERT_FATAL(db_value_set_size(value_set) == 2);
    CU_ASSERT_FATAL(!db_value_copy(test->id, db_value_set_at(value_set, 0)));
    CU_ASSERT_FATAL(!db_value_to_text(db_value_set_at(value_set, 1), &(test->name)));
    return 0;
}

int test_get_by_name(test_t* test, const char* name) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;
    int ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test);
    CU_ASSERT_PTR_NOT_NULL_FATAL(name);

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause = db_clause_new()));
    CU_ASSERT_FATAL(!db_clause_set_field(clause, "name"));
    CU_ASSERT_FATAL(!db_clause_set_type(clause, DB_CLAUSE_EQUAL));
    CU_ASSERT_FATAL(!db_value_from_text(db_clause_get_value(clause), name));
    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause));
    clause = NULL;

    ret = 1;
    result_list = db_object_read(test->dbo, NULL, clause_list);
    if (result_list) {
        result = db_result_list_next(result_list);
        if (result) {
            test_from_result(test, result);
            ret = 0;
        }
        CU_ASSERT_PTR_NULL((result = db_result_list_next(result_list)));
        if (result) {
            db_result_list_free(result_list);
            db_clause_list_free(clause_list);
            return 1;
        }
    }

    db_result_list_free(result_list);
    db_clause_list_free(clause_list);
    db_clause_free(clause);
    return ret;
}

int test_get_by_id(test_t* test, const db_value_t* id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;
    int ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test);
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause = db_clause_new()));
    CU_ASSERT_FATAL(!db_clause_set_field(clause, "id"));
    CU_ASSERT_FATAL(!db_clause_set_type(clause, DB_CLAUSE_EQUAL));
    CU_ASSERT_FATAL(!db_value_copy(db_clause_get_value(clause), id));
    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause));
    clause = NULL;

    ret = 1;
    result_list = db_object_read(test->dbo, NULL, clause_list);
    if (result_list) {
        result = db_result_list_next(result_list);
        if (result) {
            test_from_result(test, result);
            ret = 0;
        }
        CU_ASSERT_PTR_NULL((result = db_result_list_next(result_list)));
        if (result) {
            db_result_list_free(result_list);
            db_clause_list_free(clause_list);
            return 1;
        }
    }

    db_result_list_free(result_list);
    db_clause_list_free(clause_list);
    db_clause_free(clause);
    return ret;
}

int test_create(test_t* test) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_value_t* value;
    int ret = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test);
    CU_ASSERT_FATAL(db_value_not_empty(test->id));
    CU_ASSERT_PTR_NOT_NULL_FATAL(test->name);

    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field_list = db_object_field_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field = db_object_field_new()));
    CU_ASSERT_FATAL(!db_object_field_set_name(object_field, "name"));
    CU_ASSERT_FATAL(!db_object_field_set_type(object_field, DB_TYPE_TEXT));
    CU_ASSERT_FATAL(!db_object_field_list_add(object_field_list, object_field));
    object_field = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((value_set = db_value_set_new(1)));
    CU_ASSERT_PTR_NOT_NULL_FATAL((value = db_value_set_get(value_set, 0)));
    CU_ASSERT_FATAL(!db_value_from_text(value, test->name));

    if (db_object_create(test->dbo, object_field_list, value_set)) {
        ret = 1;
    }

    db_value_set_free(value_set);
    db_object_field_free(object_field);
    db_object_field_list_free(object_field_list);
    CU_ASSERT(!ret);
    return ret;
}

int test_update(test_t* test) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_value_t* value;
    int ret = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test);
    CU_ASSERT_FATAL(!db_value_not_empty(test->id));
    CU_ASSERT_PTR_NOT_NULL_FATAL(test->name);

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause = db_clause_new()));
    CU_ASSERT_FATAL(!db_clause_set_field(clause, "id"));
    CU_ASSERT_FATAL(!db_clause_set_type(clause, DB_CLAUSE_EQUAL));
    CU_ASSERT_FATAL(!db_value_copy(db_clause_get_value(clause), test->id));
    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause));
    clause = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field_list = db_object_field_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field = db_object_field_new()));
    CU_ASSERT_FATAL(!db_object_field_set_name(object_field, "name"));
    CU_ASSERT_FATAL(!db_object_field_set_type(object_field, DB_TYPE_TEXT));
    CU_ASSERT_FATAL(!db_object_field_list_add(object_field_list, object_field));
    object_field = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((value_set = db_value_set_new(1)));
    CU_ASSERT_PTR_NOT_NULL_FATAL((value = db_value_set_get(value_set, 0)));
    CU_ASSERT_FATAL(!db_value_from_text(value, test->name));

    if (db_object_update(test->dbo, object_field_list, value_set, clause_list)) {
        ret = 1;
    }

    db_clause_list_free(clause_list);
    db_clause_free(clause);
    db_value_set_free(value_set);
    db_object_field_free(object_field);
    db_object_field_list_free(object_field_list);
    CU_ASSERT(!ret);
    return ret;
}

int test_delete(test_t* test) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test);
    CU_ASSERT_FATAL(!db_value_not_empty(test->id));

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause = db_clause_new()));
    CU_ASSERT_FATAL(!db_clause_set_field(clause, "id"));
    CU_ASSERT_FATAL(!db_clause_set_type(clause, DB_CLAUSE_EQUAL));
    CU_ASSERT_FATAL(!db_value_copy(db_clause_get_value(clause), test->id));
    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause));
    clause = NULL;

    if (db_object_delete(test->dbo, clause_list)) {
        ret = 1;
    }

    db_clause_list_free(clause_list);
    db_clause_free(clause);
    CU_ASSERT(!ret);
    return ret;
}

size_t test_count_by_name(test_t* test, const char* name) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    size_t ret = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test);
    CU_ASSERT_PTR_NOT_NULL_FATAL(name);

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause = db_clause_new()));
    CU_ASSERT_FATAL(!db_clause_set_field(clause, "name"));
    CU_ASSERT_FATAL(!db_clause_set_type(clause, DB_CLAUSE_EQUAL));
    CU_ASSERT_FATAL(!db_value_from_text(db_clause_get_value(clause), name));
    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause));
    clause = NULL;

    CU_ASSERT(!db_object_count(test->dbo, NULL, clause_list, &ret));

    db_clause_list_free(clause_list);
    db_clause_free(clause);
    return ret;
}

size_t test_count_by_id(test_t* test, const db_value_t* id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    size_t ret = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test);
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause = db_clause_new()));
    CU_ASSERT_FATAL(!db_clause_set_field(clause, "id"));
    CU_ASSERT_FATAL(!db_clause_set_type(clause, DB_CLAUSE_EQUAL));
    CU_ASSERT_FATAL(!db_value_copy(db_clause_get_value(clause), id));
    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause));
    clause = NULL;

    CU_ASSERT(!db_object_count(test->dbo, NULL, clause_list, &ret));

    db_clause_list_free(clause_list);
    db_clause_free(clause);
    return ret;
}

test_list_t* test_list_new(const db_connection_t* connection) {
    test_list_t* test_list =
        (test_list_t*)calloc(1, sizeof(test_list_t));

    if (test_list) {
        CU_ASSERT_PTR_NOT_NULL_FATAL((test_list->dbo = __test_new_object(connection)));
    }

    return test_list;
}

void test_list_free(test_list_t* test_list) {
    if (test_list) {
        if (test_list->dbo) {
            db_object_free(test_list->dbo);
        }
        if (test_list->result_list) {
            db_result_list_free(test_list->result_list);
        }
        if (test_list->test) {
            test_free(test_list->test);
        }
        free(test_list);
    }
}

int test_list_get(test_list_t* test_list) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(test_list);
    CU_ASSERT_PTR_NOT_NULL_FATAL(test_list->dbo);

    if (test_list->result_list) {
        db_result_list_free(test_list->result_list);
    }
    CU_ASSERT_PTR_NOT_NULL((test_list->result_list = db_object_read(test_list->dbo, NULL, NULL)));
    if (!test_list->result_list) {
        return 1;
    }
    return 0;
}

const test_t* test_list_begin(test_list_t* test_list) {
    const db_result_t* result;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test_list);
    CU_ASSERT_PTR_NOT_NULL_FATAL(test_list->result_list);

    result = db_result_list_next(test_list->result_list);
    if (!result) {
        return NULL;
    }
    if (!test_list->test) {
        CU_ASSERT_PTR_NOT_NULL_FATAL((test_list->test = test_new(db_object_connection(test_list->dbo))));
    }
    if (test_from_result(test_list->test, result)) {
        return NULL;
    }
    return test_list->test;
}

const test_t* test_list_next(test_list_t* test_list) {
    const db_result_t* result;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test_list);

    result = db_result_list_next(test_list->result_list);
    if (!result) {
        return NULL;
    }
    if (!test_list->test) {
        CU_ASSERT_PTR_NOT_NULL_FATAL((test_list->test = test_new(db_object_connection(test_list->dbo))));
    }
    if (test_from_result(test_list->test, result)) {
        return NULL;
    }
    return test_list->test;
}

typedef struct {
    db_object_t* dbo;
    db_value_t* id;
    db_value_t* rev;
    char* name;
} test2_t;

static test2_t* test2 = NULL;
static test2_t* test2_2 = NULL;

db_object_t* __test2_new_object(const db_connection_t* connection) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_object_t* object;

    CU_ASSERT_PTR_NOT_NULL_FATAL((object = db_object_new()));

    CU_ASSERT_FATAL(!db_object_set_connection(object, connection));
    CU_ASSERT_FATAL(!db_object_set_table(object, "test2"));
    CU_ASSERT_FATAL(!db_object_set_primary_key_name(object, "id"));

    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field_list = db_object_field_list_new()));

    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field = db_object_field_new()));
    CU_ASSERT_FATAL(!db_object_field_set_name(object_field, "id"));
    CU_ASSERT_FATAL(!db_object_field_set_type(object_field, DB_TYPE_PRIMARY_KEY));
    CU_ASSERT_FATAL(!db_object_field_list_add(object_field_list, object_field));

    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field = db_object_field_new()));
    CU_ASSERT_FATAL(!db_object_field_set_name(object_field, "rev"));
    CU_ASSERT_FATAL(!db_object_field_set_type(object_field, DB_TYPE_REVISION));
    CU_ASSERT_FATAL(!db_object_field_list_add(object_field_list, object_field));

    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field = db_object_field_new()));
    CU_ASSERT_FATAL(!db_object_field_set_name(object_field, "name"));
    CU_ASSERT_FATAL(!db_object_field_set_type(object_field, DB_TYPE_TEXT));
    CU_ASSERT_FATAL(!db_object_field_list_add(object_field_list, object_field));

    CU_ASSERT_FATAL(!db_object_set_object_field_list(object, object_field_list));

    return object;
}

test2_t* test2_new(const db_connection_t* connection) {
    test2_t* test2 =
        (test2_t*)calloc(1, sizeof(test2_t));

    if (test2) {
        CU_ASSERT_PTR_NOT_NULL_FATAL((test2->dbo = __test2_new_object(connection)));
        CU_ASSERT_PTR_NOT_NULL_FATAL((test2->id = db_value_new()));
        CU_ASSERT_PTR_NOT_NULL_FATAL((test2->rev = db_value_new()));
    }

    return test2;
}

void test2_free(test2_t* test2) {
    if (test2) {
        if (test2->dbo) {
            db_object_free(test2->dbo);
        }
        if (test2->id) {
            db_value_free(test2->id);
        }
        if (test2->rev) {
            db_value_free(test2->rev);
        }
        if (test2->name) {
            free(test2->name);
        }
        free(test2);
    }
}

const db_value_t* test2_id(const test2_t* test2) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(test2);

    return test2->id;
}

const char* test2_name(const test2_t* test2) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(test2);

    return test2->name;
}

int test2_set_name(test2_t* test2, const char *name) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(test2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(name);

    if (test2->name) {
        free(test2->name);
    }
    test2->name = strdup(name);
    CU_ASSERT_PTR_NOT_NULL_FATAL(test2->name);
    return 0;
}

int test2_from_result(test2_t* test2, const db_result_t* result) {
    const db_value_set_t* value_set;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(result);

    db_value_reset(test2->id);
    db_value_reset(test2->rev);
    if (test2->name) {
        free(test2->name);
    }
    test2->name = NULL;

    value_set = db_result_value_set(result);

    CU_ASSERT_PTR_NOT_NULL_FATAL(value_set);
    CU_ASSERT_FATAL(db_value_set_size(value_set) == 3);
    CU_ASSERT_FATAL(!db_value_copy(test2->id, db_value_set_at(value_set, 0)));
    CU_ASSERT_FATAL(!db_value_copy(test2->rev, db_value_set_at(value_set, 1)));
    CU_ASSERT_FATAL(!db_value_to_text(db_value_set_at(value_set, 2), &(test2->name)));
    return 0;
}

int test2_get_by_name(test2_t* test2, const char* name) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;
    int ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(name);

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause = db_clause_new()));
    CU_ASSERT_FATAL(!db_clause_set_field(clause, "name"));
    CU_ASSERT_FATAL(!db_clause_set_type(clause, DB_CLAUSE_EQUAL));
    CU_ASSERT_FATAL(!db_value_from_text(db_clause_get_value(clause), name));
    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause));
    clause = NULL;

    ret = 1;
    result_list = db_object_read(test2->dbo, NULL, clause_list);
    if (result_list) {
        result = db_result_list_next(result_list);
        if (result) {
            test2_from_result(test2, result);
            ret = 0;
        }
        CU_ASSERT_PTR_NULL((result = db_result_list_next(result_list)));
        if (result) {
            db_result_list_free(result_list);
            db_clause_list_free(clause_list);
            return 1;
        }
    }

    db_result_list_free(result_list);
    db_clause_list_free(clause_list);
    db_clause_free(clause);
    return ret;
}

int test2_get_by_id(test2_t* test2, const db_value_t* id) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_result_list_t* result_list;
    const db_result_t* result;
    int ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause = db_clause_new()));
    CU_ASSERT_FATAL(!db_clause_set_field(clause, "id"));
    CU_ASSERT_FATAL(!db_clause_set_type(clause, DB_CLAUSE_EQUAL));
    CU_ASSERT_FATAL(!db_value_copy(db_clause_get_value(clause), id));
    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause));
    clause = NULL;

    ret = 1;
    result_list = db_object_read(test2->dbo, NULL, clause_list);
    if (result_list) {
        result = db_result_list_next(result_list);
        if (result) {
            test2_from_result(test2, result);
            ret = 0;
        }
        CU_ASSERT_PTR_NULL((result = db_result_list_next(result_list)));
        if (result) {
            db_result_list_free(result_list);
            db_clause_list_free(clause_list);
            return 1;
        }
    }

    db_result_list_free(result_list);
    db_clause_list_free(clause_list);
    db_clause_free(clause);
    return ret;
}

int test2_create(test2_t* test2) {
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_value_t* value;
    int ret = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test2);
    CU_ASSERT_FATAL(db_value_not_empty(test2->id));
    CU_ASSERT_FATAL(db_value_not_empty(test2->rev));
    CU_ASSERT_PTR_NOT_NULL_FATAL(test2->name);

    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field_list = db_object_field_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field = db_object_field_new()));
    CU_ASSERT_FATAL(!db_object_field_set_name(object_field, "name"));
    CU_ASSERT_FATAL(!db_object_field_set_type(object_field, DB_TYPE_TEXT));
    CU_ASSERT_FATAL(!db_object_field_list_add(object_field_list, object_field));
    object_field = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((value_set = db_value_set_new(1)));
    CU_ASSERT_PTR_NOT_NULL_FATAL((value = db_value_set_get(value_set, 0)));
    CU_ASSERT_FATAL(!db_value_from_text(value, test2->name));

    if (db_object_create(test2->dbo, object_field_list, value_set)) {
        ret = 1;
    }

    db_value_set_free(value_set);
    db_object_field_free(object_field);
    db_object_field_list_free(object_field_list);
    CU_ASSERT(!ret);
    return ret;
}

int test2_update(test2_t* test2) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    db_object_field_list_t* object_field_list;
    db_object_field_t* object_field;
    db_value_set_t* value_set;
    db_value_t* value;
    int ret = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test2);
    CU_ASSERT_FATAL(!db_value_not_empty(test2->id));
    CU_ASSERT_FATAL(!db_value_not_empty(test2->rev));
    CU_ASSERT_PTR_NOT_NULL_FATAL(test2->name);

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause = db_clause_new()));
    CU_ASSERT_FATAL(!db_clause_set_field(clause, "id"));
    CU_ASSERT_FATAL(!db_clause_set_type(clause, DB_CLAUSE_EQUAL));
    CU_ASSERT_FATAL(!db_value_copy(db_clause_get_value(clause), test2->id));
    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause));
    clause = NULL;
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause = db_clause_new()));
    CU_ASSERT_FATAL(!db_clause_set_field(clause, "rev"));
    CU_ASSERT_FATAL(!db_clause_set_type(clause, DB_CLAUSE_EQUAL));
    CU_ASSERT_FATAL(!db_value_copy(db_clause_get_value(clause), test2->rev));
    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause));
    clause = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field_list = db_object_field_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((object_field = db_object_field_new()));
    CU_ASSERT_FATAL(!db_object_field_set_name(object_field, "name"));
    CU_ASSERT_FATAL(!db_object_field_set_type(object_field, DB_TYPE_TEXT));
    CU_ASSERT_FATAL(!db_object_field_list_add(object_field_list, object_field));
    object_field = NULL;

    CU_ASSERT_PTR_NOT_NULL_FATAL((value_set = db_value_set_new(1)));
    CU_ASSERT_PTR_NOT_NULL_FATAL((value = db_value_set_get(value_set, 0)));
    CU_ASSERT_FATAL(!db_value_from_text(value, test2->name));

    if (db_object_update(test2->dbo, object_field_list, value_set, clause_list)) {
        ret = 1;
    }

    db_clause_list_free(clause_list);
    db_clause_free(clause);
    db_value_set_free(value_set);
    db_object_field_free(object_field);
    db_object_field_list_free(object_field_list);
    return ret;
}

int test2_delete(test2_t* test2) {
    db_clause_list_t* clause_list;
    db_clause_t* clause;
    int ret = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(test2);
    CU_ASSERT_FATAL(!db_value_not_empty(test2->id));
    CU_ASSERT_FATAL(!db_value_not_empty(test2->rev));

    CU_ASSERT_PTR_NOT_NULL_FATAL((clause_list = db_clause_list_new()));
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause = db_clause_new()));
    CU_ASSERT_FATAL(!db_clause_set_field(clause, "id"));
    CU_ASSERT_FATAL(!db_clause_set_type(clause, DB_CLAUSE_EQUAL));
    CU_ASSERT_FATAL(!db_value_copy(db_clause_get_value(clause), test2->id));
    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause));
    clause = NULL;
    CU_ASSERT_PTR_NOT_NULL_FATAL((clause = db_clause_new()));
    CU_ASSERT_FATAL(!db_clause_set_field(clause, "rev"));
    CU_ASSERT_FATAL(!db_clause_set_type(clause, DB_CLAUSE_EQUAL));
    CU_ASSERT_FATAL(!db_value_copy(db_clause_get_value(clause), test2->rev));
    CU_ASSERT_FATAL(!db_clause_list_add(clause_list, clause));
    clause = NULL;

    if (db_object_delete(test2->dbo, clause_list)) {
        ret = 1;
    }

    db_clause_list_free(clause_list);
    db_clause_free(clause);
    CU_ASSERT(!ret);
    return ret;
}

#if defined(ENFORCER_DATABASE_SQLITE3)
int init_suite_database_operations_sqlite(void) {
    if (configuration_list) {
        return 1;
    }
    if (configuration) {
        return 1;
    }
    if (connection) {
        return 1;
    }
    if (test) {
        return 1;
    }
    if (test2) {
        return 1;
    }
    if (test2_2) {
        return 1;
    }

    /*
     * Setup the configuration for the connection
     */
    if (!(configuration_list = db_configuration_list_new())) {
        return 1;
    }
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "backend")
        || db_configuration_set_value(configuration, "sqlite")
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "file")
        || db_configuration_set_value(configuration, "test.db")
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;

    /*
     * Connect to the database
     */
    if (!(connection = db_connection_new())
        || db_connection_set_configuration_list(connection, configuration_list))
    {
        db_connection_free(connection);
        connection = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration_list = NULL;

    if (db_connection_setup(connection)
        || db_connection_connect(connection))
    {
        db_connection_free(connection);
        connection = NULL;
        return 1;
    }

    return 0;
}
#endif

#if defined(ENFORCER_DATABASE_MYSQL)
int init_suite_database_operations_mysql(void) {
    if (configuration_list) {
        return 1;
    }
    if (configuration) {
        return 1;
    }
    if (connection) {
        return 1;
    }
    if (test) {
        return 1;
    }
    if (test2) {
        return 1;
    }
    if (test2_2) {
        return 1;
    }

    /*
     * Setup the configuration for the connection
     */
    if (!(configuration_list = db_configuration_list_new())) {
        return 1;
    }
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "backend")
        || db_configuration_set_value(configuration, "mysql")
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "host")
        || db_configuration_set_value(configuration, ENFORCER_DB_HOST)
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "port")
        || db_configuration_set_value(configuration, ENFORCER_DB_PORT_TEXT)
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "user")
        || db_configuration_set_value(configuration, ENFORCER_DB_USERNAME)
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "pass")
        || db_configuration_set_value(configuration, ENFORCER_DB_PASSWORD)
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;
    if (!(configuration = db_configuration_new())
        || db_configuration_set_name(configuration, "db")
        || db_configuration_set_value(configuration, ENFORCER_DB_DATABASE)
        || db_configuration_list_add(configuration_list, configuration))
    {
        db_configuration_free(configuration);
        configuration = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration = NULL;

    /*
     * Connect to the database
     */
    if (!(connection = db_connection_new())
        || db_connection_set_configuration_list(connection, configuration_list))
    {
        db_connection_free(connection);
        connection = NULL;
        db_configuration_list_free(configuration_list);
        configuration_list = NULL;
        return 1;
    }
    configuration_list = NULL;

    if (db_connection_setup(connection)
        || db_connection_connect(connection))
    {
        db_connection_free(connection);
        connection = NULL;
        return 1;
    }

    return 0;
}
#endif

int clean_suite_database_operations(void) {
    test_free(test);
    test = NULL;
    test_list_free(test_list);
    test_list = NULL;
    test2_free(test2);
    test2 = NULL;
    test2_free(test2_2);
    test2_2 = NULL;
    db_connection_free(connection);
    connection = NULL;
    db_configuration_free(configuration);
    configuration = NULL;
    db_configuration_list_free(configuration_list);
    configuration_list = NULL;
    db_value_reset(&object2_id);
    db_value_reset(&object3_id);
    return 0;
}

void __check_id(const db_value_t* id, int id_int, const char* id_text) {
    db_type_int32_t int32;
    db_type_uint32_t uint32;
    db_type_int64_t int64;
    db_type_uint64_t uint64;
    const char* text;

    CU_ASSERT_PTR_NOT_NULL(id);
    switch (db_value_type(id)) {
    case DB_TYPE_INT32:
        CU_ASSERT(!db_value_to_int32(id, &int32));
        CU_ASSERT(int32 == (db_type_int32_t)id_int);
        break;

    case DB_TYPE_UINT32:
        CU_ASSERT(!db_value_to_uint32(id, &uint32));
        CU_ASSERT(uint32 == (db_type_uint32_t)id_int);
        break;

    case DB_TYPE_INT64:
        CU_ASSERT(!db_value_to_int64(id, &int64));
        CU_ASSERT(int64 == (db_type_int64_t)id_int);
        break;

    case DB_TYPE_UINT64:
        CU_ASSERT(!db_value_to_uint64(id, &uint64));
        CU_ASSERT(uint64 == (db_type_uint64_t)id_int);
        break;

    case DB_TYPE_TEXT:
        CU_ASSERT_PTR_NOT_NULL_FATAL((text = db_value_text(id)));
        CU_ASSERT(!strcmp(text, id_text));
        break;

    default:
        CU_FAIL("db_value_type(id)");
    }
}

void test_database_operations_read_object1(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test = test_new(connection)));
    CU_ASSERT_FATAL(!test_get_by_name(test, "test"));
    __check_id(test_id(test), 1, "1");
    CU_ASSERT_PTR_NOT_NULL_FATAL(test_name(test));
    CU_ASSERT(!strcmp(test_name(test), "test"));

    test_free(test);
    test = NULL;
    CU_PASS("test_free");
}

void test_database_operations_create_object2(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test = test_new(connection)));
    CU_ASSERT_FATAL(!test_set_name(test, "name 2"));
    CU_ASSERT(!strcmp(test_name(test), "name 2"));
    CU_ASSERT_FATAL(!test_create(test));

    test_free(test);
    test = NULL;
    CU_PASS("test_free");

    CU_ASSERT_PTR_NOT_NULL_FATAL((test = test_new(connection)));
    CU_ASSERT_FATAL(!test_get_by_name(test, "name 2"));
    db_value_reset(&object2_id);
    CU_ASSERT(!db_value_copy(&object2_id, test_id(test)));
    CU_ASSERT(!strcmp(test_name(test), "name 2"));

    test_free(test);
    test = NULL;
    CU_PASS("test_free");
}

void test_database_operations_read_object2(void) {
    int cmp = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL((test = test_new(connection)));
    CU_ASSERT_FATAL(!test_get_by_id(test, &object2_id));
    CU_ASSERT(!db_value_cmp(test_id(test), &object2_id, &cmp));
    CU_ASSERT(!cmp);
    CU_ASSERT(!strcmp(test_name(test), "name 2"));

    test_free(test);
    test = NULL;
    CU_PASS("test_free");
}

void test_database_operations_update_object2(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test = test_new(connection)));
    CU_ASSERT_FATAL(!test_get_by_id(test, &object2_id));
    CU_ASSERT_FATAL(!test_set_name(test, "name 3"));
    CU_ASSERT(!strcmp(test_name(test), "name 3"));
    CU_ASSERT_FATAL(!test_update(test));

    test_free(test);
    test = NULL;
    CU_PASS("test_free");

    CU_ASSERT_PTR_NOT_NULL_FATAL((test = test_new(connection)));
    CU_ASSERT_FATAL(!test_get_by_id(test, &object2_id));
    CU_ASSERT(!strcmp(test_name(test), "name 3"));

    test_free(test);
    test = NULL;
    CU_PASS("test_free");
}

void test_database_operations_delete_object2(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test = test_new(connection)));
    CU_ASSERT_FATAL(!test_get_by_id(test, &object2_id));
    CU_ASSERT_FATAL(!test_delete(test));

    test_free(test);
    test = NULL;
    CU_PASS("test_free");

    CU_ASSERT_PTR_NOT_NULL_FATAL((test = test_new(connection)));
    CU_ASSERT_FATAL(test_get_by_id(test, &object2_id));

    test_free(test);
    test = NULL;
    CU_PASS("test_free");
}

void test_database_operations_create_object3(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test = test_new(connection)));
    CU_ASSERT_FATAL(!test_set_name(test, "name 3"));
    CU_ASSERT(!strcmp(test_name(test), "name 3"));
    CU_ASSERT_FATAL(!test_create(test));

    test_free(test);
    test = NULL;
    CU_PASS("test_free");

    CU_ASSERT_PTR_NOT_NULL_FATAL((test = test_new(connection)));
    CU_ASSERT_FATAL(!test_get_by_name(test, "name 3"));
    db_value_reset(&object3_id);
    CU_ASSERT(!db_value_copy(&object3_id, test_id(test)));
    CU_ASSERT(!strcmp(test_name(test), "name 3"));

    test_free(test);
    test = NULL;
    CU_PASS("test_free");
}

void test_database_operations_delete_object3(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test = test_new(connection)));
    CU_ASSERT_FATAL(!test_get_by_id(test, &object3_id));
    CU_ASSERT_FATAL(!test_delete(test));

    test_free(test);
    test = NULL;
    CU_PASS("test_free");

    CU_ASSERT_PTR_NOT_NULL_FATAL((test = test_new(connection)));
    CU_ASSERT_FATAL(test_get_by_id(test, &object3_id));

    test_free(test);
    test = NULL;
    CU_PASS("test_free");
}

void test_database_operations_read_all(void) {
    const test_t* local_test;
    int count = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL((test_list = test_list_new(connection)));
    CU_ASSERT_FATAL(!test_list_get(test_list));
    local_test = test_list_begin(test_list);
    while (local_test) {
        count++;
        local_test = test_list_next(test_list);
    }
    CU_ASSERT(count == 3);

    test_list_free(test_list);
    test_list = NULL;
    CU_PASS("test_list_free");
}

void test_database_operations_count(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test = test_new(connection)));
    CU_ASSERT(test_count_by_name(test, "test") == 1);
    CU_ASSERT(test_count_by_id(test, &object2_id) == 1);
    CU_ASSERT(test_count_by_id(test, &object3_id) == 1);
    CU_ASSERT(test_count_by_name(test, "name 3") == 2);
    test_free(test);
    test = NULL;
    CU_PASS("test_free");
}

void test_database_operations_read_object1_2(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test2 = test2_new(connection)));
    CU_ASSERT_FATAL(!test2_get_by_name(test2, "test"));
    __check_id(test2_id(test2), 1, "1");
    CU_ASSERT_PTR_NOT_NULL_FATAL(test2_name(test2));
    CU_ASSERT(!strcmp(test2_name(test2), "test"));

    test2_free(test2);
    test2 = NULL;
    CU_PASS("test2_free");
}

void test_database_operations_create_object2_2(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test2 = test2_new(connection)));
    CU_ASSERT_FATAL(!test2_set_name(test2, "name 2"));
    CU_ASSERT(!strcmp(test2_name(test2), "name 2"));
    CU_ASSERT_FATAL(!test2_create(test2));

    test2_free(test2);
    test2 = NULL;
    CU_PASS("test2_free");

    CU_ASSERT_PTR_NOT_NULL_FATAL((test2 = test2_new(connection)));
    CU_ASSERT_FATAL(!test2_get_by_name(test2, "name 2"));
    db_value_reset(&object2_id);
    CU_ASSERT(!db_value_copy(&object2_id, test2_id(test2)));
    CU_ASSERT(!strcmp(test2_name(test2), "name 2"));

    test2_free(test2);
    test2 = NULL;
    CU_PASS("test2_free");
}

void test_database_operations_read_object2_2(void) {
    int cmp = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL((test2 = test2_new(connection)));
    CU_ASSERT_FATAL(!test2_get_by_id(test2, &object2_id));
    CU_ASSERT(!db_value_cmp(test2_id(test2), &object2_id, &cmp));
    CU_ASSERT(!cmp);
    CU_ASSERT(!strcmp(test2_name(test2), "name 2"));

    test2_free(test2);
    test2 = NULL;
    CU_PASS("test2_free");
}

void test_database_operations_update_object2_2(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test2 = test2_new(connection)));
    CU_ASSERT_FATAL(!test2_get_by_id(test2, &object2_id));
    CU_ASSERT_FATAL(!test2_set_name(test2, "name 3"));
    CU_ASSERT(!strcmp(test2_name(test2), "name 3"));
    CU_ASSERT_FATAL(!test2_update(test2));

    test2_free(test2);
    test2 = NULL;
    CU_PASS("test2_free");

    CU_ASSERT_PTR_NOT_NULL_FATAL((test2 = test2_new(connection)));
    CU_ASSERT_FATAL(!test2_get_by_id(test2, &object2_id));
    CU_ASSERT(!strcmp(test2_name(test2), "name 3"));

    test2_free(test2);
    test2 = NULL;
    CU_PASS("test2_free");
}

void test_database_operations_update_objects_revisions(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test2 = test2_new(connection)));
    CU_ASSERT_FATAL(!test2_set_name(test2, "name 4"));
    CU_ASSERT(!strcmp(test2_name(test2), "name 4"));
    CU_ASSERT_FATAL(!test2_create(test2));

    test2_free(test2);
    test2 = NULL;
    CU_PASS("test2_free");

    CU_ASSERT_PTR_NOT_NULL_FATAL((test2 = test2_new(connection)));
    CU_ASSERT_FATAL(!test2_get_by_name(test2, "name 4"));
    CU_ASSERT(!strcmp(test2_name(test2), "name 4"));

    CU_ASSERT_PTR_NOT_NULL_FATAL((test2_2 = test2_new(connection)));
    CU_ASSERT_FATAL(!test2_get_by_name(test2_2, "name 4"));
    CU_ASSERT(!strcmp(test2_name(test2_2), "name 4"));

    CU_ASSERT_FATAL(!test2_set_name(test2_2, "name 5"));
    CU_ASSERT(!strcmp(test2_name(test2_2), "name 5"));
    CU_ASSERT_FATAL(!test2_update(test2_2));

    CU_ASSERT_FATAL(!test2_set_name(test2, "name 5"));
    CU_ASSERT(!strcmp(test2_name(test2), "name 5"));
    CU_ASSERT_FATAL(test2_update(test2));

    test2_free(test2);
    test2 = NULL;
    CU_PASS("test2_free");

    test2_free(test2_2);
    test2_2 = NULL;
    CU_PASS("test2_free");
}

void test_database_operations_delete_object2_2(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test2 = test2_new(connection)));
    CU_ASSERT_FATAL(!test2_get_by_id(test2, &object2_id));
    CU_ASSERT_FATAL(!test2_delete(test2));

    test2_free(test2);
    test2 = NULL;
    CU_PASS("test2_free");

    CU_ASSERT_PTR_NOT_NULL_FATAL((test2 = test2_new(connection)));
    CU_ASSERT_FATAL(test2_get_by_id(test2, &object2_id));

    test2_free(test2);
    test2 = NULL;
    CU_PASS("test2_free");
}

void test_database_operations_create_object3_2(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test2 = test2_new(connection)));
    CU_ASSERT_FATAL(!test2_set_name(test2, "name 3"));
    CU_ASSERT(!strcmp(test2_name(test2), "name 3"));
    CU_ASSERT_FATAL(!test2_create(test2));

    test2_free(test2);
    test2 = NULL;
    CU_PASS("test2_free");

    CU_ASSERT_PTR_NOT_NULL_FATAL((test2 = test2_new(connection)));
    CU_ASSERT_FATAL(!test2_get_by_name(test2, "name 3"));
    db_value_reset(&object3_id);
    CU_ASSERT(!db_value_copy(&object3_id, test2_id(test2)));
    CU_ASSERT(!strcmp(test2_name(test2), "name 3"));

    test2_free(test2);
    test2 = NULL;
    CU_PASS("test2_free");
}

void test_database_operations_delete_object3_2(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL((test2 = test2_new(connection)));
    CU_ASSERT_FATAL(!test2_get_by_id(test2, &object3_id));
    CU_ASSERT_FATAL(!test2_delete(test2));

    test2_free(test2);
    test2 = NULL;
    CU_PASS("test2_free");

    CU_ASSERT_PTR_NOT_NULL_FATAL((test2 = test2_new(connection)));
    CU_ASSERT_FATAL(test2_get_by_id(test2, &object3_id));

    test2_free(test2);
    test2 = NULL;
    CU_PASS("test2_free");
}
