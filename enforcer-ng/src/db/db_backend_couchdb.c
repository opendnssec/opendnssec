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

#include "db_backend_couchdb.h"
#include "db_error.h"

#include "mm.h"

#include <curl/curl.h>
#include <stdlib.h>
#include <jansson.h>
#include <string.h>

#define REQUEST_BUFFER_SIZE (4*1024*1024)

static int __couchdb_initialized = 0;

typedef struct db_backend_couchdb {
    char* url;
    CURL* curl;
    char* buffer;
    size_t buffer_position;
} db_backend_couchdb_t;

static mm_alloc_t __couchdb_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_backend_couchdb_t));

typedef struct db_backend_couchdb_query {
    db_backend_couchdb_t* backend_couchdb;
    int fields;
    const db_object_t* object;
} db_backend_couchdb_query_t;

static mm_alloc_t __couchdb_query_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_backend_couchdb_query_t));

int db_backend_couchdb_initialize(void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }

    if (!__couchdb_initialized) {
        if (curl_global_init(CURL_GLOBAL_ALL)) {
            return DB_ERROR_UNKNOWN;
        }
        __couchdb_initialized = 1;
    }
    return DB_OK;
}

int db_backend_couchdb_shutdown(void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }

    if (__couchdb_initialized) {
        curl_global_cleanup();
        __couchdb_initialized = 0;
    }
    return DB_OK;
}

size_t __db_backend_couchdb_write_response(void* ptr, size_t size, size_t nmemb, void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if(backend_couchdb->buffer_position + size * nmemb >= REQUEST_BUFFER_SIZE - 1) {
        return 0;
    }

    memcpy(backend_couchdb->buffer + backend_couchdb->buffer_position, ptr, size * nmemb);
    backend_couchdb->buffer_position += size * nmemb;

    return size * nmemb;
}

long __db_backend_couchdb_request(db_backend_couchdb_t* backend_couchdb, const char* request_url) {
    CURLcode status;
    long code;
    char url[1024];
    char* urlp;
    int ret, left;

    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb->url) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb->curl) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb->buffer) {
        return DB_ERROR_UNKNOWN;
    }
    if (!request_url) {
        return DB_ERROR_UNKNOWN;
    }

    left = sizeof(url);
    urlp = url;

    if ((ret = snprintf(urlp, left, "%s", backend_couchdb->url)) >= left) {
        return DB_ERROR_UNKNOWN;
    }
    urlp += ret;
    left -= ret;

    if (*(urlp - 1) != '/') {
        if (*request_url != '/') {
            if ((ret = snprintf(urlp, left, "/")) >= left) {
                return DB_ERROR_UNKNOWN;
            }
            urlp += ret;
            left -= ret;
        }
    }

    if ((ret = snprintf(urlp, left, "%s", request_url)) >= left) {
        return DB_ERROR_UNKNOWN;
    }
    urlp += ret;
    left -= ret;

    curl_easy_setopt(backend_couchdb->curl, CURLOPT_URL, url);
    curl_easy_setopt(backend_couchdb->curl, CURLOPT_WRITEFUNCTION, __db_backend_couchdb_write_response);
    curl_easy_setopt(backend_couchdb->curl, CURLOPT_WRITEDATA, backend_couchdb);
    backend_couchdb->buffer_position = 0;

    if ((status = curl_easy_perform(backend_couchdb->curl))) {
        puts(curl_easy_strerror(status));
        return DB_ERROR_UNKNOWN;
    }

    backend_couchdb->buffer[backend_couchdb->buffer_position] = 0;

    curl_easy_getinfo(backend_couchdb->curl, CURLINFO_RESPONSE_CODE, &code);
    return code;
}

int db_backend_couchdb_connect(void* data, const db_configuration_list_t* configuration_list) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;
    const db_configuration_t* url;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }
    if (backend_couchdb->curl) {
        return DB_ERROR_UNKNOWN;
    }
    if (!configuration_list) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(backend_couchdb->curl = curl_easy_init())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb->buffer) {
        if (!(backend_couchdb->buffer = calloc(REQUEST_BUFFER_SIZE, 1))) {
            return DB_ERROR_UNKNOWN;
        }
    }

    if (!(url = db_configuration_list_find(configuration_list, "url"))) {
        return DB_ERROR_UNKNOWN;
    }
    if (backend_couchdb->url) {
        free(backend_couchdb->url);
    }
    if (!(backend_couchdb->url = strdup(db_configuration_value(url)))) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int db_backend_couchdb_disconnect(void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }

    if (backend_couchdb->curl) {
        curl_easy_cleanup(backend_couchdb->curl);
        backend_couchdb->curl = NULL;
    }

    return DB_OK;
}

int db_backend_couchdb_create(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object_field_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!value_set) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

db_result_t* __db_backend_couchdb_result_from_json_object(const db_object_t* object, json_t* json_object) {
    size_t size, i;
    db_result_t* result;
    db_value_set_t* value_set = NULL;
    void *json_iter;
    json_t *json_value = NULL;
    const db_object_field_t* object_field;
    char key[1024];
    char* keyp;
    int ret, left;

    if (!object) {
        return NULL;
    }
    if (!json_object) {
        return NULL;
    }

    size = 0;
    json_iter = json_object_iter(json_object);
    while (json_iter) {
        if (!strcmp(json_object_iter_key(json_iter), "_rev")) {
            json_iter = json_object_iter_next(json_object, json_iter);
            continue;
        }
        if (!strcmp(json_object_iter_key(json_iter), "type")) {
            json_iter = json_object_iter_next(json_object, json_iter);
            continue;
        }

        size++;
        json_iter = json_object_iter_next(json_object, json_iter);
    }

    if (!(result = db_result_new())
        || !(value_set = db_value_set_new(size))
        || db_result_set_value_set(result, value_set))
    {
        db_result_free(result);
        db_value_set_free(value_set);
        return NULL;
    }

    i = 0;
    object_field = db_object_field_list_begin(db_object_object_field_list(object));
    while (object_field) {
        if (i == size) {
            db_result_free(result);
            return NULL;
        }

        if (db_object_field_type(object_field) == DB_TYPE_PRIMARY_KEY) {
            json_value = json_object_get(json_object, "_id");
        }
        else {
            left = sizeof(key);
            keyp = key;

            if ((ret = snprintf(keyp, left, "%s_%s", db_object_table(object), db_object_field_name(object_field))) >= left) {
                db_result_free(result);
                return NULL;
            }
            keyp += ret;
            left -= ret;

            json_value = json_object_get(json_object, key);
        }
        if (!json_value) {
            db_result_free(result);
            return NULL;
        }

        switch (db_object_field_type(object_field)) {
        case DB_TYPE_PRIMARY_KEY:
            if (!json_is_string(json_value)
                || db_value_from_text(db_value_set_get(value_set, i), json_string_value(json_value))
                || db_value_set_primary_key(db_value_set_get(value_set, i)))
            {
                db_result_free(result);
                return NULL;
            }
            break;

        case DB_TYPE_TEXT:
            if (!json_is_string(json_value)
                || db_value_from_text(db_value_set_get(value_set, i), json_string_value(json_value)))
            {
                db_result_free(result);
                return NULL;
            }
            break;

        case DB_TYPE_ENUM:
            /*
             * Enum needs to be handled elsewhere since we don't know the
             * enum_set_t here.
             */
        case DB_TYPE_INT32:
        case DB_TYPE_UINT32:
        case DB_TYPE_INT64:
        case DB_TYPE_UINT64:
            if (!json_is_number(json_value)
#ifdef JSON_INTEGER_IS_LONG_LONG
                || db_value_from_int64(db_value_set_get(value_set, i), json_integer_value(json_value)))
#else
                || db_value_from_uint64(db_value_set_get(value_set, i), json_integer_value(json_value)))
#endif
            {
                db_result_free(result);
                return NULL;
            }
            break;

        default:
            db_result_free(result);
            return NULL;
            break;
        }

        object_field = db_object_field_next(object_field);
        i++;
    }

    return result;
}

int __db_backend_couchdb_store_result(db_backend_couchdb_t* backend_couchdb, const db_object_t* object, db_result_list_t* result_list, int view) {
    json_t *root;
    json_t *rows;
    json_t *entry;
    json_error_t error;
    size_t i;
    db_result_t* result;

    if (!(root = json_loads(backend_couchdb->buffer, 0, &error))) {
        fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
        return DB_ERROR_UNKNOWN;
    }

    if (view) {
        if (!json_is_object(root)) {
            json_decref(root);
            return DB_ERROR_UNKNOWN;
        }
        rows = json_object_get(root, "rows");
        if (!rows) {
            json_decref(root);
            return DB_ERROR_UNKNOWN;
        }
    }
    else {
        rows = root;
    }

    if (json_is_object(rows)) {
        if (view) {
            entry = json_object_get(rows, "doc");
            if (!entry) {
                json_decref(root);
                return DB_ERROR_UNKNOWN;
            }
        }
        else {
            entry = rows;
        }

        if (!(result = __db_backend_couchdb_result_from_json_object(object, entry))) {
            json_decref(root);
            return DB_ERROR_UNKNOWN;
        }

        if (db_result_list_add(result_list, result)) {
            json_decref(root);
            db_result_free(result);
            return DB_ERROR_UNKNOWN;
        }
    }
    else if (json_is_array(rows)) {
        for (i = 0; i < json_array_size(rows); i++) {
            entry = json_array_get(rows, i);
            if (!json_is_object(entry)) {
                json_decref(root);
                return DB_ERROR_UNKNOWN;
            }

            if (view) {
                entry = json_object_get(entry, "doc");
                if (!entry) {
                    json_decref(root);
                    return DB_ERROR_UNKNOWN;
                }
            }

            if (!(result = __db_backend_couchdb_result_from_json_object(object, entry))) {
                json_decref(root);
                return DB_ERROR_UNKNOWN;
            }

            if (db_result_list_add(result_list, result)) {
                json_decref(root);
                db_result_free(result);
                return DB_ERROR_UNKNOWN;
            }
        }
    }
    else {
        json_decref(root);
        return DB_ERROR_UNKNOWN;
    }
    json_decref(root);
    return DB_OK;
}

int __db_backend_couchdb_build_map_function(const db_object_t* object, const db_clause_list_t* clause_list, char** stringp, int* left) {
    const db_clause_t* clause;
    int ret;
    db_type_int32_t int32;
    db_type_uint32_t uint32;
    db_type_int64_t int64;
    db_type_uint64_t uint64;
    const char* text;

    if (!clause_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!stringp) {
        return DB_ERROR_UNKNOWN;
    }
    if (!*stringp) {
        return DB_ERROR_UNKNOWN;
    }
    if (!left) {
        return DB_ERROR_UNKNOWN;
    }
    if (*left < 1) {
        return DB_ERROR_UNKNOWN;
    }

    clause = db_clause_list_begin(clause_list);
    while (clause) {
        switch (db_clause_operator(clause)) {
        case DB_CLAUSE_OPERATOR_AND:
            if ((ret = snprintf(*stringp, *left, " &&")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_OPERATOR_OR:
            if ((ret = snprintf(*stringp, *left, " ||")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        default:
            return DB_ERROR_UNKNOWN;
        }
        *stringp += ret;
        *left -= ret;

        if ((ret = snprintf(*stringp, *left, " %s_%s", db_object_table(object), db_clause_field(clause))) >= *left) {
            return DB_ERROR_UNKNOWN;
        }
        *stringp += ret;
        *left -= ret;

        switch (db_clause_type(clause)) {
        case DB_CLAUSE_EQUAL:
            if ((ret = snprintf(*stringp, *left, " == ")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_NOT_EQUAL:
            if ((ret = snprintf(*stringp, *left, " != ")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_LESS_THEN:
            if ((ret = snprintf(*stringp, *left, " < ")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_LESS_OR_EQUAL:
            if ((ret = snprintf(*stringp, *left, " <= ")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_GREATER_OR_EQUAL:
            if ((ret = snprintf(*stringp, *left, " >= ")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_GREATER_THEN:
            if ((ret = snprintf(*stringp, *left, " > ")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_CLAUSE_IS_NULL:
            if ((ret = snprintf(*stringp, *left, " == null")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            *stringp += ret;
            *left -= ret;
            clause = db_clause_next(clause);
            continue;
            break;

        case DB_CLAUSE_IS_NOT_NULL:
            if ((ret = snprintf(*stringp, *left, " != null")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            *stringp += ret;
            *left -= ret;
            clause = db_clause_next(clause);
            continue;
            break;

        case DB_CLAUSE_NESTED:
            if ((ret = snprintf(*stringp, *left, " (")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            *stringp += ret;
            *left -= ret;
            if (__db_backend_couchdb_build_map_function(object, db_clause_list(clause), stringp, left)) {
                return DB_ERROR_UNKNOWN;
            }
            if ((ret = snprintf(*stringp, *left, " )")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            *stringp += ret;
            *left -= ret;
            clause = db_clause_next(clause);
            continue;
            break;

        default:
            return DB_ERROR_UNKNOWN;
        }
        *stringp += ret;
        *left -= ret;

        switch (db_value_type(db_clause_value(clause))) {
        case DB_TYPE_INT32:
            if (db_value_to_int32(db_clause_value(clause), &int32)) {
                return DB_ERROR_UNKNOWN;
            }
            if ((ret = snprintf(*stringp, *left, "%d", int32)) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_UINT32:
            if (db_value_to_uint32(db_clause_value(clause), &uint32)) {
                return DB_ERROR_UNKNOWN;
            }
            if ((ret = snprintf(*stringp, *left, "%u", uint32)) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_INT64:
            if (db_value_to_int64(db_clause_value(clause), &int64)) {
                return DB_ERROR_UNKNOWN;
            }
            if ((ret = snprintf(*stringp, *left, "%ld", int64)) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_UINT64:
            if (db_value_to_uint64(db_clause_value(clause), &uint64)) {
                return DB_ERROR_UNKNOWN;
            }
            if ((ret = snprintf(*stringp, *left, "%lu", uint64)) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        case DB_TYPE_TEXT:
            text = db_value_text(db_clause_value(clause));
            if (!text) {
                return DB_ERROR_UNKNOWN;
            }

            if ((ret = snprintf(*stringp, *left, "\\\"")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            *stringp += ret;
            *left -= ret;

            while (*text) {
                if (*text == '"') {
                    if ((ret = snprintf(*stringp, *left, "\\\\\\\"")) >= *left) {
                        return DB_ERROR_UNKNOWN;
                    }
                }
                else {
                    if ((ret = snprintf(*stringp, *left, "%c", *text)) >= *left) {
                        return DB_ERROR_UNKNOWN;
                    }
                }
                *stringp += ret;
                *left -= ret;
                text++;
            }

            if ((ret = snprintf(*stringp, *left, "\\\"")) >= *left) {
                return DB_ERROR_UNKNOWN;
            }
            break;

        default:
            return DB_ERROR_UNKNOWN;
        }
        *stringp += ret;
        *left -= ret;

        clause = db_clause_next(clause);
    }
    return DB_OK;
}

db_result_list_t* db_backend_couchdb_read(void* data, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;
    long code;
    db_result_list_t* result_list;
    char string[4096];
    char* stringp;
    int ret, left, only_ids, have_clauses;
    const db_clause_t* clause;
    db_type_int32_t int32;
    db_type_uint32_t uint32;
    db_type_int64_t int64;
    db_type_uint64_t uint64;

    if (!__couchdb_initialized) {
        return NULL;
    }
    if (!backend_couchdb) {
        return NULL;
    }
    if (!object) {
        return NULL;
    }

    if (join_list) {
        /*
         * Joins is not supported by this backend, check if there are any and
         * return error if so.
         */
        if (db_join_list_begin(join_list)) {
            return NULL;
        }
    }

    clause = db_clause_list_begin(clause_list);
    only_ids = 1;
    have_clauses = 0;
    while (clause) {
        if (db_clause_table(clause)) {
            /*
             * This backend only supports clauses on the objects table.
             */
            if (strcmp(db_clause_table(clause), db_object_table(object))) {
                return NULL;
            }
        }

        if (strcmp(db_clause_field(clause), db_object_primary_key_name(object))) {
            only_ids = 0;
            have_clauses = 1;
        }
        clause = db_clause_next(clause);
    }

    if (!(result_list = db_result_list_new())) {
        return NULL;
    }

    if (only_ids) {
        clause = db_clause_list_begin(clause_list);
        while (clause) {
            left = sizeof(string);
            stringp = string;

            switch (db_value_type(db_clause_value(clause))) {
            case DB_TYPE_INT32:
                if (db_value_to_int32(db_clause_value(clause), &int32)) {
                    db_result_list_free(result_list);
                    return NULL;
                }
                if ((ret = snprintf(stringp, left, "/%d", int32)) >= left) {
                    db_result_list_free(result_list);
                    return NULL;
                }
                break;

            case DB_TYPE_UINT32:
                if (db_value_to_uint32(db_clause_value(clause), &uint32)) {
                    db_result_list_free(result_list);
                    return NULL;
                }
                if ((ret = snprintf(stringp, left, "/%u", uint32)) >= left) {
                    db_result_list_free(result_list);
                    return NULL;
                }
                break;

            case DB_TYPE_INT64:
                if (db_value_to_int64(db_clause_value(clause), &int64)) {
                    db_result_list_free(result_list);
                    return NULL;
                }
                if ((ret = snprintf(stringp, left, "/%ld", int64)) >= left) {
                    db_result_list_free(result_list);
                    return NULL;
                }
                break;

            case DB_TYPE_UINT64:
                if (db_value_to_uint64(db_clause_value(clause), &uint64)) {
                    db_result_list_free(result_list);
                    return NULL;
                }
                if ((ret = snprintf(stringp, left, "/%lu", uint64)) >= left) {
                    db_result_list_free(result_list);
                    return NULL;
                }
                break;

            case DB_TYPE_TEXT:
                if ((ret = snprintf(stringp, left, "/%s", db_value_text(db_clause_value(clause)))) >= left) {
                    db_result_list_free(result_list);
                    return NULL;
                }
                break;

            default:
                db_result_list_free(result_list);
                return NULL;
            }
            stringp += ret;
            left -= ret;

            code = __db_backend_couchdb_request(backend_couchdb, string);
            if (code != 200) {
                db_result_list_free(result_list);
                return NULL;
            }

            if (__db_backend_couchdb_store_result(backend_couchdb, object, result_list, 0)) {
                db_result_list_free(result_list);
                return NULL;
            }
        }
    }
    else if (have_clauses) {
        left = sizeof(string);
        stringp = string;

        if ((ret = snprintf(stringp, left, "function(doc) { if (doc.type == \\\"%s\\\"", db_object_table(object))) >= left) {
            db_result_list_free(result_list);
            return NULL;
        }
        stringp += ret;
        left -= ret;

        if (__db_backend_couchdb_build_map_function(object, clause_list, &stringp, &left)) {
            db_result_list_free(result_list);
            return NULL;
        }

        if ((ret = snprintf(stringp, left, ") { emit(doc._id, doc.test_name); } }")) >= left) {
            db_result_list_free(result_list);
            return NULL;
        }
        stringp += ret;
        left -= ret;

        puts(string);

        /* TODO: Hash function, check if it exists otherwise create it */
        /* TODO: Run the new view */
    }
    else {
        left = sizeof(string);
        stringp = string;

        if ((ret = snprintf(stringp, left, "/_design/application/_view/%s?include_docs=true", db_object_table(object))) >= left) {
            db_result_list_free(result_list);
            return NULL;
        }
        stringp += ret;
        left -= ret;

        code = __db_backend_couchdb_request(backend_couchdb, string);
        if (code != 200) {
            db_result_list_free(result_list);
            return NULL;
        }

        if (__db_backend_couchdb_store_result(backend_couchdb, object, result_list, 1)) {
            db_result_list_free(result_list);
            return NULL;
        }
    }

    return result_list;
}

int db_backend_couchdb_update(void* data, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object_field_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!value_set) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int db_backend_couchdb_delete(void* data, const db_object_t* object, const db_clause_list_t* clause_list) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

void db_backend_couchdb_free(void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (backend_couchdb) {
        if (backend_couchdb->url) {
            free(backend_couchdb->url);
        }
        if (backend_couchdb->curl) {
            db_backend_couchdb_disconnect(backend_couchdb);
        }
        if (backend_couchdb->buffer) {
            free(backend_couchdb->buffer);
        }
        mm_alloc_delete(&__couchdb_alloc, backend_couchdb);
    }
}

int db_backend_couchdb_transaction_begin(void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int db_backend_couchdb_transaction_commit(void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

int db_backend_couchdb_transaction_rollback(void* data) {
    db_backend_couchdb_t* backend_couchdb = (db_backend_couchdb_t*)data;

    if (!__couchdb_initialized) {
        return DB_ERROR_UNKNOWN;
    }
    if (!backend_couchdb) {
        return DB_ERROR_UNKNOWN;
    }

    return DB_OK;
}

db_backend_handle_t* db_backend_couchdb_new_handle(void) {
    db_backend_handle_t* backend_handle = NULL;
    db_backend_couchdb_t* backend_couchdb =
        (db_backend_couchdb_t*)mm_alloc_new0(&__couchdb_alloc);

    if (backend_couchdb && (backend_handle = db_backend_handle_new())) {
        if (db_backend_handle_set_data(backend_handle, (void*)backend_couchdb)
            || db_backend_handle_set_initialize(backend_handle, db_backend_couchdb_initialize)
            || db_backend_handle_set_shutdown(backend_handle, db_backend_couchdb_shutdown)
            || db_backend_handle_set_connect(backend_handle, db_backend_couchdb_connect)
            || db_backend_handle_set_disconnect(backend_handle, db_backend_couchdb_disconnect)
            || db_backend_handle_set_create(backend_handle, db_backend_couchdb_create)
            || db_backend_handle_set_read(backend_handle, db_backend_couchdb_read)
            || db_backend_handle_set_update(backend_handle, db_backend_couchdb_update)
            || db_backend_handle_set_delete(backend_handle, db_backend_couchdb_delete)
            || db_backend_handle_set_free(backend_handle, db_backend_couchdb_free)
            || db_backend_handle_set_transaction_begin(backend_handle, db_backend_couchdb_transaction_begin)
            || db_backend_handle_set_transaction_commit(backend_handle, db_backend_couchdb_transaction_commit)
            || db_backend_handle_set_transaction_rollback(backend_handle, db_backend_couchdb_transaction_rollback))
        {
            db_backend_handle_free(backend_handle);
            mm_alloc_delete(&__couchdb_alloc, backend_couchdb);
            return NULL;
        }
    }
    return backend_handle;
}
