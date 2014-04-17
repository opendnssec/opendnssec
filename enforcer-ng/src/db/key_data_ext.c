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

#include "key_data.h"
#include "db_error.h"

int key_data_get_key_state_list(key_data_t* key_data) {
    key_state_list_t* key_state_list;
    const key_state_t* key_state;
    key_state_t* key_state_ds = NULL;
    key_state_t* key_state_rrsig = NULL;
    key_state_t* key_state_dnskey = NULL;
    key_state_t* key_state_rrsigdnskey = NULL;
    db_value_t* id1 = NULL;
    db_value_t* id2 = NULL;
    db_value_t* id3 = NULL;
    db_value_t* id4 = NULL;
    int ret;

    if (!key_data) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_data->dbo) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_data->ds) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_data->rrsig) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_data->dnskey) {
        return DB_ERROR_UNKNOWN;
    }
    if (!key_data->rrsigdnskey) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(id1 = db_value_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(id2 = db_value_new())) {
        db_value_free(id1);
        return DB_ERROR_UNKNOWN;
    }
    if (!(id3 = db_value_new())) {
        db_value_free(id1);
        db_value_free(id2);
        return DB_ERROR_UNKNOWN;
    }
    if (!(id4 = db_value_new())) {
        db_value_free(id1);
        db_value_free(id2);
        db_value_free(id3);
        return DB_ERROR_UNKNOWN;
    }

    if (db_value_from_int32(id1, key_data->ds)
        || db_value_from_int32(id2, key_data->rrsig)
        || db_value_from_int32(id3, key_data->dnskey)
        || db_value_from_int32(id4, key_data->rrsigdnskey))
    {
        db_value_free(id1);
        db_value_free(id2);
        db_value_free(id3);
        db_value_free(id4);
        return DB_ERROR_UNKNOWN;
    }

    key_state_list = key_state_list_new(db_object_connection(key_data->dbo));
    if (!key_state_list) {
        db_value_free(id1);
        db_value_free(id2);
        db_value_free(id3);
        db_value_free(id4);
        return DB_ERROR_UNKNOWN;
    }
    if (key_state_list_get_4_by_id(key_state_list, id1, id2, id3, id4)) {
        key_state_list_free(key_state_list);
        db_value_free(id1);
        db_value_free(id2);
        db_value_free(id3);
        db_value_free(id4);
        return DB_ERROR_UNKNOWN;
    }

    key_state = key_state_list_begin(key_state_list);
    while (key_state) {
        if (db_value_cmp(key_state_id(key_state), id1, &ret)) {
            key_state_free(key_state_ds);
            key_state_free(key_state_rrsig);
            key_state_free(key_state_dnskey);
            key_state_free(key_state_rrsigdnskey);
            key_state_list_free(key_state_list);
            db_value_free(id1);
            db_value_free(id2);
            db_value_free(id3);
            db_value_free(id4);
            return DB_ERROR_UNKNOWN;
        }
        if (!ret) {
            if (!(key_state_ds = key_state_new(db_object_connection(key_data->dbo)))
                || key_state_copy(key_state_ds, key_state))
            {
                key_state_free(key_state_ds);
                key_state_free(key_state_rrsig);
                key_state_free(key_state_dnskey);
                key_state_free(key_state_rrsigdnskey);
                key_state_list_free(key_state_list);
                db_value_free(id1);
                db_value_free(id2);
                db_value_free(id3);
                db_value_free(id4);
                return DB_ERROR_UNKNOWN;
            }
            continue;
        }

        if (db_value_cmp(key_state_id(key_state), id2, &ret)) {
            key_state_free(key_state_ds);
            key_state_free(key_state_rrsig);
            key_state_free(key_state_dnskey);
            key_state_free(key_state_rrsigdnskey);
            key_state_list_free(key_state_list);
            db_value_free(id1);
            db_value_free(id2);
            db_value_free(id3);
            db_value_free(id4);
            return DB_ERROR_UNKNOWN;
        }
        if (!ret) {
            if (!(key_state_rrsig = key_state_new(db_object_connection(key_data->dbo)))
                || key_state_copy(key_state_rrsig, key_state))
            {
                key_state_free(key_state_ds);
                key_state_free(key_state_rrsig);
                key_state_free(key_state_dnskey);
                key_state_free(key_state_rrsigdnskey);
                key_state_list_free(key_state_list);
                db_value_free(id1);
                db_value_free(id2);
                db_value_free(id3);
                db_value_free(id4);
                return DB_ERROR_UNKNOWN;
            }
        }

        if (db_value_cmp(key_state_id(key_state), id3, &ret)) {
            key_state_free(key_state_ds);
            key_state_free(key_state_rrsig);
            key_state_free(key_state_dnskey);
            key_state_free(key_state_rrsigdnskey);
            key_state_list_free(key_state_list);
            db_value_free(id1);
            db_value_free(id2);
            db_value_free(id3);
            db_value_free(id4);
            return DB_ERROR_UNKNOWN;
        }
        if (!ret) {
            if (!(key_state_dnskey = key_state_new(db_object_connection(key_data->dbo)))
                || key_state_copy(key_state_dnskey, key_state))
            {
                key_state_free(key_state_ds);
                key_state_free(key_state_rrsig);
                key_state_free(key_state_dnskey);
                key_state_free(key_state_rrsigdnskey);
                key_state_list_free(key_state_list);
                db_value_free(id1);
                db_value_free(id2);
                db_value_free(id3);
                db_value_free(id4);
                return DB_ERROR_UNKNOWN;
            }
        }

        if (db_value_cmp(key_state_id(key_state), id4, &ret)) {
            key_state_free(key_state_ds);
            key_state_free(key_state_rrsig);
            key_state_free(key_state_dnskey);
            key_state_free(key_state_rrsigdnskey);
            key_state_list_free(key_state_list);
            db_value_free(id1);
            db_value_free(id2);
            db_value_free(id3);
            db_value_free(id4);
            return DB_ERROR_UNKNOWN;
        }
        if (!ret) {
            if (!(key_state_rrsigdnskey = key_state_new(db_object_connection(key_data->dbo)))
                || key_state_copy(key_state_rrsigdnskey, key_state))
            {
                key_state_free(key_state_ds);
                key_state_free(key_state_rrsig);
                key_state_free(key_state_dnskey);
                key_state_free(key_state_rrsigdnskey);
                key_state_list_free(key_state_list);
                db_value_free(id1);
                db_value_free(id2);
                db_value_free(id3);
                db_value_free(id4);
                return DB_ERROR_UNKNOWN;
            }
        }
        key_state = key_state_list_next(key_state_list);
    }
    key_state_list_free(key_state_list);

    if (!key_state_ds || !key_state_rrsig || !key_state_dnskey || !key_state_rrsigdnskey) {
        key_state_free(key_state_ds);
        key_state_free(key_state_rrsig);
        key_state_free(key_state_dnskey);
        key_state_free(key_state_rrsigdnskey);
        db_value_free(id1);
        db_value_free(id2);
        db_value_free(id3);
        db_value_free(id4);
        return DB_ERROR_UNKNOWN;
    }

    if (key_data->key_state_ds) {
        key_state_free(key_data->key_state_ds);
    }
    key_data->key_state_ds = key_state_ds;
    if (key_data->key_state_rrsig) {
        key_state_free(key_data->key_state_rrsig);
    }
    key_data->key_state_rrsig = key_state_rrsig;
    if (key_data->key_state_dnskey) {
        key_state_free(key_data->key_state_dnskey);
    }
    key_data->key_state_dnskey = key_state_dnskey;
    if (key_data->key_state_rrsigdnskey) {
        key_state_free(key_data->key_state_rrsigdnskey);
    }
    key_data->key_state_rrsigdnskey = key_state_rrsigdnskey;
    db_value_free(id1);
    db_value_free(id2);
    db_value_free(id3);
    db_value_free(id4);
    return DB_OK;
}

const key_state_t* key_data_get_ds(key_data_t* key_data) {
    db_value_t* id = NULL;

    if (!key_data) {
        return NULL;
    }
    if (!key_data->dbo) {
        return NULL;
    }
    if (!key_data->ds) {
        return NULL;
    }

    if (!key_data->key_state_ds) {
        if (!(id = db_value_new())) {
            return NULL;
        }
        if (db_value_from_int32(id, key_data->ds)) {
            db_value_free(id);
            return NULL;
        }
        key_data->key_state_ds = key_state_new(db_object_connection(key_data->dbo));
        if (key_data->key_state_ds) {
            if (key_state_get_by_id(key_data->key_state_ds, id)) {
                key_state_free(key_data->key_state_ds);
                key_data->key_state_ds = NULL;
                db_value_free(id);
                return NULL;
            }
        }
        db_value_free(id);
    }
    return key_data->key_state_ds;
}

const key_state_t* key_data_get_rrsig(key_data_t* key_data) {
    db_value_t* id = NULL;

    if (!key_data) {
        return NULL;
    }
    if (!key_data->dbo) {
        return NULL;
    }
    if (!key_data->rrsig) {
        return NULL;
    }

    if (!key_data->key_state_rrsig) {
        if (!(id = db_value_new())) {
            return NULL;
        }
        if (db_value_from_int32(id, key_data->rrsig)) {
            db_value_free(id);
            return NULL;
        }
        key_data->key_state_rrsig = key_state_new(db_object_connection(key_data->dbo));
        if (key_data->key_state_rrsig) {
            if (key_state_get_by_id(key_data->key_state_rrsig, id)) {
                key_state_free(key_data->key_state_rrsig);
                key_data->key_state_rrsig = NULL;
                return NULL;
            }
        }
        db_value_free(id);
    }
    return key_data->key_state_rrsig;
}

const key_state_t* key_data_get_dnskey(key_data_t* key_data) {
    db_value_t* id = NULL;

    if (!key_data) {
        return NULL;
    }
    if (!key_data->dbo) {
        return NULL;
    }
    if (!key_data->dnskey) {
        return NULL;
    }

    if (!key_data->key_state_dnskey) {
        if (!(id = db_value_new())) {
            return NULL;
        }
        if (db_value_from_int32(id, key_data->dnskey)) {
            db_value_free(id);
            return NULL;
        }
        key_data->key_state_dnskey = key_state_new(db_object_connection(key_data->dbo));
        if (key_data->key_state_dnskey) {
            if (key_state_get_by_id(key_data->key_state_dnskey, id)) {
                key_state_free(key_data->key_state_dnskey);
                key_data->key_state_dnskey = NULL;
                return NULL;
            }
        }
        db_value_free(id);
    }
    return key_data->key_state_dnskey;
}

const key_state_t* key_data_get_rrsigdnskey(key_data_t* key_data) {
    db_value_t* id = NULL;

    if (!key_data) {
        return NULL;
    }
    if (!key_data->dbo) {
        return NULL;
    }
    if (!key_data->rrsigdnskey) {
        return NULL;
    }

    if (!key_data->key_state_rrsigdnskey) {
        if (!(id = db_value_new())) {
            return NULL;
        }
        if (db_value_from_int32(id, key_data->rrsigdnskey)) {
            db_value_free(id);
            return NULL;
        }
        key_data->key_state_rrsigdnskey = key_state_new(db_object_connection(key_data->dbo));
        if (key_data->key_state_rrsigdnskey) {
            if (key_state_get_by_id(key_data->key_state_rrsigdnskey, id)) {
                key_state_free(key_data->key_state_rrsigdnskey);
                key_data->key_state_rrsigdnskey = NULL;
                return NULL;
            }
        }
        db_value_free(id);
    }
    return key_data->key_state_rrsigdnskey;
}

int key_data_list_get_by_enforcer_zone_id(key_data_list_t* key_data_list, const db_value_t* enforcer_zone_id) {
    db_join_list_t* join_list;
    db_join_t* join;
    db_clause_list_t* clause_list;
    db_clause_t* clause;

    if (!key_data_list) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(join_list = db_join_list_new())) {
        return DB_ERROR_UNKNOWN;
    }
    if (!(join = db_join_new())
        || db_join_set_from_table(join, "KeyData")
        || db_join_set_from_field(join, "id")
        || db_join_set_to_table(join, "EnforcerZone_keys")
        || db_join_set_to_field(join, "child_id")
        || db_join_list_add(join_list, join))
    {
        db_join_free(join);
        db_join_list_free(join_list);
        return DB_ERROR_UNKNOWN;
    }

    if (!(clause_list = db_clause_list_new())) {
        db_join_list_free(join_list);
        return DB_ERROR_UNKNOWN;
    }
    if (!(clause = db_clause_new())
        || db_clause_set_table(clause, "EnforcerZone_keys")
        || db_clause_set_field(clause, "parent_id")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), enforcer_zone_id)
        || db_clause_list_add(clause_list, clause))
    {
        db_join_list_free(join_list);
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return DB_ERROR_UNKNOWN;
    }

    if (key_data_list->result_list) {
        db_result_list_free(key_data_list->result_list);
    }

    key_data_list->result_list = db_object_read(key_data_list->dbo, join_list, clause_list);

    db_join_list_free(join_list);
    db_clause_list_free(clause_list);

    if (!key_data_list->result_list) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}
