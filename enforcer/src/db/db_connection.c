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

#include "db_connection.h"
#include "db_error.h"


#include <stdlib.h>



db_connection_t* db_connection_new(void) {
    db_connection_t* connection =
        (db_connection_t*)calloc(1, sizeof(db_connection_t));

    return connection;
}

void db_connection_free(db_connection_t* connection) {
    if (connection) {
        if (connection->backend) {
            db_backend_free(connection->backend);
        }
        free(connection);
    }
}

int db_connection_set_configuration_list(db_connection_t* connection, const db_configuration_list_t* configuration_list) {
    if (!connection) {
        return DB_ERROR_UNKNOWN;
    }
    if (connection->configuration_list) {
        return DB_ERROR_UNKNOWN;
    }

    connection->configuration_list = configuration_list;
    return DB_OK;
}

int db_connection_setup(db_connection_t* connection) {
    if (!connection) {
        return DB_ERROR_UNKNOWN;
    }
    if (!connection->configuration_list) {
        return DB_ERROR_UNKNOWN;
    }

    if (!connection->backend) {
        const db_configuration_t* backend = db_configuration_list_find(connection->configuration_list, "backend");
        if (!backend) {
            return DB_ERROR_UNKNOWN;
        }

        connection->backend = db_backend_factory_get_backend(db_configuration_value(backend));
        if (!connection->backend) {
            return DB_ERROR_UNKNOWN;
        }
    }
    return DB_OK;
}

int db_connection_connect(const db_connection_t* connection) {
    if (!connection) {
        return DB_ERROR_UNKNOWN;
    }
    if (!connection->configuration_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!connection->backend) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_connect(connection->backend, connection->configuration_list);
}

int db_connection_create(const db_connection_t* connection, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set) {
    if (!connection) {
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
    if (!connection->backend) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_create(connection->backend, object, object_field_list, value_set);
}

db_result_list_t* db_connection_read(const db_connection_t* connection, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list) {
    if (!connection) {
        return NULL;
    }
    if (!object) {
        return NULL;
    }
    if (!connection->backend) {
        return NULL;
    }

    return db_backend_read(connection->backend, object, join_list, clause_list);
}

int db_connection_update(const db_connection_t* connection, const db_object_t* object, const db_object_field_list_t* object_field_list, const db_value_set_t* value_set, const db_clause_list_t* clause_list) {
    if (!connection) {
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
    if (!connection->backend) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_update(connection->backend, object, object_field_list, value_set, clause_list);
}

int db_connection_delete(const db_connection_t* connection, const db_object_t* object, const db_clause_list_t* clause_list) {
    if (!connection) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!connection->backend) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_delete(connection->backend, object, clause_list);
}

int db_connection_count(const db_connection_t* connection, const db_object_t* object, const db_join_list_t* join_list, const db_clause_list_t* clause_list, size_t* count) {
    if (!connection) {
        return DB_ERROR_UNKNOWN;
    }
    if (!object) {
        return DB_ERROR_UNKNOWN;
    }
    if (!count) {
        return DB_ERROR_UNKNOWN;
    }
    if (!connection->backend) {
        return DB_ERROR_UNKNOWN;
    }

    return db_backend_count(connection->backend, object, join_list, clause_list, count);
}
