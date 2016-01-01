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

#include "db_configuration.h"
#include "db_error.h"


#include <stdlib.h>
#include <string.h>

/* DB CONFIGURATION */



db_configuration_t* db_configuration_new(void) {
    db_configuration_t* configuration =
        (db_configuration_t*)calloc(1, sizeof(db_configuration_t));

    return configuration;
}

void db_configuration_free(db_configuration_t* configuration) {
    if (configuration) {
        if (configuration->name) {
            free(configuration->name);
        }
        if (configuration->value) {
            free(configuration->value);
        }
        free(configuration);
    }
}

const char* db_configuration_value(const db_configuration_t* configuration) {
    if (!configuration) {
        return NULL;
    }

    return configuration->value;
}

int db_configuration_set_name(db_configuration_t* configuration, const char* name) {
    char* new_name;

    if (!configuration) {
        return DB_ERROR_UNKNOWN;
    }
    if (!name) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_name = strdup(name))) {
        return DB_ERROR_UNKNOWN;
    }

    if (configuration->name) {
        free(configuration->name);
    }
    configuration->name = new_name;
    return DB_OK;
}

int db_configuration_set_value(db_configuration_t* configuration, const char* value) {
    char* new_value;

    if (!configuration) {
        return DB_ERROR_UNKNOWN;
    }
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }

    if (!(new_value = strdup(value))) {
        return DB_ERROR_UNKNOWN;
    }

    if (configuration->value) {
        free(configuration->value);
    }
    configuration->value = new_value;
    return DB_OK;
}

int db_configuration_not_empty(const db_configuration_t* configuration) {
    if (!configuration) {
        return DB_ERROR_UNKNOWN;
    }
    if (!configuration->name) {
        return DB_ERROR_UNKNOWN;
    }
    if (!configuration->value) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

/* DB CONFIGURATION LIST */



db_configuration_list_t* db_configuration_list_new(void) {
    db_configuration_list_t* configuration_list =
        (db_configuration_list_t*)calloc(1, sizeof(db_configuration_list_t));

    return configuration_list;
}

void db_configuration_list_free(db_configuration_list_t* configuration_list) {
    if (configuration_list) {
        if (configuration_list->begin) {
            db_configuration_t* this = configuration_list->begin;
            db_configuration_t* next = NULL;

            while (this) {
                next = this->next;
                db_configuration_free(this);
                this = next;
            }
        }
        free(configuration_list);
    }
}

int db_configuration_list_add(db_configuration_list_t* configuration_list, db_configuration_t* configuration) {
    if (!configuration_list) {
        return DB_ERROR_UNKNOWN;
    }
    if (!configuration) {
        return DB_ERROR_UNKNOWN;
    }
    if (db_configuration_not_empty(configuration)) {
        return DB_ERROR_UNKNOWN;
    }
    if (configuration->next) {
        return DB_ERROR_UNKNOWN;
    }

    if (configuration_list->begin) {
        if (!configuration_list->end) {
            return DB_ERROR_UNKNOWN;
        }
        configuration_list->end->next = configuration;
        configuration_list->end = configuration;
    }
    else {
        configuration_list->begin = configuration;
        configuration_list->end = configuration;
    }

    return DB_OK;
}

const db_configuration_t* db_configuration_list_find(const db_configuration_list_t* configuration_list, const char* name) {
    db_configuration_t* configuration;

    if (!configuration_list) {
        return NULL;
    }
    if (!name) {
        return NULL;
    }

    configuration = configuration_list->begin;
    while (configuration) {
        if (db_configuration_not_empty(configuration)) {
            return NULL;
        }
        if (!strcmp(configuration->name, name)) {
            break;
        }
        configuration = configuration->next;
    }

    return configuration;
}
