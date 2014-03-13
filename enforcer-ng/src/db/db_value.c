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

#include "db_value.h"
#include "db_error.h"

#include "mm.h"

#include <string.h>

/* DB VALUE */

mm_alloc_t __value_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_value_t));

db_value_t* db_value_new() {
    db_value_t* value =
        (db_value_t*)mm_alloc_new0(&__value_alloc);

    if (value) {
        value->type = DB_TYPE_EMPTY;
    }

    return value;
}

void db_value_free(db_value_t* value) {
    if (value) {
        if (value->data) {
            free(value->data);
        }
        mm_alloc_delete(&__value_alloc, value);
    }
}

void db_value_reset(db_value_t* value) {
    if (value) {
        if (value->data) {
            free(value->data);
        }
        value->data = NULL;
        value->type = DB_TYPE_EMPTY;
    }
}

db_type_t db_value_type(const db_value_t* value) {
    if (!value) {
        return DB_TYPE_EMPTY;
    }

    return value->type;
}

const void* db_value_data(const db_value_t* value) {
    if (!value) {
        return NULL;
    }

    return value->data;
}

int db_value_set_type(db_value_t* value, db_type_t type) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (type != DB_TYPE_EMPTY) {
        return DB_ERROR_UNKNOWN;
    }

    value->type = type;
    return DB_OK;
}

int db_value_set_data(db_value_t* value, void* data) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (!data) {
        return DB_ERROR_UNKNOWN;
    }

    value->data = data;
    return DB_OK;
}

int db_value_not_empty(const db_value_t* value) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (value->type == DB_TYPE_EMPTY) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

int db_value_to_int(const db_value_t* value, int* to_int) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (!to_int) {
        return DB_ERROR_UNKNOWN;
    }
    if (value->type != DB_TYPE_INTEGER) {
        return DB_ERROR_UNKNOWN;
    }

    *to_int = *(int*)(value->data);
    return DB_OK;
}

int db_value_to_string(const db_value_t* value, char** to_string) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    if (!to_string) {
        return DB_ERROR_UNKNOWN;
    }
    if (value->type != DB_TYPE_STRING) {
        return DB_ERROR_UNKNOWN;
    }

    *to_string = strdup((char*)value->data);
    if (!*to_string) {
        return DB_ERROR_UNKNOWN;
    }
    return DB_OK;
}

int db_value_from_int(db_value_t* value, int from_int) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: support converting int to value->type */
    if (value->type != DB_TYPE_EMPTY) {
        return DB_ERROR_UNKNOWN;
    }

    /* TODO: store it inside the void* if fit */
    value->data = (void*)calloc(1, sizeof(int));
    if (!value->data) {
        return DB_ERROR_UNKNOWN;
    }
    *(int*)(value->data) = from_int;
    value->type = DB_TYPE_INTEGER;
    return DB_OK;
}

int db_value_from_string(db_value_t* value, const char* from_string) {
    if (!value) {
        return DB_ERROR_UNKNOWN;
    }
    /* TODO: support converting char* to value->type */
    if (value->type != DB_TYPE_EMPTY) {
        return DB_ERROR_UNKNOWN;
    }

    value->data = (void*)strdup(from_string);
    if (!value->data) {
        return DB_ERROR_UNKNOWN;
    }
    value->type = DB_TYPE_STRING;
    return DB_OK;
}

/* DB VALUE SET */

mm_alloc_t __value_set_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_value_set_t));
mm_alloc_t __4_value_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_value_t) * 4);
mm_alloc_t __8_value_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_value_t) * 8);
mm_alloc_t __12_value_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_value_t) * 12);
mm_alloc_t __16_value_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_value_t) * 16);
mm_alloc_t __24_value_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_value_t) * 24);
mm_alloc_t __32_value_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_value_t) * 32);
mm_alloc_t __64_value_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_value_t) * 64);
mm_alloc_t __128_value_alloc = MM_ALLOC_T_STATIC_NEW(sizeof(db_value_t) * 128);

db_value_set_t* db_value_set_new(size_t size) {
    db_value_set_t* value_set;

    if (size < 1) {
        return NULL;
    }
    if (size > 128) {
        return NULL;
    }

    value_set = (db_value_set_t*)mm_alloc_new0(&__value_set_alloc);
    if (value_set) {
        if (size <= 4) {
            value_set->values = (db_value_t*)mm_alloc_new0(&__4_value_alloc);
        }
        else if (size <= 8) {
            value_set->values = (db_value_t*)mm_alloc_new0(&__8_value_alloc);
        }
        else if (size <= 12) {
            value_set->values = (db_value_t*)mm_alloc_new0(&__12_value_alloc);
        }
        else if (size <= 16) {
            value_set->values = (db_value_t*)mm_alloc_new0(&__16_value_alloc);
        }
        else if (size <= 24) {
            value_set->values = (db_value_t*)mm_alloc_new0(&__24_value_alloc);
        }
        else if (size <= 32) {
            value_set->values = (db_value_t*)mm_alloc_new0(&__32_value_alloc);
        }
        else if (size <= 64) {
            value_set->values = (db_value_t*)mm_alloc_new0(&__64_value_alloc);
        }
        else if (size <= 128) {
            value_set->values = (db_value_t*)mm_alloc_new0(&__128_value_alloc);
        }
        if (!value_set->values) {
            mm_alloc_delete(&__value_set_alloc, value_set);
            return NULL;
        }
        value_set->size = size;
    }

    return value_set;
}

void db_value_set_free(db_value_set_t* value_set) {
    if (value_set) {
        if (value_set->values) {
            size_t i;
            for (i=0; i<value_set->size; i++) {
                db_value_reset(&value_set->values[i]);
            }

            if (value_set->size <= 4) {
                mm_alloc_delete(&__4_value_alloc, value_set->values);
            }
            else if (value_set->size <= 8) {
                mm_alloc_delete(&__8_value_alloc, value_set->values);
            }
            else if (value_set->size <= 12) {
                mm_alloc_delete(&__12_value_alloc, value_set->values);
            }
            else if (value_set->size <= 16) {
                mm_alloc_delete(&__16_value_alloc, value_set->values);
            }
            else if (value_set->size <= 24) {
                mm_alloc_delete(&__24_value_alloc, value_set->values);
            }
            else if (value_set->size <= 32) {
                mm_alloc_delete(&__32_value_alloc, value_set->values);
            }
            else if (value_set->size <= 64) {
                mm_alloc_delete(&__64_value_alloc, value_set->values);
            }
            else if (value_set->size <= 128) {
                mm_alloc_delete(&__128_value_alloc, value_set->values);
            }
        }
        mm_alloc_delete(&__value_set_alloc, value_set);
    }
}

size_t db_value_set_size(const db_value_set_t* value_set) {
    if (!value_set) {
        return DB_OK;
    }

    return value_set->size;
}

db_value_t* db_value_set_get(const db_value_set_t* value_set, size_t at) {
    if (!value_set) {
        return NULL;
    }
    if (!value_set->values) {
        return NULL;
    }
    if (at < 0) {
        return NULL;
    }
    if (!(at < value_set->size)) {
        return NULL;
    }

    return &value_set->values[at];
}
