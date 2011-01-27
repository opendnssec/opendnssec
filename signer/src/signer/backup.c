/*
 * $Id: tools.c 3817 2010-08-27 08:43:00Z matthijs $
 *
 * Copyright (c) 2006-2010 NLNet Labs. All rights reserved.
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

/**
 * Recover from backup.
 *
 */

#include "config.h"
#include "shared/log.h"
#include "util/duration.h"
#include "util/file.h"
#include "util/se_malloc.h"

#include <ldns/ldns.h>

static const char* backup_str = "backup";


/**
 * Read token from backup file.
 *
 */
char*
backup_read_token(FILE* in)
{
    static char buf[4000];
    buf[sizeof(buf)-1]=0;
    while (1) {
        if (fscanf(in, "%3990s", buf) != 1) {
            return 0;
        }
        if (buf[0] != '#') {
            return buf;
        }
        if (!fgets(buf, sizeof(buf), in)) {
            return 0;
        }
    }
    return 0;
}

/**
 * Read and match a string from backup file.
 *
 */
int
backup_read_check_str(FILE* in, const char* str)
{
    char *p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read check string \'%s\'", backup_str, str);
        return 0;
    }
    if (se_strcmp(p, str) != 0) {
        ods_log_debug("[%s] \'%s\' does not match \'%s\'", backup_str, p, str);
        return 0;
    }
    return 1;
}


/**
 * Read a string from backup file.
 *
 */
int
backup_read_str(FILE* in, char** str)
{
    char *p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read string", backup_str);
        return 0;
    }
    *str = se_strdup(p);
    return 1;
}


/**
 * Read time from backup file.
 *
 */
int
backup_read_time_t(FILE* in, time_t* v)
{
    char* p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read time", backup_str);
       return 0;
    }
    *v=atol(p);
    return 1;
}


/**
 * Read duration from backup file.
 *
 */
int
backup_read_duration(FILE* in, duration_type** v)
{
    char* p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read duration", backup_str);
       return 0;
    }
    *v=duration_create_from_string((const char*) p);
    return 1;
}


/**
 * Read rr type from backup file.
 *
 */
int
backup_read_rr_type(FILE* in, ldns_rr_type* v)
{
    char* p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read rr type", backup_str);
       return 0;
    }
    *v=(ldns_rr_type) atoi(p);
    return 1;
}


/**
 * Read integer from backup file.
 *
 */
int
backup_read_int(FILE* in, int* v)
{
    char* p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read integer", backup_str);
       return 0;
    }
    *v=atoi(p);
    return 1;
}


/**
 * Read size type from backup file.
 *
 */
size_t
backup_read_size_t(FILE* in, int* v)
{
    char* p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read size_t", backup_str);
       return 0;
    }
    *v=(size_t)atoi(p);
    return 1;
}


/**
 * Read 8bit unsigned integer from backup file.
 *
 */
int
backup_read_uint8_t(FILE* in, uint8_t* v)
{
    char* p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read uint8_t", backup_str);
       return 0;
    }
    *v= (uint8_t)atoi(p);
    return 1;
}


/**
 * Read 16bit unsigned integer from backup file.
 *
 */
int
backup_read_uint16_t(FILE* in, uint16_t* v)
{
    char* p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read uint16_t", backup_str);
       return 0;
    }
    *v= (uint16_t)atoi(p);
    return 1;
}


/**
 * Read 32bit unsigned integer from backup file.
 *
 */
int
backup_read_uint32_t(FILE* in, uint32_t* v)
{
    char* p = backup_read_token(in);
    if (!p) {
        ods_log_debug("[%s] cannot read uint32_t", backup_str);
       return 0;
    }
    *v= (uint32_t)atol(p);
    return 1;
}
