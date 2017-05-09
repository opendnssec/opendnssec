/*
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

#ifndef SIGNER_BACKUP_H
#define SIGNER_BACKUP_H

#include "config.h"
#include "duration.h"
#include "file.h"
#include "status.h"
#include "zone.h"

#include <ldns/ldns.h>

/**
 * Read token from backup file.
 * \param[in] in input file descriptor
 * \return char* read token
 *
 */
char* backup_read_token(FILE* in);

/**
 * Read and match a string from backup file.
 * \param[in] in input file descriptor
 * \param[in] str string to match
 * \return 1 if string was read and matched, 0 otherwise
 *
 */
int backup_read_check_str(FILE* in, const char* str);

/**
 * Read a string from backup file.
 * \param[in] in input file descriptor
 * \param[out] string storage
 * \return int 1 on success, 0 otherwise
 *
 */
int backup_read_str(FILE* in, const char** str);

/**
 * Read time from backup file.
 * \param[in] in input file descriptor
 * \param[out] v time_t storage
 * \return int 1 on success, 0 otherwise
 *
 */
int backup_read_time_t(FILE* in, time_t* v);

/**
 * Read duration from backup file.
 * \param[in] in input file descriptor
 * \param[out] v duration storage
 * \return int 1 on success, 0 otherwise
 *
 */
int backup_read_duration(FILE* in, duration_type** v);

/**
 * Read rr type from backup file.
 * \param[in] in input file descriptor
 * \param[out] v rr type storage
 * \return int 1 on success, 0 otherwise
 *
 */
int backup_read_rr_type(FILE* in, ldns_rr_type* v);

/**
 * Read integer from backup file.
 * \param[in] in input file descriptor
 * \param[out] v integer storage
 * \return int 1 on success, 0 otherwise
 *
 */
int backup_read_int(FILE* in, int* v);

/**
 * Read 8bit unsigned integer from backup file.
 * \param[in] in input file descriptor
 * \param[out] v uint8_t storage
 * \return int 1 on success, 0 otherwise
 *
 */
int backup_read_uint8_t(FILE* in, uint8_t* v);

/**
 * Read 32bit unsigned integer from backup file.
 * \param[in] in input file descriptor
 * \param[out] v uint32_t storage
 * \return int 1 on success, 0 otherwise
 *
 */
int backup_read_uint32_t(FILE* in, uint32_t* v);

/**
 * Read namedb from backup file.
 * \param[in] in input file descriptor
 * \param[in] zone zone reference
 * \return ods_status status
 *
 */
ods_status backup_read_namedb(FILE* in, void* zone);

/**
 * Read ixfr journal from file.
 * \param[in] in input file descriptor
 * \param[in] zone zone reference
 * \return ods_status status
 *
 */
ods_status backup_read_ixfr(FILE* in, void* zone);

#endif /* SIGNER_BACKUP_H */
