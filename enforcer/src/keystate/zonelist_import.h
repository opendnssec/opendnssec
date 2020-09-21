/*
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

#ifndef _KEYSTATE_ZONELIST_IMPORT_H_
#define _KEYSTATE_ZONELIST_IMPORT_H_

#include "daemon/engine.h"
#include "db/db_connection.h"

/**
 * Indicates a successful zonelist import.
 */
#define ZONELIST_IMPORT_OK 0
/**
 * Indicates an error with the arguments provided to zonelist_import().
 */
#define ZONELIST_IMPORT_ERR_ARGS 1
/**
 * Indicates an error with the zonelist XML like parsing, validating or content.
 */
#define ZONELIST_IMPORT_ERR_XML 2
/**
 * Indicates an error with the database like reading, updating or creating.
 */
#define ZONELIST_IMPORT_ERR_DATABASE 3
/**
 * Indicates a memory allocation error or generic internal error.
 */
#define ZONELIST_IMPORT_ERR_MEMORY 4
/**
 * Indicates that the operation was successful but no changes where made.
 */
#define ZONELIST_IMPORT_NO_CHANGE 5

/*
 * Import zones from the configured zonelist and sync it with the database.
 * \param[in] sockfd a client socket which progress is written to if non-zero.
 * \param[in] engine a engine_type pointer.
 * \param[in] dbconn a db_connection_t pointer.
 * \param[in] do_delete a interger which will trigger deletion of zones not
 * \param[in] zonelist_path if set use this zonelist rather then one mentioned in conf.xml
 * in the zonelist if non-zero.
 * \return ZONELIST_IMPORT_ERR_* on error otherwise ZONELIST_IMPORT_OK or
 * ZONELIST_IMPORT_NO_CHANGE.
 */
extern int zonelist_import(int sockfd, engine_type* engine, db_connection_t *dbconn,
    int do_delete, const char* zonelist_path);

#endif /* _KEYSTATE_ZONELIST_IMPORT_H_ */
