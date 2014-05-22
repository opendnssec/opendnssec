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

#ifndef SIGNCONF_SIGNCONF_H_
#define SIGNCONF_SIGNCONF_H_

#include "daemon/engine.h"
#include "db/db_connection.h"
#include "db/zone.h"
#include "db/policy.h"

/**
 * Indicates a successful signconf export.
 */
#define SIGNCONF_EXPORT_OK 0
/**
 * Indicates an error with the arguments provided to signconf_export*().
 */
#define SIGNCONF_EXPORT_ERR_ARGS 1
/**
 * Indicates an error with the signconf XML like parsing, validating or content.
 */
#define SIGNCONF_EXPORT_ERR_XML 2
/**
 * Indicates an error with the database like reading, updating or creating.
 */
#define SIGNCONF_EXPORT_ERR_DATABASE 3
/**
 * Indicates a memory allocation error or generic internal error.
 */
#define SIGNCONF_EXPORT_ERR_MEMORY 4
/**
 * Indicates an error when handing files.
 */
#define SIGNCONF_EXPORT_ERR_FILE 5
/**
 * Indicates that the operation was successful but no changes where made.
 */
#define SIGNCONF_EXPORT_NO_CHANGE 6

int signconf_export_all(int sockfd, engine_type* engine, db_connection_t* connection, int force);
int signconf_export_policy(int sockfd, engine_type* engine, db_connection_t* connection, const policy_t* policy, int force);
int signconf_export(int sockfd, engine_type* engine, const policy_t* policy, const zone_t* zone, int force);

#endif /* SIGNCONF_SIGNCONF_H_ */
