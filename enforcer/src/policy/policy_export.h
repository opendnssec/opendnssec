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

#ifndef _POLICY_POLICY_EXPORT_H_
#define _POLICY_POLICY_EXPORT_H_

#include "db/dbw.h"

/**
 * Indicates a successful policy export.
 */
#define POLICY_EXPORT_OK 0
/**
 * Indicates an error with the arguments provided to policy_export().
 */
#define POLICY_EXPORT_ERR_ARGS 1
/**
 * Indicates an error with the policy XML like parsing, validating or content.
 */
#define POLICY_EXPORT_ERR_XML 2
/**
 * Indicates an error with the database like reading, updating or creating.
 */
#define POLICY_EXPORT_ERR_DATABASE 3
/**
 * Indicates a memory allocation error or generic internal error.
 */
#define POLICY_EXPORT_ERR_MEMORY 4
/**
 * Indicates an error when handing files.
 */
#define POLICY_EXPORT_ERR_FILE 5

/**
 * Export all policies from the database to XML.
 * \param[in] sockfd a socket.
 * \param[in] dbconn a db_connection_t pointer.
 * \param[in] filename the filename to write to, if NULL write to stdout.
 * \return POLICY_EXPORT_ERR_* on error otherwise POLICY_EXPORT_OK.
 */
int policy_export_all(int sockfd, db_connection_t* connection, const char* filename);

/**
 * Export the policy from the database to XML.
 * \param[in] sockfd a socket.
 * \param[in] policy a policy_t pointer with the policy to export.
 * \param[in] filename the filename to write to, if NULL write to stdout.
 * \return POLICY_EXPORT_ERR_* on error otherwise POLICY_EXPORT_OK.
 */
int policy_export(int sockfd, const struct dbw_policy *policy, const char* filename);

#endif /* _POLICY_POLICY_EXPORT_H_ */
