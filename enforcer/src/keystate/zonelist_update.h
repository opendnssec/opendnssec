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

#ifndef _KEYSTATE_ZONELIST_UPDATE_H_
#define _KEYSTATE_ZONELIST_UPDATE_H_

#include "db/dbw.h"

/**
 * Indicates a successful zonelist update.
 */
#define ZONELIST_UPDATE_OK 0
/**
 * Indicates an error with the arguments provided to zonelist_update().
 */
#define ZONELIST_UPDATE_ERR_ARGS 1
/**
 * Indicates an error with the zonelist XML like parsing, validating or content.
 */
#define ZONELIST_UPDATE_ERR_XML 2
/**
 * Indicates an error with the database like reading, updating or creating.
 */
#define ZONELIST_UPDATE_ERR_DATABASE 3
/**
 * Indicates a memory allocation error or generic internal error.
 */
#define ZONELIST_UPDATE_ERR_MEMORY 4
/**
 * Indicates an error when handing files.
 */
#define ZONELIST_UPDATE_ERR_FILE 5

/**
 * Update a zonelist and add the supplied zone to it.
 * \param[in] sockfd socket fd.
 * \param[in] filename the zonelist filename to write to.
 * \param[in] zone a zone_db_t pointer to the zone to add.
 * \param[in] comment if non-zero include a comment about the zonelist file.
 * \return ZONELIST_UPDATE_ERR_* on error otherwise ZONELIST_UPDATE_OK.
 */
extern int zonelist_update_add(int sockfd, const char* filename,
       const struct dbw_zone* zone, const char *policyname, int comment);

/**
 * Update a zonelist and remove the supplied zone from it.
 * \param[in] sockfd socket fd.
 * \param[in] filename the zonelist filename to write to.
 * \param[in] zone a zone_db_t pointer to the zone to remove.
 * \param[in] comment if non-zero include a comment about the zonelist file.
 * \return ZONELIST_UPDATE_ERR_* on error otherwise ZONELIST_UPDATE_OK.
 */
extern int zonelist_update_delete(int sockfd, const char* filename,
       const struct dbw_zone* zone, const char *policyname, int comment);
#endif /* _KEYSTATE_ZONELIST_UPDATE_H_ */
