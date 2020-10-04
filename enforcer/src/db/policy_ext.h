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

#ifndef __policy_ext_h
#define __policy_ext_h

#include <libxml/tree.h>

#include "zone_db.h"
#include "policy_key.h"

/**
 * Create a policy object from XML.
 * \param[in] policy a policy_t object being created.
 * \param[in] policy_node a xmlNodePtr to the XML for the policy.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_create_from_xml(policy_t* policy, xmlNodePtr policy_node);

/**
 * Update a policy object from XML.
 * \param[in] policy a policy_t object being updated.
 * \param[in] policy_node a xmlNodePtr to the XML for the policy.
 * \param[out] updated an integer pointer that will be set to non-zero if any
 * values in the policy was updated.
 * \return DB_ERROR_* on failure, otherwise DB_OK.
 */
extern int policy_update_from_xml(policy_t* policy, xmlNodePtr policy_node, int* updated);

/**
 * Get the policy keys for a policy.
 * \param[in] policy a policy_t object.
 * \return a policy_key_list_t pointer or NULL on error.
 */
extern policy_key_list_t* policy_get_policy_keys(const policy_t* policy);

#endif
