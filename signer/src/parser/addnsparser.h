/*
 * Copyright (c) 2009-2018 NLNet Labs.
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
 */

/**
 * Parsing DNS Adapter.
 *
 */

#ifndef PARSER_ADDNSPARSER_H
#define PARSER_ADDNSPARSER_H

#include "wire/acl.h"
#include "wire/tsig.h"

#include <libxml/xpath.h>
#include <libxml/xmlreader.h>

/**
 * Parse <RequestTransfer/>.
 * \param[in] allocator memory allocator
 * \param[in] filename filename
 * \param[in] tsig list of TSIGs
 * \return acl_type* ACL
 *
 */
extern acl_type* parse_addns_request_xfr(const char* filename, tsig_type* tsig);

/**
 * Parse <AllowNotify/>.
 * \param[in] allocator memory allocator
 * \param[in] filename filename
 * \param[in] tsig list of TSIGs
 * \return acl_type* ACL
 *
 */
extern acl_type* parse_addns_allow_notify(const char* filename, tsig_type* tsig);

/**
 * Parse <ProvideTransfer/>.
 * \param[in] allocator memory allocator
 * \param[in] filename filename
 * \param[in] tsig list of TSIGs
 * \return acl_type* ACL
 *
 */
extern acl_type* parse_addns_provide_xfr(const char* filename, tsig_type* tsig);

/**
 * Parse <Notify/>.
 * \param[in] allocator memory allocator
 * \param[in] filename filename
 * \param[in] tsig list of TSIGs
 * \return acl_type* ACL
 *
 */
extern acl_type* parse_addns_do_notify(const char* filename, tsig_type* tsig);

/**
 * Parse <TSIG/>.
 * \param[in] allocator memory allocator
 * \param[in] filename filename
 * \return tsig_type* TSIG
 *
 */
extern tsig_type* parse_addns_tsig(const char* filename);

#endif /* PARSER_ADDNSPARSER_H */
