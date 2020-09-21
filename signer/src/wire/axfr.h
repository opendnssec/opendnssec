/*
 * Copyright (c) 2011-2018 NLNet Labs.
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
 * AXFR.
 *
 */

#ifndef WIRE_AXFR_H
#define WIRE_AXFR_H

#include "config.h"
#include "daemon/engine.h"
#include "wire/query.h"

#include <ldns/ldns.h>

/* NSD values */
#define MAX_COMPRESSION_OFFSET 16383 /* Compression pointers are 14 bit. */
#define AXFR_MAX_MESSAGE_LEN MAX_COMPRESSION_OFFSET

/**
 * Handle SOA request.
 * \param[in] q soa request
 * \param[in] engine signer engine
 * \return query_state state of the query
 *
 */
extern query_state soa_request(query_type* q, engine_type* engine);

/**
 * Do AXFR.
 * \param[in] q axfr request
 * \param[in] engine signer engine
 * \param[in] fallback fallback from ixfr?
 * \return query_state state of the query
 *
 */
extern query_state axfr(query_type* q, engine_type* engine, int fallback);

/**
 * Do IXFR.
 * \param[in] q ixfr request
 * \param[in] engine signer engine
 * \return query_state state of the query
 *
 */
extern query_state ixfr(query_type* q, engine_type* engine);

#endif /* WIRE_AXFR_H */
