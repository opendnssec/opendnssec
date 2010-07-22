/*
 * $Id$
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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
 *
 * Utility tools.
 */

#ifndef UTIL_UTIL_H
#define UTIL_UTIL_H

#include "config.h"

#include <ldns/ldns.h>

/* copycode: This define is taken from BIND9 */
#define DNS_SERIAL_GT(a, b) ((int)(((a) - (b)) & 0xFFFFFFFF) > 0)

/**
 * Check if a RR is a DNSSEC RR (RRSIG, NSEC, NSEC3 or NSEC3PARAMS).
 * \param[in] rr RR
 * \return int 1 on true, 0 on false
 *
 */
int util_is_dnssec_rr(ldns_rr* rr);

/**
 * Compare RRs only on RDATA.
 * \param[in] rr1 RR
 * \param[in] rr2 another RR
 * \param[out] cmp compare value
 * \return status compare status
 *
 */
ldns_status util_dnssec_rrs_compare(ldns_rr* rr1, ldns_rr* rr2, int* cmp);

/**
 * A more efficient ldns_dnssec_rrs_add_rr(), get rid of ldns_rr_compare().
 * \param[in] rrs RRset
 * \param[in] rr to add
 * \return ldns_status status
 *
 */
ldns_status util_dnssec_rrs_add_rr(ldns_dnssec_rrs *rrs, ldns_rr *rr);

#endif /* UTIL_UTIL_H */
