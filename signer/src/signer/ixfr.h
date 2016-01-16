/*
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
 * Domain name database.
 *
 */

#ifndef SIGNER_IXFR_H
#define SIGNER_IXFR_H

#include "config.h"
#include <ldns/ldns.h>

typedef struct part_struct part_type;
typedef struct ixfr_struct ixfr_type;

#include "locks.h"
#include "zone.h"

#define IXFR_MAX_PARTS 3

/**
 * Part of IXFR Journal.
 *
 */
struct part_struct {
    ldns_rr* soamin;
    ldns_rr_list* min;
    ldns_rr* soaplus;
    ldns_rr_list* plus;
};

/**
 * IXFR Journal.
 *
 */
struct ixfr_struct {
    zone_type* zone;
    part_type* part[IXFR_MAX_PARTS];
    lock_basic_type ixfr_lock;
};

/**
 * Create a new ixfr journal.
 * \param[in] zone zone reference
 * \return ixfr_type* ixfr
 *
 */
ixfr_type* ixfr_create(zone_type* zone);

/**
 * Add +RR to ixfr journal.
 * \param[in] ixfr journal
 * \param[in] rr +RR
 *
 */
void ixfr_add_rr(ixfr_type* ixfr, ldns_rr* rr);

/**
 * Add -RR to ixfr journal.
 * \param[in] ixfr journal
 * \param[in] rr -RR
 *
 */
void ixfr_del_rr(ixfr_type* ixfr, ldns_rr* rr);

/**
 * Print the ixfr journal.
 * \param[in] fd file descriptor
 * \param[in] ixfr journal
 *
 */
void ixfr_print(FILE* fd, ixfr_type* ixfr);

/**
 * Purge the ixfr journal.
 * \param[in] ixfr journal
 *
 */
void ixfr_purge(ixfr_type* ixfr);

/**
 * Cleanup the ixfr journal.
 * \param[in] ixfr journal
 *
 */
void ixfr_cleanup(ixfr_type* ixfr);

#endif /* SIGNER_IXFR_H */
