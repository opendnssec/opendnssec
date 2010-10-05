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
 * Signatures.
 *
 */

#ifndef SIGNER_RRSIGS_H
#define SIGNER_RRSIGS_H

#include "config.h"
#include "signer/se_key.h"

#include <ldns/ldns.h>

typedef struct rrsigs_struct rrsigs_type;
struct rrsigs_struct {
    ldns_rr* rr;
    const char* key_locator;
    uint32_t key_flags;
    rrsigs_type* next;
};

/**
 * Create new signature set.
 * \return rrsigs_type* new RRSIGS set
 *
 */
rrsigs_type* rrsigs_create(void);

/**
 * Add RRSIG to signature set.
 * \param[in] rrsigs signature set
 * \param[in] rr RRSIG record
 * \param[in] key key used to create this signature
 * \return int 0 on success, 1 on error
 *
 */
int rrsigs_add_sig(rrsigs_type* rrsigs, ldns_rr* rr, key_type* key);

/*
 * Clean up signature set.
 * \param[in] rrsigs signature set to clean up
 *
 */
void rrsigs_cleanup(rrsigs_type* rrsigs);

/**
 * Print signature set.
 * \param[in] fd file descriptor
 * \param[in] rrsigs signature set to be printed
 * \param[in] print_key if key credentials should be printed
 *
 */
void rrsigs_print(FILE* fd, rrsigs_type* rrsigs, int print_key);

#endif /* SIGNER_RRSIGS_H */
