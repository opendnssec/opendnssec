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

#include "hsm_key.h"
#include "db_error.h"

hsm_key_list_t* hsm_key_list_new_get_by_policy_key(const policy_key_t *pkey)
{
    hsm_key_list_t* hkey_list = NULL;
    db_clause_list_t* clause_list;
    db_clause_t* clause;

    if (!pkey || !pkey->dbo || !(clause_list = db_clause_list_new()))
        return NULL;
    
    if (!(clause = db_clause_new())
        || db_clause_set_field(clause, "policyId")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_copy(db_clause_get_value(clause), policy_key_policy_id(pkey))
        || db_clause_list_add(clause_list, clause)

        || !(clause = db_clause_new())
        || db_clause_set_field(clause, "algorithm")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_uint32(db_clause_get_value(clause), policy_key_algorithm(pkey))
        || db_clause_list_add(clause_list, clause)

        || !(clause = db_clause_new())
        || db_clause_set_field(clause, "bits")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_uint32(db_clause_get_value(clause), policy_key_bits(pkey))
        || db_clause_list_add(clause_list, clause)

        || !(clause = db_clause_new())
        || db_clause_set_field(clause, "repository")
        || db_clause_set_type(clause, DB_CLAUSE_EQUAL)
        || db_value_from_text(db_clause_get_value(clause), policy_key_repository(pkey))
        || db_clause_list_add(clause_list, clause))
    {
        db_clause_free(clause);
        db_clause_list_free(clause_list);
        return NULL;
    }

    hkey_list = hsm_key_list_new_get_by_clauses(
        db_object_connection(pkey->dbo), clause_list);
    db_clause_list_free(clause_list);
    return hkey_list;
}
