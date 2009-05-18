/*
 * $Id$
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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

/*
 * ksm_dnsseckeys.c - Manipulation of dnssec key Information
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ksm/database.h"
#include "ksm/database_statement.h"
#include "ksm/datetime.h"
#include "ksm/db_fields.h"
#include "ksm/debug.h"
#include "ksm/ksmdef.h"
#include "ksm/ksm.h"
#include "ksm/ksm_internal.h"
#include "ksm/message.h"
#include "ksm/string_util.h"

/*+
 * KsmDNSSECKeysInSMCountInit - Query for Key Information
 *
 *
 * Arguments:
 *      DB_RESULT* result
 *          Pointer to a handle to be used for information retrieval.  Will
 *          be NULL on error.
 *
 *      int id
 *          optional id of the security module that the keys must be in
 *
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
-*/

int KsmDNSSECKeysInSMCountInit(DB_RESULT* result, int id)
{
	int     where = 0;          /* WHERE clause value */
	char*   sql = NULL;         /* SQL query */
	int     status = 0;         /* Status return */

	/* Construct the query */

	sql = DqsCountInit("dnsseckeys");
	if (id >= 0) {
		DqsConditionInt(&sql, "securitymodule_id", DQS_COMPARE_EQ, id, where++);
	}


	/* Execute query and free up the query string */

	status = DbExecuteSql(DbHandle(), sql, result);

	DqsFree(sql);

	return status;
}

/*+
 * KsmDNSSECKeysInSMCountInit - Query for Policy Information
 *
 *
 * Arguments:
 *      DB_RESULT* result
 *          Pointer to a handle to be used for information retrieval.  Will
 *          be NULL on error.
 *
 *      policy_id
 *          id of the policy that keys must belong to
 *
 *      key_policy
 *          key policy that the keys must be consitent with.
 *
 *      int state
 *      	state that the key must be in
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
-*/


int KsmDNSSECKeysStateCountInit(DB_RESULT* result, int policy_id, KSM_KEY_POLICY *key_policy, int state)
{
	int     where = 0;          /* WHERE clause value */
	char*   sql = NULL;         /* SQL query */
	int     status = 0;         /* Status return */

    /* Check arguments */
    if (key_policy == NULL) {
        return MsgLog(KSM_INVARG, "NULL key_policy");
    }

	/* Construct the query */

	sql = DqsCountInit("dnsseckeys");

	DqsConditionInt(&sql, "securitymodule_id", DQS_COMPARE_EQ, key_policy->sm, where++);
	DqsConditionInt(&sql, "policy_id", DQS_COMPARE_EQ, policy_id, where++);
	DqsConditionInt(&sql, "size", DQS_COMPARE_EQ, key_policy->bits, where++);
	DqsConditionInt(&sql, "algorithm", DQS_COMPARE_EQ, key_policy->algorithm, where++);
	DqsConditionInt(&sql, "keytype", DQS_COMPARE_EQ, key_policy->type, where++);
	DqsConditionInt(&sql, "state", DQS_COMPARE_EQ, state, where++);


	/* Execute query and free up the query string */

	status = DbExecuteSql(DbHandle(), sql, result);

	DqsFree(sql);

	return status;
}

/*+
 * KsmDNSSECKeysInSMCount
 *
 * Arguments:
 *      DB_RESULT result
 *          Handle from KsmParameterInit
 *
 *		count (returns)
 *          count of keys found
 *
 * Returns:
 *      int
 *          Status return:
 *              0           success
 *              -1          end of record set reached
 *              non-zero    some error occurred and a message has been output.
 *
 *          If the status is non-zero, the returned data is meaningless.
-*/

int KsmDNSSECKeysInSMCount(DB_RESULT result, int* count)
{
	int         status = 0;     /* Return status */
	DB_ROW      row;            /* Row data */

	/* Get the next row from the data */

	status = DbFetchRow(result, &row);
	if (status == 0) {

		/* Now copy the results into the output data */

		status = DbInt(row, DB_COUNT, count);
	}
    else if (status == -1) {}
        /* No rows to return (but no error) */
	else {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
	}

    DbFreeRow(row);

	return status;
}
