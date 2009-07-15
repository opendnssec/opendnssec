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
 * ksm_zone.c - Manipulation of Zone Information
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
 * KsmZoneInit - Query for Zone Information
 *
 *
 * Arguments:
 *      DB_RESULT* result
 *          Pointer to a handle to be used for information retrieval.  Will
 *          be NULL on error.
 *
 *      const char* name
 *          Name of the parameter to retrieve information on.  If NULL, information
 *          on all parameters is retrieved.
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
-*/

int KsmZoneInit(DB_RESULT* result, int policy_id)
{
    int     where = 0;          /* WHERE clause value */
    char*   sql = NULL;         /* SQL query */
    int     status = 0;         /* Status return */

    /* Construct the query */

    sql = DqsSpecifyInit(DB_ZONE_TABLE, DB_ZONE_FIELDS);
    if (policy_id) {
        DqsConditionInt(&sql, "policy_id", DQS_COMPARE_EQ, policy_id, where++);

    }
    DqsOrderBy(&sql, "NAME");

    /* Execute query and free up the query string */

    status = DbExecuteSql(DbHandle(), sql, result);

    DqsFree(sql);

    return status;
}

/*+
 * KsmZoneCountInit
 *
 *
 * Arguments:
 *      DB_RESULT* result
 *          Pointer to a handle to be used for information retrieval.  Will
 *          be NULL on error.
 *
 *      id
 *          id of the policy
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
-*/

int KsmZoneCountInit(DB_RESULT* result, int id)
{
	int     where = 0;          /* WHERE clause value */
	char*   sql = NULL;         /* SQL query */
	int     status = 0;         /* Status return */

	/* Construct the query */

	sql = DqsCountInit(DB_ZONE_TABLE);
	if (id >= 0) {
		DqsConditionInt(&sql, "policy_id", DQS_COMPARE_EQ, id, where++);
	}


	/* Execute query and free up the query string */

	status = DbExecuteSql(DbHandle(), sql, result);

	DqsFree(sql);

	return status;
}

/*+
 * KsmZone - Return Zone Information
 *
 * Arguments:
 *      DB_RESULT result
 *          Handle from KsmParameterInit
 *
 *      KSM_PARAMETER* data
 *          Data is returned in here.
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

int KsmZone(DB_RESULT result, KSM_ZONE *data)
{
    int         status = 0;     /* Return status */
    DB_ROW      row = NULL;     /* Row data */

    /* Get the next row from the data */
    status = DbFetchRow(result, &row);

    if (status == 0) {

        /* Now copy the results into the output data */
        DbInt(row, DB_ZONE_ID, &(data->id));
        DbStringBuffer(row, DB_ZONE_NAME, data->name,
            KSM_NAME_LENGTH*sizeof(char));
    }
    else if (status == -1) {}
        /* No rows to return (but no error) */
	else {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
	}

    if (row != NULL) {
        DbFreeRow(row);
    }

    return status;
}
/*+
 * KsmZoneCount
 *
 * Arguments:
 *      DB_RESULT result
 *          Handle from KsmParameterInit
 *
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

int KsmZoneCount(DB_RESULT result, int* count)
{
	int         status = 0;     /* Return status */
	DB_ROW      row = NULL;            /* Row data */

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

/*+
 * KsmZoneIdFromName
 *
 * Arguments:
 *          const char* zone_name   name of the zone to get the id for
 *          int*        zone_id     returned id
 *
 * Returns:
 *      int
 *          Status return:
 *              0           success
 *              -1          no record found
 *              non-zero    some error occurred and a message has been output.
 *
 *          If the status is non-zero, the returned data is meaningless.
-*/
int KsmZoneIdFromName(const char* zone_name, int* zone_id)
{
    int     where = 0;          /* WHERE clause value */
    char*   sql = NULL;         /* SQL query */
    DB_RESULT       result;     /* Handle converted to a result object */
    DB_ROW      row = NULL;            /* Row data */
    int     status = 0;         /* Status return */

    /* check the argument */
    if (zone_name == NULL) {
        return MsgLog(KSM_INVARG, "NULL zone name");
    }

    /* Construct the query */

    sql = DqsSpecifyInit("zones","id, name");
    DqsConditionString(&sql, "NAME", DQS_COMPARE_EQ, zone_name, where++);
    DqsOrderBy(&sql, "id");

    /* Execute query and free up the query string */
    status = DbExecuteSql(DbHandle(), sql, &result);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        DbFreeResult(result);
        return status;
	}

    /* Get the next row from the data */
    status = DbFetchRow(result, &row);
    if (status == 0) {
        DbInt(row, DB_ZONE_ID, zone_id);
    }
    else if (status == -1) {}
        /* No rows to return (but no DB error) */
	else {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
	}

    DbFreeRow(row);
    DbFreeResult(result);
    return status;
}

/*+
 * KsmZoneIdAndPolicyFromName
 *
 * Arguments:
 *          const char* zone_name   name of the zone to get the id for
 *          int*        policy_id   returned id
 *          int*        zone_id     returned id
 *
 * Returns:
 *      int
 *          Status return:
 *              0           success
 *              -1          no record found
 *              non-zero    some error occurred and a message has been output.
 *
 *          If the status is non-zero, the returned data is meaningless.
-*/
int KsmZoneIdAndPolicyFromName(const char* zone_name, int* policy_id, int* zone_id)
{
    int     where = 0;          /* WHERE clause value */
    char*   sql = NULL;         /* SQL query */
    DB_RESULT       result;     /* Handle converted to a result object */
    DB_ROW      row = NULL;            /* Row data */
    int     status = 0;         /* Status return */

    /* check the argument */
    if (zone_name == NULL) {
        return MsgLog(KSM_INVARG, "NULL zone name");
    }

    /* Construct the query */

    sql = DqsSpecifyInit("zones","id, name, policy_id");
    DqsConditionString(&sql, "NAME", DQS_COMPARE_EQ, zone_name, where++);
    DqsOrderBy(&sql, "id");

    /* Execute query and free up the query string */
    status = DbExecuteSql(DbHandle(), sql, &result);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        DbFreeResult(result);
        return status;
	}

    /* Get the next row from the data */
    status = DbFetchRow(result, &row);
    if (status == 0) {
        DbInt(row, DB_ZONE_ID, zone_id);
        DbInt(row, DB_ZONE_POLICY_ID, policy_id);
    }
    else if (status == -1) {}
        /* No rows to return (but no DB error) */
	else {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
	}

    DbFreeRow(row);
    DbFreeResult(result);
    return status;
}
