/*
 * ksm_zone.c - Manipulation of Zone Information
 *
 * Copyright (c) 2008, John Dickinson. All rights reserved.
 * Part of OpenDNSSEC.org
 *
 * Based on ksm_parameter.c code supplied by Nominet
 * See LICENSE for the license.
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "database.h"
#include "database_statement.h"
#include "datetime.h"
#include "db_fields.h"
#include "debug.h"
#include "ksmdef.h"
#include "ksm.h"
#include "ksm_internal.h"
#include "message.h"
#include "string_util.h"

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
    DqsConditionKeyword(&sql, "z.in_adapter_id", DQS_COMPARE_EQ,"i.id", where++);
    DqsConditionKeyword (&sql, "z.out_adapter_id", DQS_COMPARE_EQ,"o.id", where++);
    if (policy_id) {
        DqsConditionInt(&sql, "z.policy_id", DQS_COMPARE_EQ, policy_id, where++);

    }
    DqsOrderBy(&sql, "z.NAME");

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

	sql = DqsCountInit(DB_ZONE_TABLE_RAW);
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
    DB_ROW      row;            /* Row data */

    /* Get the next row from the data */
    status = DbFetchRow(result, &row);

    if (status == 0) {

        /* Now copy the results into the output data */
        DbInt(row, DB_ZONE_ID, data->id);
        DbStringBuffer(row, DB_ZONE_NAME, data->name,
            KSM_NAME_LENGTH*sizeof(char));
        DbStringBuffer(row, DB_ZONE_IADAPTER, data->in_adapter,
             KSM_NAME_LENGTH*sizeof(char));
        DbStringBuffer(row, DB_ZONE_OADAPTER, data->out_adapter,
                     KSM_NAME_LENGTH*sizeof(char));
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

