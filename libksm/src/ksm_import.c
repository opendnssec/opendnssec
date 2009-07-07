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
 * ksm_import.c - Import/update configuration data in kasp database
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
 * KsmImportRepository - Insert or update a repository
 *
 *
 * Arguments:
 *
 *      const char* repo_name
 *          Name of the repository
 *
 *      const char* repo_capacity
 *          Capacity for that repository
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                         -1 if an unexpected count value was returned
-*/

int KsmImportRepository(const char* repo_name, const char* repo_capacity)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    int         count = 0;      /* Do we already have a repository with this name? */

    /* check the main argument (capacity may be NULL) */
    if (repo_name == NULL) {
        return MsgLog(KSM_INVARG, "NULL repository name");
    }

    /* 
     * First see if this repository exists
     */
    sql = DqsCountInit(DB_SECURITY_MODULE_TABLE);
    DqsConditionString(&sql, "NAME", DQS_COMPARE_EQ, repo_name, 0);
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
	}

    /* If the count was 0 then we do an insert, otherwise we do an update */
    if (count == 0)
    {
        sql = DisSpecifyInit(DB_SECURITY_MODULE_TABLE, "name, capacity");
        DisAppendString(&sql, repo_name);
        DisAppendString(&sql, repo_capacity);
        DisEnd(&sql);

        status = DbExecuteSqlNoResult(DbHandle(), sql);
        DisFree(sql);
    }
    else if (count == 1)
    {
        sql = DusInit(DB_SECURITY_MODULE_TABLE);
        DusSetString(&sql, "capacity", repo_capacity, 0);
        DusConditionString(&sql, "name", DQS_COMPARE_EQ, repo_name, 0);
        DusEnd(&sql);

        status = DbExecuteSqlNoResult(DbHandle(), sql);
        DusFree(sql);
    }
    else
    {
        return -1;
    }

    return status;
}

/*+
 * KsmImportPolicy - Insert a policy (will not be called if policy exists, unlike above
 *
 *
 * Arguments:
 *
 *      const char* policy_name
 *          Name of the policy
 *
 *      const char* policy_description
 *          Description for that policy
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                         -1 if an unexpected count value was returned
-*/

int KsmImportPolicy(const char* policy_name, const char* policy_description)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */

    /* check the main argument (description may be NULL) */
    if (policy_name == NULL) {
        return MsgLog(KSM_INVARG, "NULL policy name");
    }

    /* Insert policy */
    sql = DisSpecifyInit("policies", "name, description");
    DisAppendString(&sql, policy_name);
    DisAppendString(&sql, policy_description);
    DisEnd(&sql);

    status = DbExecuteSqlNoResult(DbHandle(), sql);
    DisFree(sql);

    return status;
}

/*+
 * KsmImportZone - Insert or update a zone
 *
 *
 * Arguments:
 *
 *      const char* zone_name
 *          Name of the repository
 *
 *      int policy_id
 *          Policy for the zone
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                         -1 if an unexpected count value was returned
-*/

int KsmImportZone(const char* zone_name, int policy_id)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    int         count = 0;      /* Do we already have a zone with this name? */

    /* check the arguments */
    if (zone_name == NULL || policy_id == 0) {
        return MsgLog(KSM_INVARG, "NULL zone name or policy");
    }

    /* 
     * First see if this repository exists
     */
    sql = DqsCountInit(DB_ZONE_TABLE);
    DqsConditionString(&sql, "NAME", DQS_COMPARE_EQ, zone_name, 0);
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
	}

    /* If the count was 0 then we do an insert, otherwise we do an update */
    if (count == 0)
    {
        sql = DisSpecifyInit(DB_ZONE_TABLE, "name, policy_id");
        DisAppendString(&sql, zone_name);
        DisAppendInt(&sql, policy_id);
        DisEnd(&sql);

        status = DbExecuteSqlNoResult(DbHandle(), sql);
        DisFree(sql);
    }
    else if (count == 1)
    {
        sql = DusInit(DB_ZONE_TABLE);
        DusSetInt(&sql, "policy_id", policy_id, 0);
        DusConditionString(&sql, "name", DQS_COMPARE_EQ, zone_name, 0);
        DusEnd(&sql);

        status = DbExecuteSqlNoResult(DbHandle(), sql);
        DusFree(sql);
    }
    else
    {
        return -1;
    }

    return status;
}

int KsmSmIdFromName(const char* name, int *id)
{
    char*   sql = NULL;         /* SQL query */
    int     status = 0;         /* Status return */

    /* check the argument */
    if (name == NULL) {
        return MsgLog(KSM_INVARG, "NULL name");
    }

    /* Construct the query */

    sql = DqsSpecifyInit(DB_SECURITY_MODULE_TABLE,"id");
    DqsConditionString(&sql, "name", DQS_COMPARE_EQ, name, 0);
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), id, sql);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
	}

    return status;
}

int KsmSerialIdFromName(const char* name, int *id)
{
    char*   sql = NULL;         /* SQL query */
    int     status = 0;         /* Status return */

    /* check the argument */
    if (name == NULL) {
        return MsgLog(KSM_INVARG, "NULL name");
    }

    /* Construct the query */

    sql = DqsSpecifyInit("serialmodes","id");
    DqsConditionString(&sql, "name", DQS_COMPARE_EQ, name, 0);
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), id, sql);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
	}

    return status;
}

int KsmPolicyIdFromName(const char* name, int *id)
{
    char*   sql = NULL;         /* SQL query */
    int     status = 0;         /* Status return */

    /* check the argument */
    if (name == NULL) {
        return MsgLog(KSM_INVARG, "NULL name");
    }

    /* Construct the query */

    sql = DqsSpecifyInit("policies","id");
    DqsConditionString(&sql, "name", DQS_COMPARE_EQ, name, 0);
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), id, sql);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
	}

    return status;
}
