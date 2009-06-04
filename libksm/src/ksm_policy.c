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
 * ksm_policy.c - Manipulation of Policy Information
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
#include "ksm/kmedef.h"
#include "ksm/ksm.h"
#include "ksm/ksm_internal.h"
#include "ksm/message.h"
#include "ksm/string_util.h"

/*+
 * KsmPolicyInit - Query for Policy Information
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

int KsmPolicyInit(DB_RESULT* result, const char* name)
{
    int     where = 0;          /* WHERE clause value */
    char*   sql = NULL;         /* SQL query */
    int     status = 0;         /* Status return */

    /* Construct the query */

    sql = DqsSpecifyInit("policies","id, name");
    if (name) {
        DqsConditionString(&sql, "NAME", DQS_COMPARE_EQ, name, where++);
    }
    DqsOrderBy(&sql, "id");

    /* Execute query and free up the query string */

    status = DbExecuteSql(DbHandle(), sql, result);

    DqsFree(sql);

    return status;
}

/*+
 * KsmPolicyParametersInit - Query for Policy Information
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

int KsmPolicyParametersInit(DB_RESULT* result, const char* name)
{
    int     where = 0;          /* WHERE clause value */
    char*   sql = NULL;         /* SQL query */
    int     status = 0;         /* Status return */

    /* Construct the query */

    sql = DqsSpecifyInit("policies p, parameters_policies x, parameters y, categories c ","y.name, c.name, x.value");
    DqsConditionKeyword(&sql, "p.id", DQS_COMPARE_EQ, "x.policy_id", where++);
    DqsConditionKeyword(&sql, "y.id", DQS_COMPARE_EQ, "x.parameter_id", where++);
    DqsConditionKeyword(&sql, "c.id", DQS_COMPARE_EQ, "y.category_id", where++);
    if (name) {
        DqsConditionString(&sql, "p.NAME", DQS_COMPARE_EQ, name, where++);
    }
    DqsOrderBy(&sql, "p.NAME");

    /* Execute query and free up the query string */

    status = DbExecuteSql(DbHandle(), sql, result);

    DqsFree(sql);

    return status;
}

/*+
 * KsmPolicyExists - Check Policy Exists
 *
 *
 * Arguments:
 *      const char* name
 *          Name of the parameter.
 *
 *
 * Returns:
 *      int
 *          0       Success, value found
 *          Other   Error, message has been output
-*/

int KsmPolicyExists(const char* name)
{
    int             status;     /* Status return */
    DB_RESULT       result;     /* Handle converted to a result object */
    DB_ROW          row;        /* Row data */

    status = KsmPolicyInit(&result, name);
    if (status == 0) {
        /* Get the next row from the data */
        status = DbFetchRow(result, &row);
        if (status > 0) {
            /* Error */
            status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        }
    }
    DbFreeRow(row);
    DbFreeResult(result);
    return status;
}

/*+
 * KsmPolicy - Return Policy Information
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

int KsmPolicy(DB_RESULT result, KSM_POLICY* data)
{
    int         status = 0;     /* Return status */
    DB_ROW      row;            /* Row data */

    /* check the argument */
    if (data == NULL) {
        return MsgLog(KSM_INVARG, "NULL data");
    }

    /* Get the next row from the data */
    status = DbFetchRow(result, &row);
    if (status == 0) {

        status = DbInt(row, DB_POLICY_ID, &(data->id));
        DbStringBuffer(row, DB_POLICY_NAME, data->name, KSM_NAME_LENGTH*sizeof(char));
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
 * KsmPolicyRead - Read Policy
 *
 * Description:
 *      Read policy from database in to a struct.
 *
 * Arguments:
 *      struct policy_t policy
 *      	struct to hold policy information
 *      const char* name
 *          Name of parameter to output, or NULL for all parameters.
-*/

int KsmPolicyRead(KSM_POLICY* policy)
{
    KSM_POLICY_PARAMETER data;           /* Parameter information */
    DB_RESULT            result;         /* Handle to parameter */
    int                  status = 0;     /* Status return */

    /* check the argument */
    if (policy == NULL) {
        return MsgLog(KSM_INVARG, "NULL policy");
    }

    /* status = KsmPolicyExists(policy->name); */
    status = KsmPolicySetIdFromName(policy);

    if (status == 0) {

        status = KsmPolicyParametersInit(&result, policy->name);
        if (status == 0) {
            status = KsmPolicyParameter(result, &data);
            while (status == 0) {
            	if (strncmp(data.category, "enforcer", 8) == 0) {
/*            		if (strncmp(data.name, "keycreate", 9) == 0) policy->enforcer->keycreate=data.value; */
            		if (strncmp(data.name, "backup_interval", 15) == 0) policy->enforcer->backup_interval=data.value;
			if (strncmp(data.name, "keygeninterval", 14) == 0) policy->enforcer->keygeninterval=data.value;
            	}
            	if (strncmp(data.category, "zone", 4) == 0) {
            		if (strncmp(data.name, "propagationdelay", 16) == 0) policy->signer->propdelay=data.value;
            		if (strncmp(data.name, "min", 6) == 0) policy->signer->soamin=data.value;
            		if (strncmp(data.name, "ttl", 6) == 0) policy->signer->soattl=data.value;
            		if (strncmp(data.name, "serial", 6) == 0) policy->signer->serial=data.value;
            	}
            	if (strncmp(data.category, "signature", 9) == 0) {
            		if (strncmp(data.name, "jitter", 6) == 0) policy->signer->jitter=data.value;
            		if (strncmp(data.name, "refresh", 7) == 0) policy->signer->refresh=data.value;
            		if (strncmp(data.name, "clockskew", 9) == 0) policy->signature->clockskew=data.value;
            		if (strncmp(data.name, "resign", 6) == 0) policy->signature->resign=data.value;
            		if (strncmp(data.name, "valdefault", 10) == 0) policy->signature->valdefault=data.value;
            		if (strncmp(data.name, "valdenial", 10) == 0) policy->signature->valdefault=data.value;
            	}
            	if (strncmp(data.category, "denial", 6) == 0) {
            		if (strncmp(data.name, "version", 7) == 0) policy->denial->version=data.value;
            		if (strncmp(data.name, "resalt", 6) == 0) policy->denial->resalt=data.value;
            		if (strncmp(data.name, "alg", 3) == 0) policy->denial->algorithm=data.value;
            		if (strncmp(data.name, "iteration", 9) == 0) policy->denial->iteration=data.value;
            		if (strncmp(data.name, "optout", 6) == 0) policy->denial->optout=data.value;
            		if (strncmp(data.name, "ttl",3) == 0) policy->denial->ttl=data.value;
            		if (strncmp(data.name, "saltlength",10) == 0) policy->denial->saltlength=data.value;
            	}
            	if (strncmp(data.category, "zsk", 3) == 0) {
            		if (strncmp(data.name, "alg",3) == 0) policy->zsk->algorithm=data.value;
            		if (strncmp(data.name, "lifetime",8) == 0) policy->zsk->lifetime=data.value;
            		if (strncmp(data.name, "repository",10) == 0) policy->zsk->sm=data.value;
            		if (strncmp(data.name, "overlap",7) == 0) policy->zsk->overlap=data.value;
            		if (strncmp(data.name, "bits",4) == 0) policy->zsk->bits=data.value;
            	}
            	if (strncmp(data.category, "ksk", 3) == 0) {
            		if (strncmp(data.name, "alg",3) == 0) policy->ksk->algorithm=data.value;
            		if (strncmp(data.name, "lifetime",8) == 0) policy->ksk->lifetime=data.value;
            		if (strncmp(data.name, "repository",10) == 0) policy->ksk->sm=data.value;
            		if (strncmp(data.name, "overlap",7) == 0) policy->ksk->overlap=data.value;
            		if (strncmp(data.name, "rfc5011",7) == 0) policy->ksk->rfc5011=data.value;
            		if (strncmp(data.name, "bits",4) == 0) policy->ksk->bits=data.value;
            	}
            	if (strncmp(data.category, "keys", 4) == 0) {
            		if (strncmp(data.name, "ttl",3) == 0) policy->ksk->ttl=data.value;
            		if (strncmp(data.name, "ttl",3) == 0) policy->zsk->ttl=data.value;
            		if (strncmp(data.name, "zones_share_keys",4) == 0) policy->shared_keys=data.value;
            	}
           		/* Ignore any unknown parameters */

                status = KsmPolicyParameter(result, &data);
            }

            /* All done, so tidy up */

            KsmParameterEnd(result);
        }
    } else {
        return status;
    }

    /* convert security module ids into names */
    status = KsmPolicyPopulateSMFromIds(policy);

    return status;
}

/*+
 * KsmPolicyParameter - Return PolicyParameter Information
 *
 * Description:
 *      Returns information about the next key in the result set.
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

int KsmPolicyParameter(DB_RESULT result, KSM_POLICY_PARAMETER* data)
{
    int         status = 0;     /* Return status */
    DB_ROW     row;            /* Row data */

    /* check the argument */
    if (data == NULL) {
        return MsgLog(KSM_INVARG, "NULL data");
    }

    /* Get the next row from the data */
    status = DbFetchRow(result, &row);

    if (status == 0) {

        /* Now copy the results into the output data */

        memset(data, 0, sizeof(KSM_POLICY_PARAMETER));
        DbStringBuffer(row, DB_POLICY_PARAMETER_NAME, data->name,
            sizeof(data->name));
        DbStringBuffer(row, DB_POLICY_PARAMETER_CATEGORY, data->category,
                    sizeof(data->category));
        status = DbInt(row, DB_POLICY_PARAMETER_VALUE, &(data->value));
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
 * KsmPolicyReadFromId - Read Policy given just the id
 *
 * Description:
 *      Read policy from database in to a struct.
 *
 * Arguments:
 *      struct policy_t policy
 *      	struct to hold policy information should have id populated
-*/

int KsmPolicyReadFromId(KSM_POLICY* policy)
{
    int status = KsmPolicyNameFromId(policy);

    if (status != 0)
    {
        return status;
    }

    return KsmPolicyRead(policy);

}

int KsmPolicyNameFromId(KSM_POLICY* policy)
{
    int     where = 0;          /* WHERE clause value */
    char*   sql = NULL;         /* SQL query */
    DB_RESULT       result;     /* Handle converted to a result object */
    DB_ROW      row;            /* Row data */
    int     status = 0;         /* Status return */

    /* check the argument */
    if (policy == NULL) {
        return MsgLog(KSM_INVARG, "NULL policy");
    }

    /* Construct the query */

    sql = DqsSpecifyInit("policies","id, name");
    DqsConditionInt(&sql, "ID", DQS_COMPARE_EQ, policy->id, where++);
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
        DbStringBuffer(row, DB_POLICY_NAME, policy->name, KSM_NAME_LENGTH*sizeof(char));
    }
    else if (status == -1) {}
        /* No rows to return (but no error) */
	else {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
	}

    DbFreeRow(row);
    DbFreeResult(result);
    return status;
}

/*+
 * KsmPolicyUpdateSalt
 *
 * Description:
 *      Given a policy see if the salt needs updating (based on denial->resalt).
 *      If it is out of date then generate a new salt and write it to the struct.
 *      Also update the database with the new value and timestamp.
 *
 * Arguments:
 *      struct policy_t policy
 *      	struct which holds the current policy information should have been populated
 *
 * Returns:
 *      int
 *          Status return:
 *              0           success
 *              non-zero    some error occurred and a message has been output.
 *              -1          no policy found
 *              -2          an error working out time difference between stamp and now
 *
-*/

int KsmPolicyUpdateSalt(KSM_POLICY* policy)
{
    /* First work out what the current salt is and when it was created */
    int     where = 0;          /* WHERE clause value */
    char*   sql = NULL;         /* SQL query */
    DB_RESULT       result;     /* Handle converted to a result object */
    DB_ROW      row;            /* Row data */
    int     status = 0;         /* Status return */
    char*   datetime_now = DtParseDateTimeString("now");    /* where are we in time */
    int     time_diff;          /* how many second have elapsed */
    unsigned int     newsaltint;         /* new salt as integer */
    char    buffer[KSM_SQL_SIZE];   /* update statement for salt_stamp */
    unsigned int    nchar;          /* Number of characters converted */

    /* check the argument */
    if (policy == NULL) {
        MsgLog(KSM_INVARG, "NULL policy");
        StrFree(datetime_now);
        return -1;
    }

    /* Construct the query */

    sql = DqsSpecifyInit("policies","id, salt, salt_stamp");
    DqsConditionInt(&sql, "ID", DQS_COMPARE_EQ, policy->id, where++);
    DqsOrderBy(&sql, "id");

    /* Execute query and free up the query string */
    status = DbExecuteSql(DbHandle(), sql, &result);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        StrFree(datetime_now);
        return status;
	}

    /* Get the next row from the data */
    status = DbFetchRow(result, &row);
    if (status == 0) {
        status = DbStringBuffer(row, DB_POLICY_SALT, policy->denial->salt, KSM_SALT_LENGTH*sizeof(char));
        if (status == 0) {
            status = DbStringBuffer(row, DB_POLICY_SALT_STAMP, policy->denial->salt_stamp, KSM_TIME_LENGTH*sizeof(char));
        }

        if (status != 0) {
            status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
            DbFreeResult(result);
            DbFreeRow(row);
            StrFree(datetime_now);
            return status;
        }
    }
    else if (status == -1) {
        /* No rows to return (but no error), policy_id doesn't exist? */
        DbFreeResult(result);
        DbFreeRow(row);
        StrFree(datetime_now);
        return -1;
    }
	else {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));

        DbFreeResult(result);
        DbFreeRow(row);
        StrFree(datetime_now);
        return status;
	}

    DbFreeResult(result);
    DbFreeRow(row);

    /* Now see if this needs to be updated; if the stamp is null then assume it does */
    if (policy->denial->salt_stamp[0] == '\0') {
        time_diff = -1;
    } else {
        status = DtDateDiff(datetime_now, policy->denial->salt_stamp, &time_diff);
    }

    if (status == 0) {
        if (policy->denial->resalt > time_diff && time_diff != -1 && policy->denial->salt[0] != '\0') {
            /* current salt is fine */
            StrFree(datetime_now);
            return status;
        } else {
            /* salt needs updating, or is null */
            /* TODO get this call into libhsmtools */
            /* newsaltint = hsm_getrand(policy->denial->saltlength); */
            newsaltint = 123456789;
            snprintf(policy->denial->salt, KSM_SALT_LENGTH, "%X", newsaltint);
            StrStrncpy(policy->denial->salt_stamp, datetime_now, KSM_TIME_LENGTH);

            /* write these back to the database */
#ifdef USE_MYSQL
            nchar = snprintf(buffer, sizeof(buffer),
                    "UPDATE policies SET salt = '%s', salt_stamp = \"%s\" WHERE ID = %lu",
                    policy->denial->salt, policy->denial->salt_stamp, (unsigned long) policy->id);
#else
            nchar = snprintf(buffer, sizeof(buffer),
                    "UPDATE policies SET salt = '%s', salt_stamp = DATETIME(\"%s\") WHERE ID = %lu",
                    policy->denial->salt, policy->denial->salt_stamp, (unsigned long) policy->id);
#endif /* USE_MYSQL */
            if (nchar < sizeof(buffer)) {
                /* All OK, execute the statement */

                status = DbExecuteSqlNoResult(DbHandle(), buffer);
            }
            else {
                /* Unable to create update statement */

                status = MsgLog(KME_BUFFEROVF, "KsmPolicy");
            }

            StrFree(datetime_now);
            return status;
        }
    } else {
		MsgLog(KSM_INVARG, "Could not calculate DateDiff");
        StrFree(datetime_now);
        return -2;
    }

    StrFree(datetime_now);
    return status;
}

/* Populate security module information for a structure that has the sm_id fields filled in */

int KsmPolicyPopulateSMFromIds(KSM_POLICY* policy)
{
    int     where = 0;          /* WHERE clause value */
    char*   sql = NULL;         /* SQL query */
    DB_RESULT       result;     /* Handle converted to a result object */
    DB_ROW      row;            /* Row data */
    DB_RESULT       result2;     /* Handle converted to a result object */
    DB_ROW      row2;            /* Row data */
    int     status = 0;         /* Status return */

    /* check the argument */
    if (policy == NULL) {
        return MsgLog(KSM_INVARG, "NULL policy");
    }

    /* Construct the query for ksk */

    sql = DqsSpecifyInit(DB_SECURITY_MODULE_TABLE, DB_SECURITY_MODULE_FIELDS);
    DqsConditionInt(&sql, "id", DQS_COMPARE_EQ, policy->ksk->sm, where++);

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
        DbStringBuffer(row, DB_SECURITY_MODULE_NAME, policy->ksk->sm_name, KSM_NAME_LENGTH*sizeof(char));
        DbUnsignedLong(row, DB_SECURITY_MODULE_CAPACITY, &(policy->ksk->sm_capacity));
    }
    else if (status == -1) {}
        /* No rows to return (but no error) */
	else {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        DbFreeResult(result);
        DbFreeRow(row);
        return status;
	}

    DbFreeResult(result);
    DbFreeRow(row);


    /* Construct the query for zsk */
    where = 0;

    sql = DqsSpecifyInit(DB_SECURITY_MODULE_TABLE, DB_SECURITY_MODULE_FIELDS);
    DqsConditionInt(&sql, "id", DQS_COMPARE_EQ, policy->zsk->sm, where++);

    /* Execute query and free up the query string */
    status = DbExecuteSql(DbHandle(), sql, &result2);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        DbFreeResult(result2);
        return status;
	}

    /* Get the next row from the data */
    status = DbFetchRow(result2, &row2);
    if (status == 0) {
        DbStringBuffer(row2, DB_SECURITY_MODULE_NAME, policy->zsk->sm_name, KSM_NAME_LENGTH*sizeof(char));
        DbUnsignedLong(row2, DB_SECURITY_MODULE_CAPACITY, &(policy->zsk->sm_capacity));
    }
    else if (status == -1) {}
        /* No rows to return (but no error) */
	else {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
	}

    DbFreeRow(row2);
    DbFreeResult(result2);
    return status;
}

/*+
 * KsmPolicySetIdFromName - Given a policy with the name set, fill in the ID
 *
 *
 * Arguments:
 *      
 *          Name of the parameter.
 *
 *
 * Returns:
 *      int
 *          0       Success, value found
 *          Other   Error
-*/

int KsmPolicySetIdFromName(KSM_POLICY *policy)
{
    int             status;     /* Status return */
    DB_RESULT       result;     /* Handle converted to a result object */
    DB_ROW          row;        /* Row data */

    if (policy == NULL || policy->name == NULL) {
        return MsgLog(KSM_INVARG, "NULL policy or name");
    }

    status = KsmPolicyInit(&result, policy->name);
    if (status == 0) {
        /* Get the next row from the data */
        status = DbFetchRow(result, &row);
        if (status == 0) {
            DbInt(row, DB_POLICY_ID, &policy->id);
        }
        else if (status == -1) {
        /* No rows to return (but no error) */
        }
        else {
            /* Error */
            status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        }

    }
    DbFreeRow(row);
    DbFreeResult(result);
    return status;
}
