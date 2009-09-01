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

/*+
 * ksm_parameter.c - Manipulation of Parameter Information
 *
 * Description:
 *      Holds the functions needed to manipulate the PARAMETER table.
 *
 *      N.B.  The table is the KEYDATA table - rather than the KEY table - as
 *      KEY is a reserved word in SQL.

-*/

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
#include "ksm/kmedef.h"
#include "ksm/ksmdef.h"
#include "ksm/ksm.h"
#include "ksm/ksm_internal.h"
#include "ksm/message.h"
#include "ksm/string_util.h"




/*+
 * KsmParameterInit - Query for Key Information
 *
 * Description:
 *      Performs a query for parameters in the parameter table that match the
 *      given conditions.
 *
 * Arguments:
 *      DB_RESULT* result
 *          Pointer to a result set to be used for information retrieval.  Will
 *          be undefined on error.
 *
 *      const char* name
 *          Name of the parameter to retrieve information on.  If NULL,
 *          information on all parameters is retrieved.
 *
 * Returns:
 *      int
 *          Status return.
 *
 *          	0		Success
 *          	Other	Error.  A message will have been output.
-*/

int KsmParameterInit(DB_RESULT* result, const char* name, const char* category, int policy_id)
{
    int     where = 0;          /* WHERE clause value */
    char*   sql = NULL;         /* SQL query */
    int     status = 0;         /* Status return */

    /* Construct the query */

    sql = DqsSpecifyInit("PARAMETER_VIEW", DB_PARAMETER_VIEW_FIELDS);
    if (name) {
        DqsConditionString(&sql, "NAME", DQS_COMPARE_EQ, name, where++);
        DqsConditionString(&sql, "CATEGORY", DQS_COMPARE_EQ, category, where++);
    }
    DqsConditionInt(&sql, "policy_id", DQS_COMPARE_EQ, policy_id, where++);

    DqsOrderBy(&sql, "NAME");

    /* Execute query and free up the query string */

    status = DbExecuteSql(DbHandle(), sql, result);

    DqsFree(sql);

    return status;
}

/*+
 * KsmParameterExist - Does the parameter exist at all?
 *
 * Description:
 *      Performs a query for parameters in the parameter table that match the
 *      given conditions.
 *
 * Arguments:
 *      DB_RESULT* result
 *          Pointer to a result set to be used for information retrieval.  Will
 *          be undefined on error.
 *
 *      const char* name
 *          Name of the parameter to retrieve information on.  If NULL,
 *          information on all parameters is retrieved.
 *
 * Returns:
 *      int
 *          Status return.
 *
 *          	0		Success
 *          	Other	Error.  A message will have been output.
-*/

int KsmParameterExist(DB_RESULT* result, const char* name, const char* category, int* parameter_id)
{
    int     where = 0;          /* WHERE clause value */
    char*   sql = NULL;         /* SQL query */
    DB_ROW		row = NULL;            /* Row data */
    int     status = 0;         /* Status return */

    /* Construct the query */

    sql = DqsSpecifyInit("PARAMETER_LIST", DB_PARAMETER_LIST_FIELDS);
    DqsConditionString(&sql, "NAME", DQS_COMPARE_EQ, name, where++);
    DqsConditionString(&sql, "CATEGORY", DQS_COMPARE_EQ, category, where++);

    DqsOrderBy(&sql, "NAME");

    /* Execute query and free up the query string */

    status = DbExecuteSql(DbHandle(), sql, result);

    if (status == 0) {
        status = DbFetchRow(*result, &row);
    }
    if (status == 0) {
        status = DbInt(row, DB_PARAMETER_ID, parameter_id);
    }

    DqsFree(sql);
    DbFreeRow(row);

    return status;
}

/*+
 * KsmParameter - Return Parameter Information
 *
 * Description:
 *      Returns information about the next key in the result set.
 *
 * Arguments:
 *      DB_RESULT result
 *          Result set from KsmParameterInit.
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

int KsmParameter(DB_RESULT result, KSM_PARAMETER* data)
{
    int         status = 0;     /* Return status */
    DB_ROW		row = NULL;     /* Row data */

    if (data == NULL) {
        return MsgLog(KSM_INVARG, "NULL data");
    }

	/* Initialize */

	memset(data, 0, sizeof(KSM_PARAMETER));

    /* Get the next row from the data */

	status = DbFetchRow(result, &row);

	if (status == 0) {
        status = DbStringBuffer(row, DB_PARAMETER_NAME, data->name,
            sizeof(data->name));
    }
	if (status == 0) {
        status = DbStringBuffer(row, DB_PARAMETER_CATEGORY, data->category,
            sizeof(data->category));
    }
    if (status == 0) {
        status = DbInt(row, DB_PARAMETER_ID, &(data->parameter_id));
    }
	if (status == 0) {
        status = DbInt(row, DB_PARAMETER_VALUE, &(data->value));
    }

    if (row != NULL) {
        DbFreeRow(row);
    }

    return status;
}


/*+
 * KsmParameterEnd - End Parameter Information
 *
 * Description:
 *      Called at the end of a KsmParameter cycle, frees up a result set.
 *
 * Arguments:
 *      DB_RESULT result
 *          Handle from KsmParameterInit
-*/

void KsmParameterEnd(DB_RESULT result)
{
    DbFreeResult(result);
}



/*+
 * KsmParameterValue - Get Parameter Value
 *
 * Description:
 *      Gets the data for the named parameter.  If the parameter does not
 *      exist, a warning is output and an error returned.
 *
 * Arguments:
 *      const char* name
 *          Name of the parameter.
 *
 *      const char* category
 *          Category of the parameter.
 *
 *      int* value
 *          Location into which the value of the parameter is put.
 *
 *      int policy_id
 *          ID of the policy we are interested in
 *
 *      int* parameter_id
 *          Location into which the ID of the parameter is put.
 *
 * Returns:
 *      int
 *          0       Success, value found
 *          -2      Success, value not set
 *          Other   Error, message has been output
-*/

int KsmParameterValue(const char* name, const char* category, int* value, int policy_id, int* parameter_id)
{
    DB_RESULT       handle;     /* Handle to the parameter information */
    KSM_PARAMETER   data;       /* Parameter data */
    int             status;     /* Status return */

    /* check the arguments */
    if (value == NULL || parameter_id == NULL) {
        return MsgLog(KSM_INVARG, "NULL arg");
    }
    status = KsmParameterInit(&handle, name, category, policy_id);
    if (status == 0) {

        /* Initialized OK, get the value */

        status = KsmParameter(handle, &data);
        if (status == 0) {
            *value = data.value;
            *parameter_id = data.parameter_id;
        }
        else if (status == -1) {
            status = KsmParameterExist(&handle, name, category, parameter_id);
            if (status == 0) {
                /* parameter by that name exists, but is not set */
                status = -2;
            } 
            else {
                status = MsgLog(KME_NOSUCHPAR, name);
            }
        }

        /* ... and tidy up */

        KsmParameterEnd(handle);
    }

    return status;
}



/*+
 * KsmCollectionInit - Fill In Parameter Collection with defaults
 *
 * Description:
 *      Fills in the parameter collection object with the values of the
 *      parameters given in ksm.h.
 *
 * Arguments:
 *      KSM_PARCOLL* data
 *          Pointer to the parameter collection object.  This will be filled in
 *          by this function.
 *
 * Returns:
 *      int
 *          0       Success
 *          Other   One or more errors,  in which case a message will have been
 *                  output.
-*/

int KsmCollectionInit(KSM_PARCOLL* data)
{
    if (data == NULL) {
        return MsgLog(KSM_INVARG, "NULL data");
    }

    data->clockskew = KSM_PAR_CLOCKSKEW;
    data->ksklife = KSM_PAR_KSKLIFE;
    data->nemkskeys = KSM_PAR_NEMKSKEYS;
    data->nemzskeys = KSM_PAR_NEMZSKEYS;
    data->propdelay = KSM_PAR_PROPDELAY;
    data->signint = KSM_PAR_SIGNINT;
    data->soamin = KSM_PAR_SOAMIN;
    data->soattl = KSM_PAR_SOATTL;
    data->zsksiglife = KSM_PAR_ZSKSIGLIFE;
    data->zsklife = KSM_PAR_ZSKLIFE;
    data->zskttl = KSM_PAR_ZSKTTL;
    data->kskttl = KSM_PAR_KSKTTL;
    data->kskpropdelay = KSM_PAR_KSKPROPDELAY;
    data->regdelay = KSM_PAR_REGDELAY;
    data->pub_safety = KSM_PAR_PUBSAFETY;
    data->ret_safety = KSM_PAR_RETSAFETY;

    return(0);
}

/*+
 * KsmParameterCollection - Fill In Parameter Collection Given Name
 *
 * Description:
 *      Fills in the parameter collection object with the values of the
 *      parameters.
 *
 * Arguments:
 *      KSM_PARCOLL* data
 *          Pointer to the parameter collection object.  This will be filled in
 *          by this function.
 *
 * Returns:
 *      int
 *          0       Success
 *          Other   One or more errors,  in which case a message will have been
 *                  output.
-*/

int KsmParameterCollection(KSM_PARCOLL* data, int policy_id)
{
    int status = 0;
    int param_id;

    /* check the arguments */
    if (data == NULL) {
        return MsgLog(KSM_INVARG, "NULL data");
    }

    status = KsmParameterValue(KSM_PAR_CLOCKSKEW_STRING, KSM_PAR_CLOCKSKEW_CAT, &(data->clockskew), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_KSKLIFE_STRING, KSM_PAR_KSKLIFE_CAT, &(data->ksklife), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_NEMKSKEYS_STRING, KSM_PAR_NEMKSKEYS_CAT, &(data->nemkskeys), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_NEMZSKEYS_STRING, KSM_PAR_NEMZSKEYS_CAT, &(data->nemzskeys), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_PROPDELAY_STRING, KSM_PAR_PROPDELAY_CAT, &(data->propdelay), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_SIGNINT_STRING, KSM_PAR_SIGNINT_CAT, &(data->signint), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_SOAMIN_STRING, KSM_PAR_SOAMIN_CAT, &(data->soamin), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_SOATTL_STRING, KSM_PAR_SOATTL_CAT, &(data->soattl), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_ZSKSIGLIFE_STRING, KSM_PAR_ZSKSIGLIFE_CAT, &(data->zsksiglife), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_ZSKLIFE_STRING, KSM_PAR_ZSKLIFE_CAT, &(data->zsklife), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_ZSKTTL_STRING, KSM_PAR_ZSKTTL_CAT, &(data->zskttl), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_KSKTTL_STRING, KSM_PAR_KSKTTL_CAT, &(data->kskttl), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_KSKPROPDELAY_STRING, KSM_PAR_KSKPROPDELAY_CAT, &(data->kskpropdelay), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_REGDELAY_STRING, KSM_PAR_REGDELAY_CAT, &(data->regdelay), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_PUBSAFETY_STRING, KSM_PAR_PUBSAFETY_CAT, &(data->pub_safety), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_RETSAFETY_STRING, KSM_PAR_RETSAFETY_CAT, &(data->ret_safety), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_KSK_MAN_ROLL_STRING, KSM_PAR_KSK_MAN_ROLL_CAT, &(data->kskmanroll), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_ZSK_MAN_ROLL_STRING, KSM_PAR_ZSK_MAN_ROLL_CAT, &(data->zskmanroll), policy_id, &param_id);
    if (status > 0) return status;

    return 0;
}




/*+
 * KsmParameterSet - Set Parameter Entry
 *
 * Description:
 *      Sets the value of a parameter in the database.
 *
 * Arguments:
 *      const char* name
 *          Name of parameter to set.  This must exist, else the setting
 *          will fail.
 *
 *      int value
 *          Value of the parameter.  For intervals, this is the value in
 *          seconds.
 *
 * Returns:
 *      int
 *          Status return.  0 => Success, non-zero => error.DisInt
-*/

int KsmParameterSet(const char* name, const char* category, int value, int policy_id)
{
    int             curvalue;               /* Current value */
    int             param_id;               /* Unique ID of this param */
    int             status = 0;             /* Status return */
    int             set = 0;                /* SET clause value */
    char*           sql = NULL;             /* SQL for the insert */
    int             where = 0;              /* WHERE clause value */

    /* Check to see if the parameter exists */

    status = KsmParameterValue(name, category, &curvalue, policy_id, &param_id);
    if (status == 0) {

        /* It does.  Update the value */

        sql = DusInit("parameters_policies");
        DusSetInt(&sql, "value", value, set++);
        DusConditionInt(&sql, "parameter_id", DQS_COMPARE_EQ, param_id, where++);
        DusConditionInt(&sql, "policy_id", DQS_COMPARE_EQ, policy_id, where++);
        DusEnd(&sql);

        status = DbExecuteSqlNoResult(DbHandle(), sql);
        DusFree(sql);
    }
    else if (status == -2) {
        /* param name is legal, but is not set for this policy */
        sql = DisInit("parameters_policies");
        DisAppendInt(&sql, param_id);
        DisAppendInt(&sql, policy_id);
        DisAppendInt(&sql, value);
        DisEnd(&sql);

        status = DbExecuteSqlNoResult(DbHandle(), sql);
        DisFree(sql);
    }
    /*
     * else {
     *      Error.  A message will have been output.
     * }
     */

    return status;
}

/*+
 * KsmParameterShow - Show Parameter
 *
 * Description:
 *      Prints to stdout the values of the parameter (or parameters).
 *
 * Arguments:
 *      const char* name
 *          Name of parameter to output, or NULL for all parameters.
-*/

int KsmParameterShow(const char* name, const char* category, int policy_id)
{
    KSM_PARAMETER data;         /* Parameter information */
    DB_RESULT	result;         /* Result of parameter query */
    int         param_id;       /* Unique ID of param */
    int         status = 0;     /* Status return */
    char        text[32];       /* For translated string */
    int         value;          /* Value of the parameter */

    /*
     * If a parameter was given, does it exist?  An error will be output if not
     * and the status return will be non-zero.
     */

    if (name) {
        status = KsmParameterValue(name, category, &value, policy_id, &param_id);
    }

    if (status == 0) {

        /* No problem to perform ther listing */

        status = KsmParameterInit(&result, name, category, policy_id);
        if (status == 0) {
            status = KsmParameter(result, &data);
            while (status == 0) {

                /* Get a text form of the value */

                DtSecondsInterval(data.value, text, sizeof(text));

                /* ... and print */

                StrTrimR(data.name);
                printf("%-12s %-12s %9d (%s)\n", data.name, data.category, data.value, text);
                
                /* Get the next parameter */

                status = KsmParameter(result, &data);
            }

            /* All done, so tidy up */

            KsmParameterEnd(result);
        }
    }

    return 0;
}
