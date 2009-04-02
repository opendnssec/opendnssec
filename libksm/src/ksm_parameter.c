/*+
 * ksm_parameter.c - Manipulation of Parameter Information
 *
 * Description:
 *      Holds the functions needed to manipulate the PARAMETER table.
 *
 *      N.B.  The table is the KEYDATA table - rather than the KEY table - as
 *      KEY is a reserved word in SQL.
 *
 *
 * Copyright:
 *      Copyright 2008 Nominet
 *      
 * Licence:
 *      Licensed under the Apache Licence, Version 2.0 (the "Licence");
 *      you may not use this file except in compliance with the Licence.
 *      You may obtain a copy of the Licence at
 *      
 *          http://www.apache.org/licenses/LICENSE-2.0
 *      
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the Licence is distributed on an "AS IS" BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the Licence for the specific language governing permissions and
 *      limitations under the Licence.
-*/

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
#include "kmedef.h"
#include "ksm.h"
#include "ksm_internal.h"
#include "message.h"
#include "string_util.h"




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
    DB_ROW		row;            /* Row data */
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
    DB_ROW		row;            /* Row data */

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

	DbFreeRow(row);

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

    status = KsmParameterValue(KSM_PAR_CLOCKSKEW_STRING, KSM_PAR_CLOCKSKEW_CAT, &(data->clockskew), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_KSKLIFE_STRING, KSM_PAR_KSKLIFE_CAT, &(data->ksklife), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_NEMKEYS_STRING, KSM_PAR_NEMKEYS_CAT, &(data->nemkeys), policy_id, &param_id);
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

    status = KsmParameterValue(KSM_PAR_PUBSAFETY_STRING, KSM_PAR_PUBSAFETY_CAT, &(data->pub_safety), policy_id, &param_id);
    if (status > 0) return status;

    status = KsmParameterValue(KSM_PAR_RETSAFETY_STRING, KSM_PAR_RETSAFETY_CAT, &(data->ret_safety), policy_id, &param_id);
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
