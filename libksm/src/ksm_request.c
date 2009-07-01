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
 * ksm_request.c - Handle Request Keys Processing
 *
 * Description:
 *      The REQUEST command asks KSM to list the keys to be included in the
 *      zone when it is next signed.  It can optionally force a rollover by
 *      marking the active key as retired.
-*/

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ksm/database.h"
#include "ksm/database_statement.h"
#include "ksm/db_fields.h"
#include "ksm/debug.h"
#include "ksm/ksm.h"
#include "ksm/kmedef.h"
#include "ksm/ksmdef.h"
#include "ksm/message.h"
#include "ksm/memory.h"
#include "ksm/string_util.h"
#include "ksm/string_util2.h"



/*+
 * KsmRequestKeys - Request Keys for Output
 *
 * Description:
 *      Updates the key times and then calls KsmRequestKeysByType to process
 *      keys of the type chosen by the keytype argument.
 *
 * Arguments:
 *      int keytype
 *          Key type for which the request should happen.
 *
 *              KSM_TYPE_KSK    KSKs
 *              KSM_TYPE_ZSK    ZSKs
 *              Other           Both KSK and ZSK
 *
 *      int rollover
 *          1 to force a rollover, 0 to ignore
 *
 *      const char* datetime
 *          Time at which the request is issued.  Comparisons for key
 *          expirations etc. will be against this time.
 *
 *      KSM_REQUEST_CALLBACK callback
 *          Callback function called for every key that will be issued.
 *
 *      void* context
 *      	Context argument passed uninterpreted to the callback function.
 *
 *      int policy_id
 *          ID of policy that we are looking at
 *
 *      int zone_id
 *          ID of zone that we are looking at (-1 == all zones)
 *
-*/

void KsmRequestKeys(int keytype, int rollover, const char* datetime,
	KSM_REQUEST_CALLBACK callback, void* context, int policy_id, int zone_id)
{
    int         status;     /* Status return */

    /* Start the transaction */
    status = DbBeginTransaction();
    if (status != 0) {
        /* Something went wrong */

        MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        return;
    }

    /* Update the estimated times of state change */
    status = KsmUpdate(policy_id, zone_id);
    if (status == 0) {

        /* Process all key types */

        if ((keytype == KSM_TYPE_KSK) || (keytype == KSM_TYPE_ZSK)) {
            status = KsmRequestKeysByType(keytype, rollover, datetime,
				callback, context, policy_id, zone_id);
            
            if (status != 0) {
                DbRollback();
                return;
            }
        }
        else {
            status = KsmRequestKeysByType(KSM_TYPE_KSK, rollover, datetime,
				callback, context, policy_id, zone_id);
            if (status != 0) {
                DbRollback();
                return;
            }

            status = KsmRequestKeysByType(KSM_TYPE_ZSK, rollover, datetime,
				callback, context, policy_id, zone_id);
            if (status != 0) {
                DbRollback();
                return;
            }
        }

        /*
         * Finally, update the key times again, in case any keys were
         * moved between states.
         */

            status = KsmUpdate(policy_id, zone_id);
            if (status != 0) {
                DbRollback();
                return;
            }
            else
            {
                /* Everything worked by the looks of it */
                DbCommit();
            }
    }
    else
    {
        /* Whatever happened, it was not good */
        DbRollback();
    }

    return;
}


/*+
 * KsmRequestKeysByType - Request Keys for Output
 *
 * Description:
 *      Does REQUEST KEYS processing for keys of a given type.
 *
 * Arguments:
 *      int keytype
 *          Key type for which the request should happen.
 *
 *              KSM_TYPE_KSK    KSKs
 *              KSM_TYPE_ZSK    ZSKs
 *
 *      int rollover
 *          1 to force a rollover, 0 to ignore
 *
 *      const char* datetime
 *          Time to insert into database.
 *
 *      KSM_REQUEST_CALLBACK callback
 *          Callback function called for every key that will be issued.
 *
 *      void* context
 *      	Context argument passed uninterpreted to the callback function.
 *
 *      int policy_id
 *          ID of policy that we are looking at
 *
 *      int zone_id
 *          ID of zone that we are looking at
 *
 * Returns:
 *      int
 *          Status return.  0 = Success, other = error (in which case a message
 *          will have been output).
-*/

int KsmRequestKeysByType(int keytype, int rollover, const char* datetime,
	KSM_REQUEST_CALLBACK callback,  void* context, int policy_id, int zone_id)
{
    int     active;         /* Number of active keys to be retired */
    KSM_PARCOLL collection; /* Parameters collection */
    int     ready;          /* Number of keys in the "ready" state */
    int     status;         /* Status return */

	/* Check that we have a valid key type */

    if ((keytype != KSM_TYPE_KSK) && (keytype != KSM_TYPE_ZSK)) {
		status = MsgLog(KME_UNKEYTYPE, keytype);
		return status;
	}

	DbgLog(DBG_M_REQUEST, KME_REQKEYTYPE,
		(keytype == KSM_TYPE_KSK) ? "key" : "zone");

    /* Get list of parameters */

    status = KsmParameterCollection(&collection, policy_id);
    if (status != 0) {
        return status;
    }

    /*
     * Step 0: If rolling over the key, set the expected retirement date of
     * active keys to the given date/time.
     */

    if (rollover) {
        status = KsmRequestSetActiveExpectedRetire(keytype, datetime, zone_id);
        if (status != 0) {
            return status;
        }
    }

    /*
     * Step 1.  For each retired key, mark it as dead if it past the given
     * time.
     */

    status = KsmRequestChangeStateRetireDead(keytype, datetime, zone_id);
    if (status != 0) {
        return status;
    }

    /*
     * Step 2.  For each key in the published state, set it ready if it has
     * been in the zone long enough.
     */

    status = KsmRequestChangeStatePublishReady(keytype, datetime, zone_id);
    if (status != 0) {
        return status;
    }

    /*
     * Step 3.  We are within the appropriate interval of the retirement
     * of the active key, move keys from the generate state into the
     * publish state.
     */

    status = KsmRequestChangeStateGeneratePublishConditional(keytype, datetime, &collection, zone_id);
    if (status != 0) {
        return status;
    }

    /*
     * Step 4. If there is an active key and the date on which this procedure
     * is run is earlier than the retire time of that key, exit the procedure.
     */

    status = KsmRequestCheckActiveKey(keytype, datetime, &active, zone_id);
    if (status != 0) {
        return status;
    }

    /*
     * Step 5: Unless we are forcing a rollover, if there are some keys that
     * will be active after the cut-off, end the modification of key states and
     * times now.  Otherwise continue.
     *
     * Note that we don't return if keys are active - we still need to issue
     * the keys.
     */

    if ((active <= 0) || (rollover)) {

        /*
         * Step 6. If there are keys to be made active, count the number of keys
         * in the "READY" state.
         */

        status = KsmRequestCountReadyKey(keytype, datetime, &ready, zone_id);
        if (status != 0) {
            return status;
        }

        /*
         * Step 7. We can only promote a key if there is at least one key in the
         * READY state.  Otherwise, just issue what we have.
         */

        if (ready <= 0) {
            /*
             * If active <= 0 then we can promote a published key as this is the 
             * first pass for this zone.
             * NB: A consequence of this is that these keys will have no "ready"
             *     time as they are never in the "ready" state.
             */
            if (active <= 0) {
                /* TODO log what we are doing? */
                status = KsmRequestChangeStateN(keytype, datetime, 1,
                                    KSM_STATE_PUBLISH, KSM_STATE_ACTIVE, zone_id);
                if (status != 0) {
                    return status;
                }
            }
            else {
                (void) MsgLog(KME_NOREADYKEY);
                /* TODO return here? */
            }
        }
        else {

            /* Step 8. Make a key active. */

            status = KsmRequestChangeStateReadyActive(keytype, datetime, 1, zone_id);
            if (status != 0) {
                return status;
            }

            /* Step 9. ... and retire old active keys */

            status = KsmRequestChangeStateActiveRetire(keytype, datetime, zone_id);
            if (status != 0) {
                return status;
            }
        }
    }

    /* Step 10. Issue the keys */

    status = KsmRequestIssueKeys(keytype, callback, context, zone_id);

    return status;
}



/*+
 * KsmRequestSetActiveExpectedRetire - Set Expected Retire Date
 *
 * Description:
 *      Sets the expected retire date for active keys to the date specified.
 *      Note that this does change not the state from active - it only changes
 *      the expected retire date.
 *
 * Arguments:
 *      int keytype
 *          Type of keys being changed.
 *
 *      const char* datetime
 *          Date/time for which the calculation is being done.  This can be
 *          the string "NOW()".
 *
 *      int zone_id
 *          Zone we are looking at (-1 == all zones)
 *
 *  Returns:
 *      int
 *          Status return. 0 => success, Other => failure, in which case an
 *          error message will have been output.
-*/

int KsmRequestSetActiveExpectedRetire(int keytype, const char* datetime, int zone_id)
{
    int     count;          /* Count of keys whose date will be set */
    int     set = 0;        /* For the update "set" clause */
    char*   sql = NULL;     /* For creating the SQL command */
    int     status = 0;     /* Status return */
    int     where = 0;      /* For the SQL selection */

    if (DbgIsSet(DBG_M_REQUEST)) {

        /* Count how many keys will have the retire date set */

        sql = DqsCountInit("KEYDATA_VIEW");
        DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype, where++);
        DqsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, KSM_STATE_ACTIVE, where++);
        if (zone_id != -1) {
            DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, where++);
        }
        DqsEnd(&sql);

        status = DbIntQuery(DbHandle(), &count, sql);
        DqsFree(sql);

        if (status == 0) {
            MsgLog(KME_ACTKEYRET, count);
        }
        else {
            status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        }
    }

    if (status == 0) {

		/*
		 * Update the keys.  This is done after a status check, as the debug
		 * code may have hit a database error, in which case we won't query the
		 * database again. ("status" is initialized to success in case the debug
		 * code is not executed.)
		 */

        where = set = 0;
        sql = DusInit("KEYDATA_VIEW");
        DusSetString(&sql, "RETIRE", datetime, set++);
        DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype, where++);
        DusConditionInt(&sql, "STATE", DQS_COMPARE_EQ, KSM_STATE_ACTIVE, where++);
        if (zone_id != -1) {
            DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, where++);
        }
        DusEnd(&sql);

        status = DbExecuteSqlNoResult(DbHandle(), sql);
        DusFree(sql);
    }

    return status;
}



/*+
 * KsmRequestChangeStatePublishReady - Change State from PUBLISH to READY
 * KsmRequestChangeStateActiveRetire - Change State from ACTIVE to RETIRE
 * KsmRequestChangeStateRetireDead - Change State from RETIRE to DEAD
 *
 * Description:
 *      Changes the state of keys of a particular type in the given zone
 *      between two states.
 *
 * Arguments:
 *      int keytype
 *          Type of keys being changed.
 *
 *      const char* datetime
 *          Date/time for which the calculation is being done.  This ancan be
 *          the string "NOW()".
 *
 *      int zone_id
 *          ID of zone that we are looking at (-1 == all zones)
 *
 *  Returns:
 *      int
 *          Status return. 0 => success, Other => failure, in which case an
 *          error message will have been output.
-*/

int KsmRequestChangeStatePublishReady(int keytype, const char* datetime, int zone_id)
{
    return KsmRequestChangeState(keytype, datetime,
        KSM_STATE_PUBLISH, KSM_STATE_READY, zone_id);
}

int KsmRequestChangeStateActiveRetire(int keytype, const char* datetime, int zone_id)
{
    return KsmRequestChangeState(keytype, datetime,
        KSM_STATE_ACTIVE, KSM_STATE_RETIRE, zone_id);
}

int KsmRequestChangeStateRetireDead(int keytype, const char* datetime, int zone_id)
{
    return KsmRequestChangeState(keytype, datetime,
        KSM_STATE_RETIRE, KSM_STATE_DEAD, zone_id);
}



/*+
 * KsmRequestChangeState - Change State of a Key
 *
 * Description:
 *      Changes the state of a key between two states if the estimated time of
 *      entering the target state is equal to or earlier than the given time.
 *      The time of entering the state is updated to the given time as well.
 *
 * Arguments:
 *      int keytype
 *          Type of keys being changed.
 *
 *      const char* datetime
 *          Date/time for which the calculation is being done.  This can be
 *          the string "NOW()".
 *
 *      int src_state
 *          ID of the state that the key is moving from.
 *
 *      int dst_state
 *          ID of the state that the key is moving to.
 *
 *      int zone_id
 *          ID of zone that we are looking at (-1 == all zones)
 *
 *  Returns:
 *      int
 *          Status return. 0 => success, Other => failure, in which case an
 *          error message will have been output.
-*/

int KsmRequestChangeState(int keytype, const char* datetime,
    int src_state, int dst_state, int zone_id)
{
    int     where = 0;		/* for the SELECT statement */
    char*   dst_col = NULL; /* Destination column */
    int     set = 0;    	/* For UPDATE */
    char*   sql = NULL;     /* SQL statement (when verifying) */
    int     status = 0;     /* Status return */
    int     count = 0;      /* How many keys fit our select? */
    int     i = 0;          /* A counter */
    int     j = 0;          /* Another counter */
    char*   insql = NULL;   /* SQL "IN" clause */
    int*    keyids;         /* List of IDs of keys to promote */
    DB_RESULT    result;    /* List result set */
    KSM_KEYDATA  data;      /* Data for this key */
    char    buffer[32];         /* For integer conversion */

    /* Create the destination column name */

    dst_col = StrStrdup(KsmKeywordStateValueToName(dst_state));
    (void) StrToUpper(dst_col);

    /* First up we need to count how many keys will move */
    sql = DqsCountInit("KEYDATA_VIEW");
    DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype, where++);
    DqsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, src_state, where++);
    if (zone_id != -1) {
        DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, where++);
    }
    DqsConditionString(&sql, dst_col, DQS_COMPARE_LE, datetime, where++);
    DqsEnd(&sql);

    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);

    if (status != 0) {
        status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        StrFree(dst_col);
        return status;
    }

    if (count == 0) {
        /* Nothing to do */
        StrFree(dst_col);
        return status;
    }

    /* Allocate space for the list of key IDs */
    keyids = MemMalloc(count * sizeof(int));

    /* Get the list of IDs */

    where = 0;
    sql = DqsSpecifyInit("KEYDATA_VIEW", DB_KEYDATA_FIELDS);
    DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype, where++);
    DqsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, src_state, where++);
    if (zone_id != -1) {
        DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, where++);
    }
    DqsConditionString(&sql, dst_col, DQS_COMPARE_LE, datetime, where++);
    DqsEnd(&sql);

    status = KsmKeyInitSql(&result, sql);
    DqsFree(sql);

    if (status == 0) {
        while (status == 0) {
            status = KsmKey(result, &data);
            if (status == 0) {
                keyids[i] = data.keypair_id;
                i++;
            }
        }

        /* Convert EOF status to success */

        if (status == -1) {
            status = 0;
        } else {
            status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
            StrFree(dst_col);
            StrFree(keyids);
            return status;
        }

        KsmKeyEnd(result);

    } else {
        status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        StrFree(dst_col);
        StrFree(keyids);
		return status;
	}
    
	/* Notify progress if debugging */

	DbgLog(DBG_M_REQUEST, KME_KEYCHSTATE, count,
		KsmKeywordStateValueToName(src_state),
		KsmKeywordStateValueToName(dst_state));

    /*
     * Now construct the "IN" statement listing the IDs of the keys we
     * are planning to change the state of.
     */

    StrAppend(&insql, "(");
    for (j = 0; j < i; ++j) {
        if (j != 0) {
            StrAppend(&insql, ",");
        }
        snprintf(buffer, sizeof(buffer), "%d", keyids[j]);
        StrAppend(&insql, buffer);
    }
    StrAppend(&insql, ")");

    /*
     * Update the keys.  This is done after a status check, as the debug
     * code may have hit a database error, in which case we won't query the
     * database again. ("status" is initialized to success in case the debug
     * code is not executed.)
     */

    sql = DusInit("keypairs");
    DusSetInt(&sql, "STATE", dst_state, set++);
    DusSetString(&sql, dst_col, datetime, set++);

    DusConditionKeyword(&sql, "ID", DQS_COMPARE_IN, insql, 0);
    StrFree(insql);
    DusEnd(&sql);

    status = DbExecuteSqlNoResult(DbHandle(), sql);
    DusFree(sql);

    /* Report any errors */
    if (status != 0) {
        status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
    }


    StrFree(dst_col);
    StrFree(keyids);

    return status;
}



/*+
 * KsmRequestChangeStateGeneratePublish - Change State from GENERATE to PUBLISH
 * KsmRequestChangeStateReadyActive - Change State from READY to ACTIVE
 *
 * Description:
 *      Changes the state of a number of keys from one state to another.
 *
 * Arguments:
 *      int keytype
 *          Type of keys being changed.
 *
 *      const char* datetime
 *          Date/time for which this request is being made.
 *
 *      int count
 *          Number of keys to be promoted to the publish state.  There is no
 *          check as to whether that number of keys are available in the
 *          GENERATE state - it is assumed that that check has already been
 *          carried out.
 *
 *      int zone_id
 *          ID of zone that we are looking at (-1 == all zones)
 *
 *  Returns:
 *      int
 *          Status return. 0 => success, Other => failure, in which case an
 *          error message will have been output.
-*/

int KsmRequestChangeStateGeneratePublish(int keytype, const char* datetime,
	int count, int zone_id)
{
    return KsmRequestChangeStateN(keytype, datetime, count,
        KSM_STATE_GENERATE, KSM_STATE_PUBLISH, zone_id);
}

int KsmRequestChangeStateReadyActive(int keytype, const char* datetime,
	int count, int zone_id)
{
    return KsmRequestChangeStateN(keytype, datetime, count,
        KSM_STATE_READY, KSM_STATE_ACTIVE, zone_id);
}


/*+
 * KsmRequestChangeStateN - Change State of N Keys
 *
 * Description:
 *      Changes the state of a given number of keys from one state to another.
 *
 * Arguments:
 *      int keytype
 *          Type of keys being changed.
 *
 *      const char* datetime
 *          Date/time for which this request is being made.
 *
 *      int count
 *          Number of keys to be promoted to the destination state.  There is no
 *          check as to whether that number of keys are available in the
 *          state - it is assumed that that check has already been carried out.
 *
 *      int src_state
 *          State from which keys are being prompted.
 *
 *      int dst_state
 *          State to which keys are being promoted.
 *
 *      int zone_id
 *          ID of zone that we are looking at (-1 == all zones)
 *
 *  Returns:
 *      int
 *          Status return. 0 => success, Other => failure, in which case an
 *          error message will have been output.
-*/

int KsmRequestChangeStateN(int keytype, const char* datetime, int count,
	int src_state, int dst_state, int zone_id)
{
    char                buffer[32];         /* For integer conversion */
    DQS_QUERY_CONDITION condition[4];       /* Condition codes */
    KSM_KEYDATA         data;               /* Data for this key */
    char*               dst_name = NULL;    /* Dest state name uppercase */
    DB_RESULT           result;             /* List result set */
    int                 i;                  /* Loop counter */
    char*               insql = NULL;       /* SQL "IN" clause */
    int*                keyids;             /* List of IDs of keys to promote */
    int                 setclause = 0;      /* For the "SET" clauses */
    char*               sql = NULL;         /* SQL statement */
    int                 status;             /* Status return */
    int                 whereclause = 0;    /* For the "WHERE" clauses */

    /* Just checking */
    if (count <= 0) {
        status = MsgLog(KSM_INVARG, "Asked to move 0 keys");
        return status;
    }

	/* Notify progress if debugging */

	DbgLog(DBG_M_REQUEST, KME_KEYCHSTATE, count,
		KsmKeywordStateValueToName(src_state),
		KsmKeywordStateValueToName(dst_state));

    /* Allocate space for the list of key IDs */
    keyids = MemMalloc(count * sizeof(int));

    /* Get the list of IDs */

    condition[0].code = DB_KEYDATA_KEYTYPE;
    condition[0].data.number = keytype;
    condition[0].compare = DQS_COMPARE_EQ;

    condition[1].code = DB_KEYDATA_STATE;
    condition[1].data.number = src_state;
    condition[1].compare = DQS_COMPARE_EQ;

    condition[2].compare = DQS_END_OF_LIST;

    if (zone_id != -1) {
        condition[2].code = DB_KEYDATA_ZONE_ID;
        condition[2].data.number = zone_id;
        condition[2].compare = DQS_COMPARE_EQ;

        condition[3].compare = DQS_END_OF_LIST;
    }


    status = KsmKeyInit(&result, condition);
    for (i = 0; ((i < count) && (status == 0)); ++i) {
        status = KsmKey(result, &data);
        if (status == 0) {
            keyids[i] = data.keypair_id;
        }
    }
    KsmKeyEnd(result);

    /* Did we get everything? */

    if (status == 0) {

        /*
         * Yes: construct the "IN" statement listing the IDs of the keys we
         * are planning to change the state of.
         */

        StrAppend(&insql, "(");
        for (i = 0; i < count; ++i) {
            if (i != 0) {
                StrAppend(&insql, ",");
            }
            snprintf(buffer, sizeof(buffer), "%d", keyids[i]);
            StrAppend(&insql, buffer);
        }
        StrAppend(&insql, ")");

        /* Get upper case names of the states (= names of date columns) */

        dst_name = StrStrdup(KsmKeywordStateValueToName(dst_state));
        (void) StrToUpper(dst_name);

        /*
         * Now construct the "UPDATE" statement and execute it.  This relies on
         * the fact that the name of the state is the same as the name of
         * the column in KEYDATA holding the date at which the key moved to
         * that state.
         */

        sql = DusInit("keypairs");
        DusSetInt(&sql, "STATE", dst_state, setclause++);
        DusSetString(&sql, dst_name, datetime, setclause++);
        StrFree(dst_name);

        DusConditionKeyword(&sql, "ID", DQS_COMPARE_IN, insql, whereclause++);
        StrFree(insql);
        DusEnd(&sql);

        status = DbExecuteSqlNoResult(DbHandle(), sql);
        DusFree(sql);

        /* Report any errors */

        if (status != 0) {
            status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        }
    }
    
    /* Free up resources */

    MemFree(keyids);

    return status;
}



/*+
 * KsmRequestChangeStateGeneratePublishConditional -
 *          Change State from Generate to Pubish
 *
 * Description:
 *      Unlike the other "Change State" functions, this is conditional.  It
 *      promotes keys in the "Generate" state to the "Publish" state to maintain
 *      the required number of keys active/emergency keys when the active keys
 *      are retired.
 *
 *      a) For the given time, work out how many "active" keys have a retire
 *         date within this time + "publication interval".  Call this number
 *         Npr (Number pending retirement).
 *
 *         This should be 1 or 0, as there is an assumption that there is only
 *         ever one active key.
 *
 *      b) Work out how many keys are in the active, publish and ready states.
 *         Call this Nt (Number total).
 *
 *      c) Now look at the difference (Nt - Npr).  This is the number of keys
 *         that will be (potentially) usable after the active key retires.
 *         If this number is less than (1 + Ne) (where Ne is the number of
 *         emergency keys), move the difference from the generated state into
 *         the published state.
 *
 * Arguments:
 *      int keytype
 *          Key type for which the request should happen.
 *
 *              KSM_TYPE_KSK    KSKs
 *              KSM_TYPE_ZSK    ZSKs
 *
 *      const char* datetime
 *          Date/time for which this request is taking place.
 *
 *      KSM_PARCOLL* collection
 *          Pointer to parameter collection for this zone.
 *
 *      int zone_id
 *          ID of zone that we are looking at (-1 == all zones)
 *
 * Returns:
 *      int
 *          Status return. 0 => success, Other => failure, in which case an
 *          error message will have been output.
-*/

int KsmRequestChangeStateGeneratePublishConditional(int keytype,
	const char* datetime, KSM_PARCOLL* collection, int zone_id)
{
    int     availkeys;      /* Number of availkeys keys */
    int     gencnt;         /* Number of keys in generate state */
    int     newkeys;        /* New keys required */
    int     pendret;        /* Number of keys that will be retired */
    int     reqkeys;        /* Number of keys required */
    int     status;         /* Status return */

    /* How many active keys will be retired in the immediate future */

    status = KsmRequestPendingRetireCount(keytype, datetime, collection,
        &pendret, zone_id);
    if (status != 0) {
        return status;
    }
	DbgLog(DBG_M_REQUEST, KME_RETIRECNT, pendret);

    /* How many available keys are there */

    status = KsmRequestAvailableCount(keytype, datetime, collection,
        &availkeys, zone_id);
    if (status != 0) {
        return status;
    }
	DbgLog(DBG_M_REQUEST, KME_AVAILCNT, availkeys);

    /*
     * We need at least one active key and "number of emergency keys" ready
     * keys at any one time.
     */

    if (keytype == KSM_TYPE_KSK) {
        reqkeys = 1 + KsmParameterEmergencyKSKeys(collection);
    }
    else if (keytype == KSM_TYPE_ZSK) {
        reqkeys = 1 + KsmParameterEmergencyZSKeys(collection);
    }
    else {
        /* should not get here */
        return -1;
    }

    /*
     * So, if we remove "pendret" keys from the number of "available"
     * keys, how many are we short of the required number?  This is how many
     * we need to promote from "generate" to "publish"
     */

    newkeys = reqkeys - (availkeys - pendret);
	DbgLog(DBG_M_REQUEST, KME_KEYCNTSUMM, reqkeys, newkeys);

    if (newkeys > 0) {

        /* Are there enough generated keys available */

        status = KsmRequestGenerateCount(keytype, &gencnt, zone_id);
        if (status == 0) {
            if (gencnt < newkeys) {
                status = MsgLog(KME_INSFGENKEY, gencnt,
                    KsmKeywordTypeValueToName(keytype));
            }
			DbgLog(DBG_M_REQUEST, KME_GENERATECNT, gencnt,
				KsmKeywordTypeValueToName(keytype));

            if (status == 0) {

                /* There are enough keys, so move them to "publish" state */

                status = KsmRequestChangeStateGeneratePublish(keytype,
                    datetime, newkeys, zone_id);
            }
        }
    }

    return 0;
}



/*+
 * KsmRequestPendingRetireCount - Get Count of Keys Pending Retirement
 *
 * Description:
 *      For the given time, works out how many "active" keys have a retire
 *      date within this time + "publication interval".
 *
 *      This should be 1 or 0, as there is an assumption that there is only
 *      ever one active key.
 *
 * Arguments:
 *      int keytype
 *          Key type for which the request should happen.
 *
 *              KSM_TYPE_KSK    KSKs
 *              KSM_TYPE_ZSK    ZSKs
 *
 *      const char* datetime
 *          Date/time for which this request is taking place.
 *
 *      KSM_PARCOLL* parameters
 *          Parameters associated with this zone.
 *
 *      int* count (returned)
 *          Number of active keys that will retire within that period.
 *
 *      int zone_id
 *          ID of zone that we are looking at (-1 == all zones)
 *
 * Returns:
 *      int
 *          Status return.  0 => success, <>0 => error, in which case a message
 *          will have been output.
-*/

int KsmRequestPendingRetireCount(int keytype, const char* datetime,
    KSM_PARCOLL* parameters, int* count, int zone_id)
{
    char    buffer[256];    /* For constructing part of the command */
    int     clause = 0;     /* Used in constructing SQL statement */
    size_t  nchar;          /* Number of characters written */
    char*   sql;            /* SQL command to be isssued */
    int     status;         /* Status return */

    /* Create the SQL command to interrogate the database */

    sql = DqsCountInit("KEYDATA_VIEW");
    DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype, clause++);
    DqsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, KSM_STATE_ACTIVE, clause++);
    if (zone_id != -1) {
        DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, clause++);
    }

    /* Calculate the initial publication interval & add to query */

    /* 
     * TODO is there an alternative to DATE_ADD which is more generic? 
     */
#ifdef USE_MYSQL
    nchar = snprintf(buffer, sizeof(buffer),
        "DATE_ADD(\"%s\", INTERVAL %d SECOND)",
        datetime, KsmParameterInitialPublicationInterval(parameters));
#else
    nchar = snprintf(buffer, sizeof(buffer),
        "DATETIME('%s', '+%d SECONDS')",
        datetime, KsmParameterInitialPublicationInterval(parameters));
#endif /* USE_MYSQL */
    if (nchar >= sizeof(buffer)) {
        status = MsgLog(KME_BUFFEROVF, "KsmRequestKeys");
        return status;
    }

#ifdef USE_MYSQL
    DqsConditionKeyword(&sql, "RETIRE", DQS_COMPARE_LE, buffer, clause++);
#else
    DqsConditionKeyword(&sql, "DATETIME(RETIRE)", DQS_COMPARE_LE, buffer, clause++);
#endif /* USE_MYSQL */

    DqsEnd(&sql);

    /* Execute the query and free resources */

    status = DbIntQuery(DbHandle(), count, sql);
    DqsFree(sql);

    /* Report any errors */

    if (status != 0) {
        status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
    }

    return status;
}



/*+
 * KsmRequestAvailableCount - Get Count of Available Keys
 *
 * Description:
 *      By "available", is the number of keys in the "published", "ready"
 *      and "active" state.
 *
 * Arguments:
 *      int keytype
 *          Key type for which the request should happen.
 *
 *              KSM_TYPE_KSK    KSKs
 *              KSM_TYPE_ZSK    ZSKs
 *
 *      const char* datetime
 *          Date/time for which this request is taking place.
 *
 *      KSM_PARCOLL* parameters
 *          Parameters associated with this zone.
 *
 *      int* count (returned)
 *          Number of available keys.
 *
 *      int zone_id
 *          ID of zone that we are looking at (-1 == all zones)
 *
 * Returns:
 *      int
 *          Status return.  0 => success, <>0 => error, in which case a message
 *          will have been output.
-*/

int KsmRequestAvailableCount(int keytype, const char* datetime, KSM_PARCOLL* parameters, int* count, int zone_id)
{
    char    buffer[256];    /* For constructing part of the command */
    int     clause = 0;     /* Used in constructing SQL statement */
    size_t  nchar;          /* Number of characters written */
    char*   sql;            /* SQL command to be isssued */
    int     status;         /* Status return */

    /* Create the SQL command to interrogate the database */

    sql = DqsCountInit("KEYDATA_VIEW");
    DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype, clause++);

    /* Calculate the initial publication interval & add to query */

    nchar = snprintf(buffer, sizeof(buffer), "(%d, %d, %d)",
        KSM_STATE_PUBLISH, KSM_STATE_READY, KSM_STATE_ACTIVE);
    if (nchar >= sizeof(buffer)) {
        status = MsgLog(KME_BUFFEROVF, "KsmRequestKeys");
        return status;
    }
    DqsConditionKeyword(&sql, "STATE", DQS_COMPARE_IN, buffer, clause++);
    if (zone_id != -1) {
        DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, clause++);
    }
    DqsEnd(&sql);

    /* Execute the query and free resources */

    status = DbIntQuery(DbHandle(), count, sql);
    DqsFree(sql);

    /* Report any errors */

    if (status != 0) {
        status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
    }

    return status;
}


/*+
 * KsmRequestGenerateCount - Return Number of Keys in Generate State
 *
 * Description:
 *      Returns the retire time of the currently active key.  If there are
 *      multiple active keys, returns the earliest time.
 *
 * Arguments:
 *      int keytype
 *          Time of key to search for.
 *
 *      int* count (returned)
 *          Number of available keys.
 *
 *      int zone_id
 *          ID of zone that we are looking at (-1 == all zones)
 *
 * Returns:
 *      int
 *          Status return. 0 => success, Other implies error, in which case a
 *          message will have been output.
-*/

int KsmRequestGenerateCount(int keytype, int* count, int zone_id)
{
    int     clause = 0;     /* Clause count */
    char*   sql = NULL;     /* SQL to interrogate database */
    int     status = 0;     /* Status return */

    /* Create the SQL */

    sql = DqsCountInit("KEYDATA_VIEW");
    DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype, clause++);
    DqsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, KSM_STATE_GENERATE, clause++);
    if (zone_id != -1) {
        DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, clause++);
    }
    DqsEnd(&sql);

    /* Execute the query and free resources */

    status = DbIntQuery(DbHandle(), count, sql);
    DqsFree(sql);

    /* Report any errors */

    if (status != 0) {
        status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
    }

    return status;
}

/*
 * KsmRequestCheckActiveKey - Check Active Key
 *
 * Description:
 *      Checks:
 *
 *      a) If there is an active key.
 *      b) If a key is present, what the retire time of it is.  This is compared
 *         against the specified date/time.
 *
 *      A flag is returned indicating whether the key (if active) should be
 *      replaced.
 *
 * Arguments:
 *      int keytype
 *          Either KSK or ZSK, depending on the key type
 *
 *      const char* datetime
 *          Date/time at which the check is being carried out.
 *
 *      int* count
 *          Number of active keys of the appropriate type and in the zone
 *          that will be active AFTER the given date and time.
 *
 *      int zone_id
 *          ID of zone that we are looking at (-1 == all zones)
 *
 *          This negative form (i.e. keys not meeting the specified condition)
 *          is used to ensure that if there are no active keys, this fact is
 *          reported.
 *
 * Returns:
 *      int
 *          Status return. 0 => success, Other => error, in which case a message
 *          will have been output.
-*/

int KsmRequestCheckActiveKey(int keytype, const char* datetime, int* count, int zone_id)
{
    int     clause = 0;     /* Clause counter */
    char*   sql = NULL;     /* SQL command */
    int     status;         /* Status return */
#ifdef USE_MYSQL
#else
    char    buf[256];       /* For constructing part of the command */
#endif /* USE_MYSQL */
    sql = DqsCountInit("KEYDATA_VIEW");
    DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype, clause++);
    DqsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, KSM_STATE_ACTIVE, clause++);
    if (zone_id != -1) {
        DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, clause++);
    }

#ifdef USE_MYSQL
    DqsConditionString(&sql, "RETIRE", DQS_COMPARE_GT, datetime, clause++);
#else
    snprintf(buf, sizeof(buf), "DATETIME('%s')", datetime);
    DqsConditionKeyword(&sql, "DATETIME(RETIRE)", DQS_COMPARE_GT, buf, clause++);
#endif /* USE_MYSQL */

    DqsEnd(&sql);

    status = DbIntQuery(DbHandle(), count, sql);
    DqsFree(sql);

    if (status != 0) {
        status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
    }
	DbgLog(DBG_M_REQUEST, KME_REMAINACT, *count,
		KsmKeywordTypeValueToName(keytype));

    return status;
}



/*
 * KsmRequestCountReadyKey - Count Keys in READY state
 *
 * Description:
 *      Counts the number of keys in the "READY" state.
 *
 * Arguments:
 *      int keytype
 *          Either KSK or ZSK, depending on the key type
 *
 *      const char* datetime
 *          Date/time at which the check is being carried out.
 *
 *      int* count
 *          Number of keys meeting the condition.
 *
 *      int zone_id
 *          ID of zone that we are looking at (-1 == all zones)
 *
 * Returns:
 *      int
 *          Status return. 0 => success, Other => error, in which case a message
 *          will have been output.
-*/

int KsmRequestCountReadyKey(int keytype, const char* datetime, int* count, int zone_id)
{
    int     clause = 0;     /* Clause counter */
    char*   sql = NULL;     /* SQL command */
    int     status;         /* Status return */

    sql = DqsCountInit("KEYDATA_VIEW");
    DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype, clause++);
    DqsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, KSM_STATE_READY, clause++);
    if (zone_id != -1) {
        DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, clause++);
    }
    DqsEnd(&sql);

    status = DbIntQuery(DbHandle(), count, sql);
    DqsFree(sql);

    if (status != 0) {
        status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
    }
	DbgLog(DBG_M_REQUEST, KME_READYCNT, *count,
		KsmKeywordTypeValueToName(keytype));

    return status;
}


/*+
 * KsmRequestIssueKeys - Issue Keys
 *
 * Description:
 *      Done as the last step in the "REQUEST KEYS" operation, this actually
 *      issues the keys that should be in the current zone file.  All keys in
 *      the "publish", "ready", "active" and "retire" states are included.
 *
 * Arguments:
 *      int keytype
 *          Type of keys required.
 *
 *      KSM_REQUEST_CALLBACK callback
 *          Callback function called for every key that will be issued.
 *
 *      void* context
 *      	Context argument passed uninterpreted to the callback function.
 *
 *      int zone_id
 *          ID of zone that we are looking at (-1 == all zones)
 *
 * Returns:
 *      int
 *          Status return.  0 => success, <>0 => error (in which case a message
 *          will have been output).
-*/

int KsmRequestIssueKeys(int keytype, KSM_REQUEST_CALLBACK callback,
	void* context, int zone_id)
{
    int     clause = 0;     /* For the WHERE clause */
    KSM_KEYDATA data;       /* Data for this key */
    DB_RESULT	result;     /* Result set from query */
    char    in[128];        /* Easily large enought for four keys */
    size_t  nchar;          /* Number of output characters */
    char*   sql = NULL;     /* SQL statement to get listing */
    int     status;         /* Status return */

    /*
     * Construct the "IN" statement listing the states of the keys that
     * are included in the output.
     */

    nchar = snprintf(in, sizeof(in), "(%d, %d, %d, %d)",
        KSM_STATE_PUBLISH, KSM_STATE_READY, KSM_STATE_ACTIVE, KSM_STATE_RETIRE);
    if (nchar >= sizeof(in)) {
        status = MsgLog(KME_BUFFEROVF, "KsmRequestIssueKeys");
        return status;
    }

    /* Create the SQL command to interrogate the database */

    sql = DqsSpecifyInit("KEYDATA_VIEW", DB_KEYDATA_FIELDS);
    DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype, clause++);
    DqsConditionKeyword(&sql, "STATE", DQS_COMPARE_IN, in, clause++);
    if (zone_id != -1) {
        DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, clause++);
    }
    DqsEnd(&sql);

    /* Now iterate round the keys meeting the condition and print them */

    status = KsmKeyInitSql(&result, sql);
    if (status == 0) {
        status = KsmKey(result, &data);
        while (status == 0) {
			status = (*callback)(context, &data);
			if (status == 0) {
				status = KsmKey(result, &data);
			}
        }

        /* Convert EOF status to success */

        if (status == -1) {
            status = 0;
        }

        KsmKeyEnd(result);
    }

    return status;
}



/*+
 * KsmRequestPrintKey - Print Key Data
 *
 * Description:
 *		Suitable callback function for KsmRequest, this prints a summary of the
 *		key information to stdout.
 *
 * Arguments:
 * 		void* context
 * 			Context passed to KsmUpdate.  This is unused.
 *
 * 		KSM_KEYDATA* data
 * 			Data about the key to be isssued.
 *
 * Returns:
 * 		int
 * 			Always 0.
-*/

int KsmRequestPrintKey(void* context, KSM_KEYDATA* data)
{
	printf("%s %lu %d %d %s\n", KsmKeywordStateValueToName(data->state),
		data->keypair_id, data->keytype, data->algorithm, data->location);

	return 0;
}
