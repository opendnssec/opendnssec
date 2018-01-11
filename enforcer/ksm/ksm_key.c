/*
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
 * KsmKey - Manipulation of Key Information
 *
 * Description:
 *      Holds the functions needed to manipulate the KEYDATA table.
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
#include "ksm/ksm.h"
#include "ksm/ksmdef.h"
#include "ksm/ksm_internal.h"
#include "ksm/message.h"
#include "ksm/string_util.h"
#include "ksm/string_util2.h"

/*+
 * KsmKeyPairCreate - Create Entry in the KeyPairs table 
 *                    (i.e. key creation in the HSM)
 *
 * Description:
 *      Creates a key in the database.
 *
 * Arguments:
 *      policy_id
 *          policy that the key is created for
 *      HSMKeyID
 *          ID the key is refered to in the HSM
 *      smID
 *          security module ID
 *      size
 *          size of key
 *      alg
 *          algorithm used
 *      generate
 *          timestamp of generation
 *
 *      DB_ID* id (returned)
 *          ID of the created entry.  This will be undefined on error.
 *
 * Returns:
 *      int
 *          Status return.  0=> Success, non-zero => error.
-*/
int KsmKeyPairCreate(int policy_id, const char* HSMKeyID, int smID, int size, int alg, const char* generate, DB_ID* id)
{
    unsigned long rowid;			/* ID of last inserted row */
    int         status = 0;         /* Status return */
    char*       sql = NULL;         /* SQL Statement */

    /* Check arguments */
    if (id == NULL) {
        return MsgLog(KSM_INVARG, "NULL id");
    }

    sql = DisSpecifyInit("keypairs", "policy_id, HSMkey_id, securitymodule_id, size, algorithm, generate");
    DisAppendInt(&sql, policy_id);
    DisAppendString(&sql, HSMKeyID);
    DisAppendInt(&sql, smID);
    DisAppendInt(&sql, size);
    DisAppendInt(&sql, alg);
    DisAppendString(&sql, generate);
    DisEnd(&sql);

    /* Execute the statement */

    status = DbExecuteSqlNoResult(DbHandle(), sql);
    DisFree(sql);

    if (status == 0) {

        /* Succcess, get the ID of the inserted record */

		status = DbLastRowId(DbHandle(), &rowid);
		if (status == 0) {
			*id = (DB_ID) rowid;
		}
    }

    return status;
}

/*+
 * KsmDnssecKeyCreate - Create Entry in Dnsseckeys table 
 *                      (i.e. when a key is assigned to a policy/zone)
 *
 * Description:
 *      Allocates a key in the database.
 *
 * Arguments:
 *      KSM_KEY* data
 *          Data to insert into the database.  The ID argument is ignored.
 *
 *      DB_ID* id (returned)
 *          ID of the created entry.  This will be undefined on error.
 *
 * Returns:
 *      int
 *          Status return.  0=> Success, non-zero => error.
-*/

int KsmDnssecKeyCreate(int zone_id, int keypair_id, int keytype, int state, int rfc5011, const char* time, const char* retTime, DB_ID* id)
{
	unsigned long rowid;			/* ID of last inserted row */
    int         status = 0;         /* Status return */
    char*       sql = NULL;         /* SQL Statement */
    char*       columns = NULL;     /* what columns are we setting */

    /* Check arguments */
    if (id == NULL) {
        return MsgLog(KSM_INVARG, "NULL id");
    }

    StrAppend(&columns, "zone_id, keypair_id, keytype, state, rfc5011, revoked");
    if (state != KSM_STATE_GENERATE) {
        StrAppend(&columns, ", ");
        StrAppend(&columns, KsmKeywordStateValueToName(state));
    }
	if (state == KSM_STATE_ACTIVE && (retTime != NULL && retTime[0] != '\0')) {
        StrAppend(&columns, ", retire");
    }

    sql = DisSpecifyInit("dnsseckeys", columns);
    DisAppendInt(&sql, zone_id);
    DisAppendInt(&sql, keypair_id);
    DisAppendInt(&sql, keytype);
    DisAppendInt(&sql, state);
    DisAppendInt(&sql, rfc5011 && (keytype==KSM_TYPE_KSK));
    DisAppendInt(&sql, 0); /* revoke */
    if (state != KSM_STATE_GENERATE) {
        DisAppendString(&sql, time);
    }
	if (state == KSM_STATE_ACTIVE && (retTime != NULL && retTime[0] != '\0')) {
        DisAppendString(&sql, retTime);
    }
    DisEnd(&sql);

    /* Execute the statement */

    status = DbExecuteSqlNoResult(DbHandle(), sql);
    DisFree(sql);
    StrFree(columns);

    if (status == 0) {

        /* Succcess, get the ID of the inserted record */

		status = DbLastRowId(DbHandle(), &rowid);
		if (status == 0) {
			*id = (DB_ID) rowid;
		}
    }

    return status;
}

/*+
 * KsmKeyInitSql - Query for Key Information With Sql Query
 *
 * Description:
 *      Performs a query for keys in the keydata table that match the given
 *      conditions.
 *
 * Arguments:
 *      DB_RESULT* result
 *          Pointer to a result to be used for information retrieval.  Will
 *          be NULL on error.
 *
 *      const char* sql
 *          SQL statement to select keys.
 *
 *          (Actually, the statement could be anything, but it is assumed
 *          that it is an SQL statement starting "SELECT xxx FROM KEYDATA".)
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
-*/

int KsmKeyInitSql(DB_RESULT* result, const char* sql)
{
    return DbExecuteSql(DbHandle(), sql, result);
}




/*+
 * KsmKeyInit - Query for Key Information
 *
 * Description:
 *      Performs a query for keys in the keydata table that match the given
 *      conditions.
 *
 * Arguments:
 *      DB_RESULT* result
 *          Pointer to a result to be used for information retrieval.  Will
 *          be NULL on error.
 *
 *      DQS_QUERY_CONDITION* condition
 *          Array of condition objects, each defining a condition.  The
 *          conditions are ANDed together.  The array should end with an object
 *          with a condition code of 0.
 *
 *          If NULL, all objects are selected.
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
-*/

int KsmKeyInit(DB_RESULT* result, DQS_QUERY_CONDITION* condition)
{
    int     i;                  /* Condition index */
    char*   sql = NULL;         /* SQL query */
    int     status = 0;         /* Status return */

    /* Construct the query */

    sql = DqsSpecifyInit("KEYDATA_VIEW", DB_KEYDATA_FIELDS);
    if (condition) {
        for (i = 0; condition[i].compare != DQS_END_OF_LIST; ++i) {
            switch (condition[i].code) {
            case DB_KEYDATA_ALGORITHM:
                DqsConditionInt(&sql, "ALGORITHM", condition[i].compare,
                    condition[i].data.number, i);
                break;

            case DB_KEYDATA_ID:
                DqsConditionInt(&sql, "ID", condition[i].compare,
                    condition[i].data.number, i);
                break;

            case DB_KEYDATA_KEYTYPE:
                DqsConditionInt(&sql, "KEYTYPE", condition[i].compare,
                    condition[i].data.number, i);
                break;

            case DB_KEYDATA_STATE:
                DqsConditionInt(&sql, "STATE", condition[i].compare,
                        condition[i].data.number, i);
                break;

            case DB_KEYDATA_ZONE_ID:
                DqsConditionInt(&sql, "ZONE_ID", condition[i].compare,
                    condition[i].data.number, i);
                break;

            default:

                /* Warn about unrecognised condition code */

                MsgLog(KME_UNRCONCOD, condition[i].code);
            }
        }
    }
    DqsEnd(&sql);

    /* Execute query and free up the query string */

    status = KsmKeyInitSql(result, sql);
    DqsFree(sql);

    return status;
}



/*+
 * KsmKeyInitId - Query for Key Information by ID
 *
 * Description:
 *      Performs a query for a key in the zone table that matches the
 *      given ID.
 *
 * Arguments:
 *      DB_RESULT* result
 *          Pointer to a result to be used for information retrieval.  Will
 *          be NULL on error.
 *
 *      DB_ID id
 *          ID of the object.
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
-*/

int KsmKeyInitId(DB_RESULT* result, DB_ID id)
{
    DQS_QUERY_CONDITION condition[2];   /* Condition for query */

    /* Initialize */

    condition[0].code = DB_KEYDATA_ID;
    condition[0].compare = DQS_COMPARE_EQ;
    condition[0].data.number = (int) id;

    condition[1].compare = DQS_END_OF_LIST;

    return KsmKeyInit(result, condition);
}



/*+
 * KsmKey - Return Key Information
 *
 * Description:
 *      Returns information about the next key in the result set.
 *
 * Arguments:
 *      DB_RESULT result
 *          Handle from KsmKeyInit
 *
 *      KSM_KEYDATA* data
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

int KsmKey(DB_RESULT result, KSM_KEYDATA* data)
{
    DB_ROW      row = NULL;     /* Row data */
    int         status = 0;     /* Return status */

    /* Check arguments */
    if (data == NULL) {
        return MsgLog(KSM_INVARG, "NULL data");
    }

	/* Initialize */

	memset(data, 0, sizeof(KSM_KEYDATA));

    /* Get the next row from the data and copy data across */

	status = DbFetchRow(result, &row);

	if (status == 0) {
        status = DbUnsignedLong(row, DB_KEYDATA_ID, &(data->keypair_id));
	}

	if (status == 0) {
        status = DbInt(row, DB_KEYDATA_STATE, &(data->state));
	}

	if (status == 0) {
        status = DbStringBuffer(row, DB_KEYDATA_GENERATE,
            data->generate, sizeof(data->generate));
	}

	if (status == 0) {
        status = DbStringBuffer(row, DB_KEYDATA_PUBLISH,
            data->publish, sizeof(data->publish));
	}

	if (status == 0) {
        status = DbStringBuffer(row, DB_KEYDATA_READY,
            data->ready, sizeof(data->ready));
	}

	if (status == 0) {
        status = DbStringBuffer(row, DB_KEYDATA_ACTIVE,
            data->active, sizeof(data->active));
	}

	if (status == 0) {
        status = DbStringBuffer(row, DB_KEYDATA_RETIRE,
            data->retire, sizeof(data->retire));
	}

	if (status == 0) {
        status = DbStringBuffer(row, DB_KEYDATA_DEAD,
            data->dead, sizeof(data->dead));
	}

	if (status == 0) {
        status = DbInt(row, DB_KEYDATA_KEYTYPE, &(data->keytype));
	}

	if (status == 0) {
        status = DbInt(row, DB_KEYDATA_ALGORITHM, &(data->algorithm));
	}

/*	if (status == 0) {
        status = DbInt(row, DB_KEYDATA_SIGLIFETIME, &(data->siglifetime));
	}
*/
	if (status == 0) {
        status = DbStringBuffer(row, DB_KEYDATA_LOCATION,
            data->location, sizeof(data->location));
    }

	if (status == 0) {
        status = DbInt(row, DB_KEYDATA_ZONE_ID, &(data->zone_id));
	}

	if (status == 0) {
        status = DbInt(row, DB_KEYDATA_FIXED_DATE, &(data->fixedDate));
	}

    if (status == 0) {
        status = DbInt(row, DB_KEYDATA_RFC5011, &(data->rfc5011));
    }
    if (status == 0) {
        status = DbInt(row, DB_KEYDATA_REVOKE, &(data->revoke));
    }

	DbFreeRow(row);

    return status;
}


/*+
 * KsmKeyEnd - End Key Information
 *
 * Description:
 *      Called at the end of a ksm_key cycle, frees up the stored
 *      result set.
 *
 *      N.B. This does not clear stored error information, so allowing it
 *      to be called after a failure return from KsmKey to free up database
 *      context whilst preserving the reason for the error.
 *
 * Arguments:
 *      DB_RESULT result
 *          Handle from KsmKeyInit
-*/

void KsmKeyEnd(DB_RESULT result)
{
    DbFreeResult(result);
}



/*+
 * KsmKeyData - Return Data for Key
 *
 * Description:
 *      Returns data for the named Key.
 *
 * Arguments:
 *      DB_ID id
 *          Name/ID of the Key.
 *
 *      KSM_GROUP* data
 *          Data for the Key.
 *
 * Returns:
 *      int
 *          Status return.  One of:
 *
 *              0       Success
 *              -1      Key not found
 *              Other   Error
-*/

int KsmKeyData(DB_ID id, KSM_KEYDATA* data)
{
    DB_RESULT   result;     /* Handle to the data */
    int         status;     /* Status return code */

    status = KsmKeyInitId(&result, id);
    if (status == 0) {

        /* Retrieve the key data */

        status = KsmKey(result, data);
        (void) KsmKeyEnd(result);
    }
    /*
     * else {
     *      On error, a message will have been output
     * }
     */

    return status;
}

/*+
 * KsmKeyPredict - predict how many keys are needed
 *
 * Description:
 *      Given a policy and a keytype work out how many keys will be required
 *      during the timeinterval specified (in seconds).
 *
 *      We assume no emergency rollover and that a key has just been published
 *
 *      Dt	= interval
 *      Sp	= safety margin
 *      Lk	= lifetime of the key (either KSK or ZSK)
 *      Ek  = no of standby keys 
 * 
 *      no of keys = ( (Dt + Sp)/Lk ) + Ek
 *      
 *      (rounded up)
 *
 * Arguments:
 *      int policy_id
 *          The policy in question
 *      KSM_TYPE key_type
 *          KSK or ZSK
 *      int shared_keys 
 *          0 if keys not shared between zones
 *      int interval
 *          timespan (in seconds)
 *      int *count
 *          (OUT) the number of keys (-1 on error)
 *      int rollover_scheme
 *          KSK rollover scheme in use
 *      int zone_count
 *          Number of zones on this policy
 *
 * Returns:
 *      int
 *          Status return.  One of:
 *
 *              0       Success
 *              Other   Error
-*/

int KsmKeyPredict(int policy_id, int keytype, int shared_keys, int interval, int *count, int rollover_scheme, int zone_count) 
{ 
    int status = 0;   /* Status return */ 
    KSM_PARCOLL coll; /* Parameters collection */ 

    /* Check arguments */
    if (count == NULL) {
        return MsgLog(KSM_INVARG, "NULL count");
    }

    /* make sure that we have at least one zone */ 
    if (zone_count == 0) { 
        *count = 0; 
        return status; 
    } 

    /* Check that we have a valid key type */
    if ((keytype != KSM_TYPE_KSK) && (keytype != KSM_TYPE_ZSK)) {
        status = MsgLog(KME_UNKEYTYPE, keytype);
        return status;
    }

    /* Get list of parameters */
    status = KsmParameterCollection(&coll, policy_id);
    if (status != 0) {
        *count = -1;
        return status;
    }

    /* We should have the policy now */
    if (keytype == KSM_TYPE_KSK)
    {
        if (coll.ksklife == 0) {
            *count = coll.standbyksks + 1;
        } 
        else if (rollover_scheme == KSM_ROLL_DNSKEY) {
            *count = ((interval + coll.pub_safety + coll.propdelay + coll.kskttl)/coll.ksklife) + coll.standbyksks + 1;
        }
        else if (rollover_scheme == KSM_ROLL_DS) {
            *count = ((interval + coll.pub_safety + coll.kskpropdelay + coll.dsttl)/coll.ksklife) + coll.standbyksks + 1;
        }
        /* YBS: I don't think 5011 affects the number of keys needed. It
         * does not affect lifetime, just the time the keys are published.*/
/*        else if (rollover_scheme == KSM_ROLL_RRSET) {
            temp = MAX((propdelay + kskttl), (kskpropdelay + dsttl));
            if (RFC5011) {
                temp = max(temp, 30*24*60*60);
            }
            *count = ((interval + coll.pub_safety + temp)/coll.ksklife) + coll.standbyksks + 1;
        } */

    }
    else if (keytype == KSM_TYPE_ZSK)
    {
        if (coll.zsklife == 0) {
            *count = coll.standbyzsks + 1;
        } else {
            *count = ((interval + coll.pub_safety)/coll.zsklife) + coll.standbyzsks + 1;
        }
    } 

    if (shared_keys == KSM_KEYS_NOT_SHARED) { 
        *count *= zone_count;
    }

    return status;
}

/*+ 
 * KsmKeyCountQueue - Return Number of Keys in the queue before active state 
 * 
 * Description: 
 *      Returns the number of keys in the KSM_STATE_GENERATE, KSM_STATE_PUBLISH,  
 *      KSM_STATE_READY and KSM_STATE_ACTIVE state. 
 *      (plus KSM_STATE_DSSUB, KSM_STATE_DSPUBLISH, KSM_STATE_DSREADY 
 *      for standby KSKs)
 * 
 * Arguments: 
 *      int keytype 
 *          Key type, KSK or ZSK 
 * 
 *      int* count (returned) 
 *          Number of keys in the que. 
 * 
 *      int zone_id 
 *          ID of zone that we are looking at (-1 == all zones) 
 * 
 * Returns: 
 *      int 
 *          Status return. 0 => success, Other implies error, in which case a 
 *          message will have been output. 
-*/ 

int KsmKeyCountQueue(int keytype, int* count, int zone_id) 
{ 
    int     clause = 0;     /* Clause count */ 
    char*   sql = NULL;     /* SQL to interrogate database */ 
    int     status = 0;     /* Status return */ 
    char    in[128];        /* Easily large enought for 7 keys */ 
    size_t  nchar;          /* Number of output characters */

    /* Create the SQL command to interrogate the database */ 

    nchar = snprintf(in, sizeof(in), "(%d, %d, %d, %d, %d, %d, %d)", 
            KSM_STATE_GENERATE, KSM_STATE_PUBLISH, KSM_STATE_READY, KSM_STATE_ACTIVE, KSM_STATE_DSSUB, KSM_STATE_DSPUBLISH, KSM_STATE_DSREADY); 
    if (nchar >= sizeof(in)) { 
        status = MsgLog(KME_BUFFEROVF, "KsmKeyCountQueue"); 
        return status; 
    }

    sql = DqsCountInit("KEYDATA_VIEW"); 
    DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype, clause++); 
    DqsConditionKeyword(&sql, "STATE", DQS_COMPARE_IN, in, clause++);
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
 * KsmKeyCountStillGood - Return Number of Keys that will still be usable at a particular
 *                        time given a number of parameters 
 * 
 * Description: 
 *      Returns the number of keys in the KSM_STATE_GENERATE, KSM_STATE_PUBLISH,
 *      KSM_STATE_READY, KSM_STATE_ACTIVE (or KSM_STATE_DSSUB, 
 *      KSM_STATE_DSPUBLISH, KSM_STATE_DSREADY for standby KSKs) state after 
 *      the given interval. 
 * 
 * Arguments:
 *      int policy_id
 *          id of the policy for which they key must have been created 
 *              (-1 == all policies)
 *      int sm
 *          id of security module
 *              (-1 == all modules)
 *      int bits
 *          size of key desired
 *              (-1 == all sizes)
 *      int algorithm
 *          algorithm of key desired
 *              (-1 == all algorithms`)
 *      int interval
 *          how many seconds in the future we are talking about
 *      const char* datetime
 *          string describing when this calculation is being run
 * 
 *      int* count (returned) 
 *          Number of keys in the que. 
 * 
 *      int keytype 
 *          Key type, KSK or ZSK 
 * 
 * Returns: 
 *      int 
 *          Status return. 0 => success, Other implies error, in which case a 
 *          message will have been output. 
-*/ 
 
int KsmKeyCountStillGood(int policy_id, int sm, int bits, int algorithm, int interval, const char* datetime, int *count, int keytype)
{ 
    int     where = 0;      /* WHERE clause value */
    char*   sql = NULL;     /* SQL to interrogate database */ 
    int     status = 0;     /* Status return */ 
    char    in[128];        /* Easily large enought for three keys */ 
    char    buffer[512];    /* For constructing part of the command */
    size_t  nchar;          /* Number of output characters */
    int     total_interval; /* interval plus retirement time */
    KSM_PARCOLL collection; /* Parameters collection */
 
    /* 
     * Construct the "IN" statement listing the states of the keys that 
     * are included in the output. 
     */ 

    /* Get list of parameters */
    status = KsmParameterCollection(&collection, policy_id);
    if (status != 0) {
        return status;
    }

    if (keytype == KSM_TYPE_ZSK)
    {
        total_interval = KsmParameterZskTtl(&collection) +
                         KsmParameterPropagationDelay(&collection) +
                         KsmParameterPubSafety(&collection) +
                         interval;
    } else {
        total_interval = KsmParameterKskTtl(&collection) +
                         KsmParameterKskPropagationDelay(&collection) +
                         KsmParameterPubSafety(&collection) +
                         interval;
    }

    nchar = snprintf(in, sizeof(in), "(%d, %d, %d, %d, %d, %d, %d)", 
        KSM_STATE_GENERATE, KSM_STATE_PUBLISH, KSM_STATE_READY, KSM_STATE_ACTIVE, KSM_STATE_DSSUB, KSM_STATE_DSPUBLISH, KSM_STATE_DSREADY); 
    if (nchar >= sizeof(in)) { 
        status = MsgLog(KME_BUFFEROVF, "KsmKeyCountStillGood"); 
        return status; 
    } 

    /* 
     * TODO is there an alternative to DATE_ADD which is more generic? 
     */
#ifdef USE_MYSQL
    nchar = snprintf(buffer, sizeof(buffer),
        "DATE_ADD('%s', INTERVAL %d SECOND)", datetime, total_interval);
#else
    nchar = snprintf(buffer, sizeof(buffer),
        "DATETIME('%s', '+%d SECONDS')", datetime, total_interval);
#endif /* USE_MYSQL */
    if (nchar >= sizeof(buffer)) {
        status = MsgLog(KME_BUFFEROVF, "KsmKeyCountStillGood");
        return status;
    }

    /* Create the SQL command to interrogate the database */ 
 
     /* Use 'distinct location' here so we don't count multiple entries for zones which share keys*/
    sql = StrStrdup("SELECT COUNT(*) FROM ");
    StrAppend(&sql, "(SELECT DISTINCT location FROM KEYDATA_VIEW");
    if (policy_id != -1) {
        DqsConditionInt(&sql, "policy_id", DQS_COMPARE_EQ, policy_id, where++);
    }
    if (sm != -1) {
        DqsConditionInt(&sql, "securitymodule_id", DQS_COMPARE_EQ, sm, where++);
    }
    if (bits != -1) {
        DqsConditionInt(&sql, "size", DQS_COMPARE_EQ, bits, where++);
    }
    DqsConditionInt(&sql, "keytype", DQS_COMPARE_EQ, keytype, where++);
    if (algorithm != -1) {
        DqsConditionInt(&sql, "algorithm", DQS_COMPARE_EQ, algorithm, where++);
    }

    DqsConditionKeyword(&sql, "(STATE", DQS_COMPARE_IN, in, where++);
    StrAppend(&sql, " or STATE is NULL)");
    
    /* Can't use our generic functions for this aggregated clause */
#ifdef USE_MYSQL
    StrAppend(&sql, " and (RETIRE > ");
#else
    StrAppend(&sql, " and (DATETIME(RETIRE) > ");
#endif /* USE_MYSQL */
    StrAppend(&sql, buffer);
    StrAppend(&sql, " or RETIRE is NULL)");

    StrAppend(&sql, " and location NOT IN (SELECT DISTINCT location FROM KEYDATA_VIEW");
    where = 0;
    if (policy_id != -1) {
        DqsConditionInt(&sql, "policy_id", DQS_COMPARE_EQ, policy_id, where++);
    }
    if (sm != -1) {
        DqsConditionInt(&sql, "securitymodule_id", DQS_COMPARE_EQ, sm, where++);
    }
    if (bits != -1) {
        DqsConditionInt(&sql, "size", DQS_COMPARE_EQ, bits, where++);
    }
    DqsConditionInt(&sql, "keytype", DQS_COMPARE_EQ, keytype, where++);
    if (algorithm != -1) {
        DqsConditionInt(&sql, "algorithm", DQS_COMPARE_EQ, algorithm, where++);
    }

#ifdef USE_MYSQL
    StrAppend(&sql, " and (RETIRE is NOT NULL) and (RETIRE < ");
#else
    StrAppend(&sql, " and (RETIRE is NOT NULL) and (DATETIME(RETIRE) < ");
#endif
    StrAppend(&sql, buffer);
    StrAppend(&sql, " )))");

    /*DqsConditionKeyword(&sql, "zone_id", DQS_COMPARE_IS, "NULL", where++);*/
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
 * KsmKeyGetUnallocated
 *
 * Description:
 *      Given a set of policy values get the next unallocated keypair
 *      Executes:
 *          select min(id) from keydata 
 *              where policy_id = policy_id 
 *                and securitymodule_id = sm 
 *                and size = bits 
 *                and algorithm = algorithm 
 *                and state is KSM_STATE_GENERATE
 *
 * Arguments:
 *      int policy_id
 *          id of the policy for which they key must have been created
 *      int sm
 *          id of security module
 *      int bits
 *          size of key desired
 *      int algorithm
 *          algorithm of key desired
 *      int zone_id
 *          zone we are allocating to
 *      int share_keys
 *          0 if keys are not shared; 1 if they are
 *      int *keypair_id (out)
 *          id of next keypair
 *
 * Returns:
 *      int
 *          Status return.  0=> Success, non-zero => error.
 *          -1 == no free keys on that policy
 */

int KsmKeyGetUnallocated(int policy_id, int sm, int bits, int algorithm, int zone_id, int share_keys, int *keypair_id) 
{

    int     where = 0;          /* WHERE clause value */
    char*   sql = NULL;         /* SQL query */
    DB_RESULT       result;     /* Handle converted to a result object */
    DB_ROW      row = NULL;     /* Row data */
    int     status = 0;         /* Status return */
    char    in_sql[1024];
    char    in_sql2[1024];

    if (share_keys == KSM_KEYS_NOT_SHARED) {
        /* Construct the query */
        sql = DqsSpecifyInit("KEYDATA_VIEW","min(id)");
        DqsConditionInt(&sql, "policy_id", DQS_COMPARE_EQ, policy_id, where++);
        DqsConditionInt(&sql, "securitymodule_id", DQS_COMPARE_EQ, sm, where++);
        DqsConditionInt(&sql, "size", DQS_COMPARE_EQ, bits, where++);
        DqsConditionInt(&sql, "algorithm", DQS_COMPARE_EQ, algorithm, where++);
        DqsConditionKeyword(&sql, "zone_id", DQS_COMPARE_IS, "NULL", where++);
    } else {
        snprintf(in_sql, 1024, "(select id from KEYALLOC_VIEW where zone_id = %d)", zone_id);
        snprintf(in_sql2, 1024, "(select distinct id from KEYDATA_VIEW where policy_id = %d and state in (%d, %d))", policy_id, KSM_STATE_RETIRE, KSM_STATE_DEAD);

        /* Construct the query */
        sql = DqsSpecifyInit("KEYALLOC_VIEW","min(id)");
        DqsConditionInt(&sql, "policy_id", DQS_COMPARE_EQ, policy_id, where++);
        DqsConditionInt(&sql, "securitymodule_id", DQS_COMPARE_EQ, sm, where++);
        DqsConditionInt(&sql, "size", DQS_COMPARE_EQ, bits, where++);
        DqsConditionInt(&sql, "algorithm", DQS_COMPARE_EQ, algorithm, where++);
        DqsConditionKeyword(&sql, "zone_id", DQS_COMPARE_IS, "NULL", where++);
        DqsConditionKeyword(&sql, "id", DQS_COMPARE_NOT_IN, in_sql, where++);
        DqsConditionKeyword(&sql, "id", DQS_COMPARE_NOT_IN, in_sql2, where++);
    }
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
        DbInt(row, DB_KEYDATA_ID, keypair_id);
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
 * KsmMarkKeysAsDead - When deleting zones we may need to indicate that keys are now dead
 *                     (i.e. when keysharing is turned off or if we removed is the last zone on a policy)
 *
 * Description:
 *      Marks selected keys as dead in the database.
 *
 * Arguments:
 *      int zone_id
 *          ID of the zone (-1 if all zones are being removed)
 *
 * Returns:
 *      int
 *          Status return.  0=> Success, non-zero => error.
-*/

int KsmMarkKeysAsDead(int zone_id)
{
    int status = 0;

    DB_RESULT	    result;         /* Result of query */
    KSM_KEYDATA     data;           /* key information */
    char*           sql = NULL;     /* SQL query */
    int             clause = 0;

    /* Find all the keys which are on that zone but are not already dead */
    sql = DqsSpecifyInit("KEYDATA_VIEW", DB_KEYDATA_FIELDS);
    DqsConditionInt(&sql, "state", DQS_COMPARE_LT, KSM_STATE_DEAD, clause++);
    DqsConditionInt(&sql, "state", DQS_COMPARE_GT, KSM_STATE_GENERATE, clause++);
    if (zone_id != -1) {
        DqsConditionInt(&sql, "zone_id", DQS_COMPARE_EQ, zone_id, clause++);
    }
    DqsEnd(&sql);

    /* Now iterate round the keys meeting the condition and print them */

    status = KsmKeyInitSql(&result, sql);
    if (status == 0) {
        status = KsmKey(result, &data);
        while (status == 0) {

            /* Kill the Key */
			status = KsmKillKey(data.keypair_id, zone_id);
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

	DqsFree(sql);
    return 0;
}

/*+
 * KsmKillKey - Update key status to "dead"
 *
 * Description:
 *      Changes a keys status to dead (from any state)
 *
 * Arguments:
 *      int keypair_id
 *          Which key to process
 *      int zone_id
 *          Which zone to process
 *
 * Returns:
 *      int
 *          Status return.  0=> Success, non-zero => error.
-*/

int KsmKillKey(int keypair_id, int zone_id)
{
    int         status = 0;         /* Status return */
    char*       sql = NULL;         /* SQL Statement */
    int         set = 0;
    char*       now = DtParseDateTimeString("now");

    /* Check datetime in case it came back NULL */
    if (now == NULL) {
        printf("Couldn't turn \"now\" into a date, quitting...\n");
        exit(1);
    }

    sql = DusInit("dnsseckeys");
    DusSetInt(&sql, "STATE", KSM_STATE_DEAD, set++);
    DusSetString(&sql, "DEAD", now, set++);
    DusConditionInt(&sql, "KEYPAIR_ID", DQS_COMPARE_EQ, keypair_id, 0);
    if (zone_id != -1) {
        DqsConditionInt(&sql, "zone_id", DQS_COMPARE_EQ, zone_id, 1);
    }
    DusEnd(&sql);

    /* Execute the statement */

    status = DbExecuteSqlNoResult(DbHandle(), sql);
    DusFree(sql);

    StrFree(now);

    return status;
}

