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
 * Filename: test_ksm_key.c - Test Key Module
 *
 * Description:
 *      This is a short test module to check the function in the Ksm Key
 *      module.
 *
 *      The test program makes use of the CUnit framework, as described in
 *      http://cunit.sourceforge.net
-*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "CUnit/Basic.h"

#include "ksm/ksm.h"
#include "ksm/db_fields.h"
#include "ksm/datetime.h"
#include "ksm/string_util.h"
#include "test_routines.h"

/*+
 * testKeyClear - Clear KEYDATA Structure
 *
 * Description:
 *      Zeroes the contents of the passed KEYDATA structure.
 *
 * Arguments:
 *      KSM_KEYDATA* data
 *          Key data object to initialize.
-*/

static void TestKeyClear(KSM_KEYDATA* data)
{
    memset(data, 0, sizeof(KSM_KEYDATA));

    return;
}

/*+
 * TestKeyDefaults - Set Default Values
 *
 * Description:
 *      Sets up default values for the key data object.
 *
 * Arguments:
 *      KSM_KEYDATA* data
 *          Key data object to initialize.
-*/

static void TestKeyDefaults(KSM_KEYDATA* data)
{
    TestKeyClear(data);

    data->algorithm = KSM_ALGORITHM_RSASHA1;
    data->keytype = KSM_TYPE_ZSK;
    data->siglifetime = 7 * 24 * 3600;  /* 7 days */
    data->state = KSM_STATE_GENERATE;

    data->flags |= (KEYDATA_M_ALGORITHM | KEYDATA_M_KEYTYPE |
        KEYDATA_M_SIGLIFETIME | KEYDATA_M_STATE);
    
    return;
}

/*+
 * TestKsmKeyPairCreate - Test KeyPair Create code
 *
 * Description:
 *      Tests that keys are created when requested
-*/

static void TestKsmKeyPairCreate(void)
{

    DB_ID           key_id;         /* Created key ID */
    int             status = 0;     /* Status return */
    int			    rowcount;	    /* Number of rows returned */
	char*		    sql;		    /* Constructed query */
	int			    where = 0;	    /* WHERE clause count */

    /* variables to stick into table */
    int     policy_id = 2;
    char*   HSMKeyID = "0x1";
    int     smID = 1;
    int     size = 1024;
    int     alg = KSM_ALGORITHM_DSASHA1;
    char*   generate = DtParseDateTimeString("now");

    status = KsmKeyPairCreate(policy_id, HSMKeyID, smID, size, alg, generate, &key_id);

	CU_ASSERT_EQUAL(status, 0);

	/* Check that a key has been added */

	sql = DqsCountInit("keypairs");
	DqsConditionInt(&sql, "ID", DQS_COMPARE_EQ, key_id, where++);
	DqsEnd(&sql);
	status = DbIntQuery(DbHandle(), &rowcount, sql);
	DqsFree(sql);

	CU_ASSERT_EQUAL(status, 0);

	CU_ASSERT_EQUAL(rowcount, 1);

	StrFree(generate);

}

/*+
 * TestKsmKeyCreate - Test Key Create code
 *
 * Description:
 *      Tests that keys are created when requested
-*/

static void TestKsmDnssecKeyCreate(void)
{

    DB_ID           keypair_id;     /* Created key ID */
    DB_ID           dnsseckey_id;   /* Created key ID */
    int             status = 0;     /* Status return */
    int			    rowcount;	    /* Number of rows returned */
	char*		    sql;		    /* Constructed query */
	int			    where = 0;	    /* WHERE clause count */
    int             zone_id = 1;

    /* Create a new keypair entry */
    int     policy_id = 2;
    char*   HSMKeyID = "0x1";
    int     smID = 1;
    int     size = 1024;
    int     alg = KSM_ALGORITHM_DSASHA1;
    char*   generate = "2009-01-01";

    status = KsmKeyPairCreate(policy_id, HSMKeyID, smID, size, alg, generate, &keypair_id);

	CU_ASSERT_EQUAL(status, 0);

    /* Now create a row in dnsseckeys for the above */

    status = KsmDnssecKeyCreate(zone_id, keypair_id, KSM_TYPE_ZSK, &dnsseckey_id);

	CU_ASSERT_EQUAL(status, 0);

	/* Check that a key has been added */

	sql = DqsCountInit("dnsseckeys");
	DqsConditionInt(&sql, "ID", DQS_COMPARE_EQ, dnsseckey_id, where++);
	DqsEnd(&sql);
	status = DbIntQuery(DbHandle(), &rowcount, sql);
	DqsFree(sql);

	CU_ASSERT_EQUAL(status, 0);

	CU_ASSERT_EQUAL(rowcount, 1);

}

/*+
 * TestKsmKeyModify - Test Key Modify code
 *
 * Description:
 *      Tests that keys are created when requested
-*/

static void TestKsmKeyModify(void)
{

    KSM_KEYDATA     data;           /* Holds information for insertion */
	char		buffer[8]; /* User buffer */
	DB_RESULT	result;		/* Result object */
	DB_ROW		row;		/* Row object */
    DB_ID           key_id;         /* Created key ID */
    int             status = 0;     /* Status return */
	char*		sql;		/* Constructed query */
	int			where = 0;	/* WHERE clause count */

    /* Create a new keypair entry */
    int     policy_id = 2;
    char*   HSMKeyID = "0x1";
    int     smID = 1;
    int     size = 1024;
    int     alg = KSM_ALGORITHM_DSASHA1;
    char*   generate = "2009-01-01";

    status = KsmKeyPairCreate(policy_id, HSMKeyID, smID, size, alg, generate, &key_id);

	CU_ASSERT_EQUAL(status, 0);

	/* Assume that a key has been added (tested above) */

    /* Change the algorithm and save to database */
    TestKeyClear(&data);
    data.algorithm = KSM_ALGORITHM_RSAMD5;
    data.flags |= KEYDATA_M_ALGORITHM;

    status = KsmKeyModify(&data, key_id, key_id);

	CU_ASSERT_EQUAL(status, 0);

    /* check on the key */
    sql = DqsSpecifyInit("KEYDATA_VIEW", DB_KEYDATA_FIELDS);
	DqsConditionInt(&sql, "ID", DQS_COMPARE_EQ, key_id, where++);
	DqsEnd(&sql);
	status = DbExecuteSql(DbHandle(), sql, &result);
	CU_ASSERT_EQUAL(status, 0);
	DqsFree(sql);

	status = DbFetchRow(result, &row);
	CU_ASSERT_EQUAL(status, 0);
	status = DbStringBuffer(row, DB_KEYDATA_ALGORITHM, buffer, sizeof(buffer));
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_STRING_EQUAL(buffer, "1");

	DbFreeRow(row);
	DbFreeResult(result);

}

/*+
 * TestKsmKeyPredict - Test Key Predict code
 *
 * Description:
 *      Tests that key numbers can be predicted
-*/

static void TestKsmKeyPredict(void)
{
    int policy_id = 2;
    int keytype = KSM_TYPE_KSK;
    int keys_shared = KSM_KEYS_SHARED;
    int interval = 86400*4; /* 4 days; lifetime == 1day */
    int count;
    int status;

    status =  KsmKeyPredict(policy_id, keytype, keys_shared, interval, &count, KSM_ROLL_DEFAULT);

    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(count, 7); /* 4 rollovers, 2 standby plus one to get ready */

    keytype = KSM_TYPE_ZSK;
    status =  KsmKeyPredict(policy_id, keytype, keys_shared, interval, &count, KSM_ROLL_DEFAULT);

    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(count, 7);
}

/*+
 * TestKsmKeyCountQueue - Test Key Queue counting code
 *
 * Description:
 *      Tests that key numbers can be counted
-*/

static void TestKsmKeyCountQueue(void)
{
    int zone_id = 1;
    int keytype = KSM_TYPE_KSK;
    int count;
    int status;

    status = KsmKeyCountQueue(keytype, &count, zone_id);

    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(count, 1); 

    keytype = KSM_TYPE_ZSK;
    status = KsmKeyCountQueue(keytype, &count, zone_id);

    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(count, 1);
}

/*+
 * TestKsmKeyCountUnallocated - Test Key Unallocated counting code
 *
 * Description:
 *      Tests that Unallocated key numbers can be counted
-*/

static void TestKsmKeyCountUnallocated(void)
{
    int policy_id = 2;
    int sm = -1;        /* count over all security modules */
    int bits = -1;      /* count over all sizes */
    int algorithm = -1; /* count over all algorithms */
    int count;
    int status;

/*    status = KsmKeyCountStillGood(policy_id, sm, bits, algorithm, &count);

    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(count, 15); 

    algorithm = KSM_ALGORITHM_RSASHA1;
    status = KsmKeyCountStillGood(policy_id, sm, bits, algorithm, &count);*/

    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(count, 13);
}

/*+
 * TestKsmKeyGetUnallocated - Test Key Unallocated getting code
 *
 * Description:
 *      Tests that Unallocated keys can be found
-*/

static void TestKsmKeyGetUnallocated(void)
{
    int policy_id = 2;
    int sm = 1;        /* count over all security modules */
    int bits = 1024;      /* count over all sizes */
    int algorithm = KSM_ALGORITHM_RSASHA1; /* count over all algorithms */
    int keypair_id;
    DB_ID dnsseckey_id;
    int zone_id = 1;
    int status;

    status = KsmKeyGetUnallocated(policy_id, sm, bits, algorithm, &keypair_id);

    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(keypair_id, 3); 

    status = KsmDnssecKeyCreate(zone_id, keypair_id, KSM_TYPE_ZSK, &dnsseckey_id);
    CU_ASSERT_EQUAL(status, 0);

    status = KsmKeyGetUnallocated(policy_id, sm, bits, algorithm, &keypair_id);

    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(keypair_id, 4);
}

/*+
 * TestKsmKeyCreateOnPolicy - Test Key Create code for shared key policies
 *
 * Description:
 *      Tests that keys are created when requested
-*/

static void TestKsmDnssecKeyCreateOnPolicy(void)
{

    DB_ID           key_pair_id;     /* Created key ID */
    DB_ID           dnsseckey_id;   /* Created key ID */
    int             status = 0;     /* Status return */
    int			    rowcount;	    /* Number of rows returned */
	char*		    sql;		    /* Constructed query */
	int			    where = 0;	    /* WHERE clause count */
    int             zone_id = 1;

    /* Create a new keypair entry */
    int     policy_id = 2;
    char*   HSMKeyID = "0x1";
    int     smID = 1;
    int     size = 1024;
    int     alg = KSM_ALGORITHM_DSASHA1;
    char*   generate = "2009-01-01";

    /* make sure that sharing is turned on */
    status = KsmParameterSet("zones_share_keys", "keys", 1, policy_id);
	CU_ASSERT_EQUAL(status, 0);

    status = KsmKeyPairCreate(policy_id, HSMKeyID, smID, size, alg, generate, &key_pair_id);
	CU_ASSERT_EQUAL(status, 0);

    /* Now create rows in dnsseckeys for the above */
    status = KsmDnssecKeyCreateOnPolicy(policy_id, key_pair_id, KSM_TYPE_ZSK);
	CU_ASSERT_EQUAL(status, 0);

	/* Check that a key has been added */

	sql = DqsCountInit("dnsseckeys");
	DqsConditionInt(&sql, "keypair_id", DQS_COMPARE_EQ, key_pair_id, where++);
	DqsEnd(&sql);
	status = DbIntQuery(DbHandle(), &rowcount, sql);
	DqsFree(sql);

	CU_ASSERT_EQUAL(status, 0);

    /* There are 2 zones on this policy */
	CU_ASSERT_EQUAL(rowcount, 2);

}

/*
 * TestKsmKey - Create Test Suite
 *
 * Description:
 *      Adds the test suite to the CUnit test registry and adds all the tests
 *      to it.
 *
 * Arguments:
 *      None.
 *
 * Returns:
 *      int
 *          Return status.  0 => Success.
 */

int TestKsmKey(void);	/* Declaration */
int TestKsmKey(void)
{
    struct test_testdef tests[] = {
        {"KsmKeyPairCreate", TestKsmKeyPairCreate},
        {"KsmDnssecKeyCreate", TestKsmDnssecKeyCreate},
        {"KsmKeyModify", TestKsmKeyModify},
        {"KsmKeyPredict", TestKsmKeyPredict},
        {"KsmKeyCountQueue", TestKsmKeyCountQueue},
/*        {"KsmKeyCountUnallocated", TestKsmKeyCountUnallocated},*/
        {"KsmKeyGetUnallocated", TestKsmKeyGetUnallocated},
        {"KsmDnssecKeyCreateOnPolicy", TestKsmDnssecKeyCreateOnPolicy},
        {NULL,                      NULL}
    };

    /* TODO 
     * have been a bit lazy here and reuse TdbSetup etc...
     * this has the consequence of all the setups running for each suite
     * if this gets too slow then we will need to separate them out
     * */
    return TcuCreateSuite("KsmKey", TdbSetup, TdbTeardown, tests);
}
