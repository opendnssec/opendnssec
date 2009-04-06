/*+
 * Filename: test_ksm_key.c - Test Key Module
 *
 * Description:
 *      This is a short test module to check the function in the Ksm Key
 *      module.
 *
 *      The test program makes use of the CUnit framework, as described in
 *      http://cunit.sourceforge.net
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "CUnit/Basic.h"

#include "ksm.h"
#include "db_fields.h"
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
    char*   generate = "2009-01-01";

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
        {NULL,                      NULL}
    };

    /* TODO 
     * have been a bit lazy here and reuse TdbSetup etc...
     * this has the consequence of all the setups running for each suite
     * if this gets too slow then we will need to separate them out
     * */
    return TcuCreateSuite("KsmKey", TdbSetup, TdbTeardown, tests);
}
