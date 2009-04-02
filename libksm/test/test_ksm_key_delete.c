/*+
 * Filename: test_ksm_key_delete.c - Test Key Delete Module
 *
 * Description:
 *      This is a short test module to check the functions in the Ksm Key Delete
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
#include "test_routines.h"


/*+
 * TestKsmKeyDeleteRange - Test KsmDeleteKeyRange code
 *
 * Description:
 *      Tests that a key range can be deleted
-*/

static void TestKsmKeyDeleteRange(void)
{
	char*		sql;		/* Constructed query */
	int			status;		/* Status return */
	int			where = 0;	/* WHERE clause count */
	int	        rowcount;	/* Result */

    /* First check that the rows exist */
	sql = DqsCountInit("KEYDATA_VIEW");
	DqsConditionInt(&sql, "ID", DQS_COMPARE_GT, 2, where++);
	DqsConditionInt(&sql, "ID", DQS_COMPARE_LT, 5, where++);
	DqsEnd(&sql);
    status = DbIntQuery(DbHandle(), &rowcount, sql);
	CU_ASSERT_EQUAL(status, 0);

	CU_ASSERT_EQUAL(rowcount, 2);

	/* Delete some */
    status = KsmDeleteKeyRange(3, 4);
	CU_ASSERT_EQUAL(status, 0);

    /* Make sure that they have gone */
    status = DbIntQuery(DbHandle(), &rowcount, sql);
	CU_ASSERT_EQUAL(status, 0);
	DqsFree(sql);

	CU_ASSERT_EQUAL(rowcount, 0);

    /* Check that no other keys were harmed */
    where = 0;
	sql = DqsCountInit("KEYDATA_VIEW");
	DqsConditionInt(&sql, "ID", DQS_COMPARE_GE, 1, where++);
	DqsConditionInt(&sql, "ID", DQS_COMPARE_LE, 7, where++);
	DqsEnd(&sql);
    status = DbIntQuery(DbHandle(), &rowcount, sql);
	CU_ASSERT_EQUAL(status, 0);

	/* 6 expected because key 1 has 2 instances */
	CU_ASSERT_EQUAL(rowcount, 6);

    /* 
     * Start again, this time we will put min and max in the "wrong" way round
     * First check that the rows exist 
     */
    where = 0;
	sql = DqsCountInit("KEYDATA_VIEW");
	DqsConditionInt(&sql, "ID", DQS_COMPARE_GT, 4, where++);
	DqsConditionInt(&sql, "ID", DQS_COMPARE_LT, 7, where++);
	DqsEnd(&sql);
    status = DbIntQuery(DbHandle(), &rowcount, sql);
	CU_ASSERT_EQUAL(status, 0);

	CU_ASSERT_EQUAL(rowcount, 2);

	/* Delete some */
    status = KsmDeleteKeyRange(6, 5);
	CU_ASSERT_EQUAL(status, 0);

    /* Make sure that they have gone */
    status = DbIntQuery(DbHandle(), &rowcount, sql);
	CU_ASSERT_EQUAL(status, 0);
	DqsFree(sql);

	CU_ASSERT_EQUAL(rowcount, 0);

    /* Check that no other keys were harmed */
    where = 0;
	sql = DqsCountInit("KEYDATA_VIEW");
	DqsConditionInt(&sql, "ID", DQS_COMPARE_GE, 1, where++);
	DqsConditionInt(&sql, "ID", DQS_COMPARE_LE, 7, where++);
	DqsEnd(&sql);
    status = DbIntQuery(DbHandle(), &rowcount, sql);
	CU_ASSERT_EQUAL(status, 0);

	/* 4 expected because key 1 has 2 instances */
	CU_ASSERT_EQUAL(rowcount, 4);
}

/*+
 * TestKsmKeyDeleteRanges - Test KsmDeleteKeyRanges code
 *
 * Description:
 *      Tests that key ranges can be deleted
-*/

static void TestKsmKeyDeleteRanges(void)
{
	char*		sql;		/* Constructed query */
	int			status;		/* Status return */
	int			where = 0;	/* WHERE clause count */
	int	        rowcount;	/* Result */
	int	        limit[4];	/* ranges to delete */
	int	        size;	    /* size of limit vector */

    /* First check that the rows exist */
	sql = DqsCountInit("KEYDATA_VIEW");
	DqsConditionInt(&sql, "ID", DQS_COMPARE_GT, 8, where++);
	DqsConditionInt(&sql, "ID", DQS_COMPARE_LT, 14, where++);
	DqsEnd(&sql);
    status = DbIntQuery(DbHandle(), &rowcount, sql);
	CU_ASSERT_EQUAL(status, 0);

	CU_ASSERT_EQUAL(rowcount, 5);

	/* Delete some */
    limit[0] = 9;
    limit[1] = 10;
    limit[2] = 13;
    limit[3] = 12;
    size = 4;
    status = KsmDeleteKeyRanges(limit, size);
	CU_ASSERT_EQUAL(status, 0);

    /* Make sure that they have gone */
    status = DbIntQuery(DbHandle(), &rowcount, sql);
	CU_ASSERT_EQUAL(status, 0);
	DqsFree(sql);

	CU_ASSERT_EQUAL(rowcount, 1);

    /* Check that no other keys were harmed */
    where = 0;
	sql = DqsCountInit("KEYDATA_VIEW");
	DqsConditionInt(&sql, "ID", DQS_COMPARE_GE, 8, where++);
	DqsConditionInt(&sql, "ID", DQS_COMPARE_LE, 15, where++);
	DqsEnd(&sql);
    status = DbIntQuery(DbHandle(), &rowcount, sql);
	CU_ASSERT_EQUAL(status, 0);

	CU_ASSERT_EQUAL(rowcount, 4);

    where = 0;
	sql = DqsCountInit("KEYDATA_VIEW");
	DqsConditionInt(&sql, "ID", DQS_COMPARE_EQ, 11, where++);
	DqsEnd(&sql);
    status = DbIntQuery(DbHandle(), &rowcount, sql);
	CU_ASSERT_EQUAL(status, 0);

	CU_ASSERT_EQUAL(rowcount, 1);

    /* TODO what happens if the limit vector is not set? */
}

/*
 * TestKsmKeyDelete - Create Test Suite
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

int TestKsmKeyDelete(void);	/* Declaration */
int TestKsmKeyDelete(void)
{
    struct test_testdef tests[] = {
        {"KsmKeyDeleteRange", TestKsmKeyDeleteRange},
        {"KsmKeyDeleteRanges", TestKsmKeyDeleteRanges}, 
        {NULL,                      NULL}
    };

    /* TODO 
     * have been a bit lazy here and reuse TdbSetup etc...
     * this has the consequence of all the setups running for each suite
     * if this gets too slow then we will need to separate them out
     * */
    return TcuCreateSuite("KsmKeyDelete", TdbSetup, TdbTeardown, tests);
}
