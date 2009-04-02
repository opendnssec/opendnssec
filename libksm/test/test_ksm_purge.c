/*+
 * Filename: test_ksm_purge.c - Test Key Purge Module
 *
 * Description:
 *      This is a short test module to check the function in the Ksm Purge
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
 * TestKsmPurgeInternal - Test Key Purge code
 *
 * Description:
 *      Tests that all dead keys are removed when requested
-*/

static void TestKsmPurgeInternal(void)
{
    int			rowcount;	/* Number of rows returned */
	char*		sql;		/* Constructed query */
	char*		sql2;		/* Constructed query */
	int			status;		/* Status return */
	int			where = 0;	/* WHERE clause count */

	/* Check that only one key is "dead" (STATE=6) */

	sql = DqsCountInit("keypairs");
	DqsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, 6, where++);
	DqsEnd(&sql);
	status = DbIntQuery(DbHandle(), &rowcount, sql);

	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(rowcount, 1);

    /* With 2 entries in dnsseckeys */
    where = 0;
	sql2 = DqsCountInit("dnsseckeys");
	DqsConditionInt(&sql2, "keypair_id", DQS_COMPARE_EQ, 1, where++);
	DqsEnd(&sql2);
	status = DbIntQuery(DbHandle(), &rowcount, sql2);

	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(rowcount, 2);


    /* Call KsmPurge */
    KsmPurge();

    /* Now make sure that we have no dead keys */
	status = DbIntQuery(DbHandle(), &rowcount, sql);
	DqsFree(sql);

	CU_ASSERT_EQUAL(status, 0);

	CU_ASSERT_EQUAL(rowcount, 0);

    /* Make sure that the entries in dnsseckeys have gone too */
    status = DbIntQuery(DbHandle(), &rowcount, sql2);
	DqsFree(sql2);

	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(rowcount, 0);

}

/*
 * TestKsmPurge - Create Test Suite
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

int TestKsmPurge(void);	/* Declaration */
int TestKsmPurge(void)
{
    struct test_testdef tests[] = {
        {"KsmPurge", TestKsmPurgeInternal},
        {NULL,                      NULL}
    };

    /* TODO 
     * have been a bit lazy here and reuse TdbSetup etc...
     * this has the consequence of all the setups running for each suite
     * if this gets too slow then we will need to separate them out
     * */
    return TcuCreateSuite("KsmPurge", TdbSetup, TdbTeardown, tests);
}
