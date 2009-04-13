/*+
 * Filename: test_ksm_update.c - Test Key update Module
 *
 * Description:
 *      This is a short test module to check the functions in the Ksm update
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
 * TestKsmUpdateInternal - Test Update code
 *
 * Description:
 *      Tests that keys times can be updated
-*/

static void TestKsmUpdateInternal(void)
{
	int			status;		/* Status return */
    int         policy_id = 2;
    int         zone_id = 1;
    DB_ID       dnsseckey_id;   /* Created key ID */
    char*   datetime = DtParseDateTimeString("now");

    /* Create a new dnsseckeys entry (use our previously tested routines) 
     * keys 3 - 15 are unallocated */

    status = KsmDnssecKeyCreate(zone_id, 3, KSM_TYPE_ZSK, &dnsseckey_id);
	CU_ASSERT_EQUAL(status, 0);

	/* push a key into some state that update can operate on */
    status = KsmRequestChangeStateN( KSM_TYPE_ZSK, datetime, 1,
        KSM_STATE_GENERATE, KSM_STATE_PUBLISH);

    CU_ASSERT_EQUAL(status, 0);

	/* Check that the call works? We get no feedback */
    status = KsmUpdate(policy_id, zone_id);
	CU_ASSERT_EQUAL(status, 0); /* not that it can be anything else */

    /* TODO check the keys have updated */
}

/*
 * TestKsmUpdate - Create Test Suite
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

int TestKsmUpdate(void);	/* Declaration */
int TestKsmUpdate(void)
{
    struct test_testdef tests[] = {
        {"KsmUpdate", TestKsmUpdateInternal},
        {NULL,                      NULL}
    };

    /* TODO 
     * have been a bit lazy here and reuse TdbSetup etc...
     * this has the consequence of all the setups running for each suite
     * if this gets too slow then we will need to separate them out
     * */
    return TcuCreateSuite("KsmUpdate", TdbSetup, TdbTeardown, tests);
}
