/*+
 * Filename: test_ksm_zone.c - Test ksm_zone Module
 *
 * Description:
 *      This is a short test module to check the function in the Ksm Zone
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
 * TestKsmZoneRead - Test
 *
 * Description:
 *      Tests that a zone can be returned
-*/

static void TestKsmZoneRead(void)
{
	int			status;		/* Status return */
	int         policy_id = 2;
    DB_RESULT   result;
	KSM_ZONE*   zone;

	zone = (KSM_ZONE *)malloc(sizeof(KSM_ZONE));
    zone->name = (char *)calloc(KSM_NAME_LENGTH, sizeof(char));

	/* Call KsmZoneInit */
    status = KsmZoneInit(&result, policy_id);
	CU_ASSERT_EQUAL(status, 0);

    /* get the first zone */
    status = KsmZone(result, zone);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_STRING_EQUAL(zone->name, "opendnssec.org");

    /* get the second zone */
    status = KsmZone(result, zone);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_STRING_EQUAL(zone->name, "opendnssec.se");

	free(zone->name);
	free(zone);
}

/*
 * TestKsmZone - Create Test Suite
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

int TestKsmZone(void);	/* Declaration */
int TestKsmZone(void)
{
    struct test_testdef tests[] = {
        {"KsmZone", TestKsmZoneRead},
        {NULL,                      NULL}
    };

    /* TODO 
     * have been a bit lazy here and reuse TdbSetup etc...
     * this has the consequence of all the setups running for each suite
     * if this gets too slow then we will need to separate them out
     * */
    return TcuCreateSuite("KsmZone", TdbSetup, TdbTeardown, tests);
}
