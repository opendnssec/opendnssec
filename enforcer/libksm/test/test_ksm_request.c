/*+
 * Filename: test_ksm_parameter.c - Test Key Parameter Module
 *
 * Description:
 *      This is a short test module to check the functions in the Ksm Parameter
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
#include "datetime.h"
#include "test_routines.h"

int l_keytype = -1;
int no_keys = 0;

/*
 * TestCallback Function 
 */
static int TestCallbackFn(void* context, KSM_KEYDATA* data)
{
	printf("%s %lu %d %d %s\n", KsmKeywordStateValueToName(data->state),
		data->keypair_id, data->keytype, data->algorithm, data->location);

    no_keys++;

	return 0;
}


/*+
 * TestKsmRequestKeys - Test Request code
 *
 * Description:
 *      Tests that a parameter can be set
-*/

static void TestKsmRequestKeys(void)
{
    int     keytype = 0; /*KSM_TYPE_ZSK;*/       /* Type of key */
    int     rollover = 0;       /* Set 1 to roll over the current key */
	int		status = 0;

    char*   datetime = DtParseDateTimeString("now");

    /* push a key into some state that update can operate on */
    status = KsmRequestChangeStateN( KSM_TYPE_ZSK, datetime, 1,
        KSM_STATE_GENERATE, KSM_STATE_PUBLISH);

	/* Check that keys of a particular type can be requested */
    KsmRequestKeys(keytype, rollover, datetime, TestCallbackFn, NULL, 2, 1);

	CU_ASSERT_EQUAL(status, 1); /* just make sure that something flags this as needing more work */
	CU_ASSERT_EQUAL(no_keys, 1);
    
	/* TODO work out some test scenarios here and use Callback to check */
}

/*
 * TestKsmRequest - Create Test Suite
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

int TestKsmRequest(void);	/* Declaration */
int TestKsmRequest(void)
{
    struct test_testdef tests[] = {
        {"KsmRequest", TestKsmRequestKeys},
        {NULL,                      NULL}
    };

    /* TODO 
     * have been a bit lazy here and reuse TdbSetup etc...
     * this has the consequence of all the setups running for each suite
     * if this gets too slow then we will need to separate them out
     * */
    return TcuCreateSuite("KsmRequest", TdbSetup, TdbTeardown, tests);
}
