/*+
 * Filename: test_ksm_policy.c - Test Key Purge Module
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
 * TestKsmPolicyRead - Test
 *
 * Description:
 *      Tests that a polcy can be returned
-*/

static void TestKsmPolicyRead(void)
{
	int			status;		/* Status return */
	KSM_POLICY*     	policy;
	policy = (KSM_POLICY *)malloc(sizeof(KSM_POLICY));
	policy->signer = (KSM_SIGNER_POLICY *)malloc(sizeof(KSM_SIGNER_POLICY));
	policy->signature = (KSM_SIGNATURE_POLICY *)malloc(sizeof(KSM_SIGNATURE_POLICY));
	policy->ksk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
	policy->zsk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
	policy->denial = (KSM_DENIAL_POLICY *)malloc(sizeof(KSM_DENIAL_POLICY));
	policy->enforcer = (KSM_ENFORCER_POLICY *)malloc(sizeof(KSM_ENFORCER_POLICY));

	policy->name = "default";

	/* Call KsmPolicyRead */

	status = KsmPolicyRead(policy);

	CU_ASSERT_EQUAL(status, 0);

	/* Call KsmPolicyRead again */

	status = KsmPolicyRead(policy);

	CU_ASSERT_EQUAL(status, 0);

	free(policy->enforcer);
	free(policy->denial);
	free(policy->zsk);
	free(policy->ksk);
	free(policy->signature);
	free(policy->signer);
	free(policy);
}

static void TestKsmPolicy2(void)
{
	DB_RESULT result;
	DB_HANDLE		 dbhandle;
	int status = 0;
	int i;
	KSM_POLICY *policy;
	policy = (KSM_POLICY *)malloc(sizeof(KSM_POLICY));
	policy->signer = (KSM_SIGNER_POLICY *)malloc(sizeof(KSM_SIGNER_POLICY));
	policy->signature = (KSM_SIGNATURE_POLICY *)malloc(sizeof(KSM_SIGNATURE_POLICY));
	policy->ksk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
	policy->zsk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
	policy->denial = (KSM_DENIAL_POLICY *)malloc(sizeof(KSM_DENIAL_POLICY));
	policy->enforcer = (KSM_ENFORCER_POLICY *)malloc(sizeof(KSM_ENFORCER_POLICY));
	policy->name = (char *)calloc(KSM_NAME_LENGTH, sizeof(char));


	for (i=1; i<5 ; i++) {
		printf("Try: %i\n",i);
		/* Read all policies */
		status = KsmPolicyInit(&result, NULL);
		if (status == 0) {
			/* get the first policy */
			status = KsmPolicy(result, policy);
			while (status == 0) {

				/* get next policy */
				status = KsmPolicy(result, policy);
			}
		}

		DbFreeResult(result);

	}
	;
	free(policy->name);
	free(policy->enforcer);
	free(policy->denial);
	free(policy->zsk);
	free(policy->ksk);
	free(policy->signature);
	free(policy->signer);
	free(policy);
}

/*
 * TestKsmPolicy - Create Test Suite
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

int TestKsmPolicy(void);	/* Declaration */
int TestKsmPolicy(void)
{
    struct test_testdef tests[] = {
        {"KsmPolicy", TestKsmPolicyRead},
        {"KsmPolicy2", TestKsmPolicy2},
        {NULL,                      NULL}
    };

    /* TODO 
     * have been a bit lazy here and reuse TdbSetup etc...
     * this has the consequence of all the setups running for each suite
     * if this gets too slow then we will need to separate them out
     * */
    return TcuCreateSuite("KsmPolicy", TdbSetup, TdbTeardown, tests);
}
