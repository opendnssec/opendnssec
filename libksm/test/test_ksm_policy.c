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
 * Filename: test_ksm_policy.c - Test Key Purge Module
 *
 * Description:
 *      This is a short test module to check the function in the Ksm Purge
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
    policy->zone = (KSM_ZONE_POLICY *)malloc(sizeof(KSM_ZONE_POLICY));
    policy->parent = (KSM_PARENT_POLICY *)malloc(sizeof(KSM_PARENT_POLICY));
    policy->keys = (KSM_COMMON_KEY_POLICY *)malloc(sizeof(KSM_COMMON_KEY_POLICY));
	policy->ksk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
	policy->zsk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
	policy->denial = (KSM_DENIAL_POLICY *)malloc(sizeof(KSM_DENIAL_POLICY));
	policy->enforcer = (KSM_ENFORCER_POLICY *)malloc(sizeof(KSM_ENFORCER_POLICY));
    policy->description = (char *)calloc(KSM_POLICY_DESC_LENGTH, sizeof(char));

	policy->name = "default";

	/* Call KsmPolicyRead */

	status = KsmPolicyRead(policy);

	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(policy->id, 2);

	/* Call KsmPolicyRead again */

	status = KsmPolicyRead(policy);

	CU_ASSERT_EQUAL(status, 0);

    free(policy->description);
	free(policy->enforcer);
	free(policy->denial);
	free(policy->keys);
	free(policy->zsk);
	free(policy->ksk);
    free(policy->zone);
    free(policy->parent);
	free(policy->signature);
	free(policy->signer);
	free(policy);
}

static void TestKsmPolicyReadId(void)
{
	int			status;		/* Status return */
	KSM_POLICY*     	policy;
	policy = (KSM_POLICY *)malloc(sizeof(KSM_POLICY));
	policy->signer = (KSM_SIGNER_POLICY *)malloc(sizeof(KSM_SIGNER_POLICY));
	policy->signature = (KSM_SIGNATURE_POLICY *)malloc(sizeof(KSM_SIGNATURE_POLICY));
    policy->zone = (KSM_ZONE_POLICY *)malloc(sizeof(KSM_ZONE_POLICY));
    policy->parent = (KSM_PARENT_POLICY *)malloc(sizeof(KSM_PARENT_POLICY));
    policy->keys = (KSM_COMMON_KEY_POLICY *)malloc(sizeof(KSM_COMMON_KEY_POLICY));
	policy->ksk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
	policy->zsk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
	policy->denial = (KSM_DENIAL_POLICY *)malloc(sizeof(KSM_DENIAL_POLICY));
	policy->enforcer = (KSM_ENFORCER_POLICY *)malloc(sizeof(KSM_ENFORCER_POLICY));
    policy->description = (char *)calloc(KSM_POLICY_DESC_LENGTH, sizeof(char));
	policy->name = (char *)calloc(KSM_NAME_LENGTH, sizeof(char));


	policy->id = 2;

	/* Call KsmPolicyReadFromId */

	status = KsmPolicyReadFromId(policy);

	CU_ASSERT_EQUAL(status, 0);

	/* Call KsmPolicyRead again */

	status = KsmPolicyReadFromId(policy);

	CU_ASSERT_EQUAL(status, 0);

    free(policy->description);
	free(policy->name);
	free(policy->enforcer);
	free(policy->denial);
	free(policy->keys);
	free(policy->zsk);
	free(policy->ksk);
    free(policy->zone);
    free(policy->parent);
	free(policy->signature);
	free(policy->signer);
	free(policy);
}

static void TestKsmPolicy2(void)
{
	DB_RESULT result;
	int status = 0;
	int i;
	KSM_POLICY *policy;
	policy = (KSM_POLICY *)malloc(sizeof(KSM_POLICY));
	policy->signer = (KSM_SIGNER_POLICY *)malloc(sizeof(KSM_SIGNER_POLICY));
	policy->signature = (KSM_SIGNATURE_POLICY *)malloc(sizeof(KSM_SIGNATURE_POLICY));
    policy->zone = (KSM_ZONE_POLICY *)malloc(sizeof(KSM_ZONE_POLICY));
    policy->parent = (KSM_PARENT_POLICY *)malloc(sizeof(KSM_PARENT_POLICY));
    policy->keys = (KSM_COMMON_KEY_POLICY *)malloc(sizeof(KSM_COMMON_KEY_POLICY));
	policy->ksk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
	policy->zsk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
	policy->denial = (KSM_DENIAL_POLICY *)malloc(sizeof(KSM_DENIAL_POLICY));
	policy->enforcer = (KSM_ENFORCER_POLICY *)malloc(sizeof(KSM_ENFORCER_POLICY));
    policy->description = (char *)calloc(KSM_POLICY_DESC_LENGTH, sizeof(char));
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
    free(policy->description);
	free(policy->name);
	free(policy->enforcer);
	free(policy->denial);
	free(policy->keys);
	free(policy->zsk);
	free(policy->ksk);
    free(policy->zone);
    free(policy->parent);
	free(policy->signature);
	free(policy->signer);
	free(policy);
}

/*+
 * TestKsmPolicySalt - Test
 *
 * Description:
 *      Tests that salt can be updated and returned
-*/

static void TestKsmPolicySalt(void)
{
	int			status;		/* Status return */
	KSM_POLICY*     	policy;
	policy = (KSM_POLICY *)malloc(sizeof(KSM_POLICY));
	policy->signer = (KSM_SIGNER_POLICY *)malloc(sizeof(KSM_SIGNER_POLICY));
	policy->signature = (KSM_SIGNATURE_POLICY *)malloc(sizeof(KSM_SIGNATURE_POLICY));
    policy->zone = (KSM_ZONE_POLICY *)malloc(sizeof(KSM_ZONE_POLICY));
    policy->parent = (KSM_PARENT_POLICY *)malloc(sizeof(KSM_PARENT_POLICY));
    policy->keys = (KSM_COMMON_KEY_POLICY *)malloc(sizeof(KSM_COMMON_KEY_POLICY));
	policy->ksk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
	policy->zsk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
	policy->denial = (KSM_DENIAL_POLICY *)malloc(sizeof(KSM_DENIAL_POLICY));
	policy->enforcer = (KSM_ENFORCER_POLICY *)malloc(sizeof(KSM_ENFORCER_POLICY));
    policy->description = (char *)calloc(KSM_POLICY_DESC_LENGTH, sizeof(char));

	policy->name = "default";
	policy->id = 2;

	/* Do the salt/resalt */

	status = KsmPolicyUpdateSalt(policy, NULL);

	CU_ASSERT_EQUAL(status, 0);

    free(policy->description);
	free(policy->enforcer);
	free(policy->denial);
	free(policy->keys);
	free(policy->zsk);
	free(policy->ksk);
    free(policy->zone);
    free(policy->parent);
	free(policy->signature);
	free(policy->signer);
	free(policy);

    DbCommit();
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
        {"KsmPolicyFromId", TestKsmPolicyReadId}, 
        {"KsmPolicy2", TestKsmPolicy2},
        {"KsmPolicySalt", TestKsmPolicySalt},
        {NULL,                      NULL}
    };

    /* TODO 
     * have been a bit lazy here and reuse TdbSetup etc...
     * this has the consequence of all the setups running for each suite
     * if this gets too slow then we will need to separate them out
     * */
    return TcuCreateSuite("KsmPolicy", TdbSetup, TdbTeardown, tests);
}
