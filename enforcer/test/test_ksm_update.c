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
 * Filename: test_ksm_update.c - Test Key update Module
 *
 * Description:
 *      This is a short test module to check the functions in the Ksm update
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
#include "ksm/datetime.h"
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
        KSM_STATE_GENERATE, KSM_STATE_PUBLISH, zone_id);

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
