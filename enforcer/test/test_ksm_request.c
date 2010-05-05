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
 * Filename: test_ksm_parameter.c - Test Key Parameter Module
 *
 * Description:
 *      This is a short test module to check the functions in the Ksm Parameter
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

int l_keytype = -1;
int no_keys = 0;

/*
 * TestCallback Function 
 */
static int TestCallbackFn(void* context, KSM_KEYDATA* data)
{
    fprintf(stderr, "\n");
    fprintf(stderr, "\t\t\t<Key>\n");
    fprintf(stderr, "\t\t\t\t<Flags>%d</Flags>\n", data->keytype);
    fprintf(stderr, "\t\t\t\t<Algorithm>%d</Algorithm>\n", data->algorithm);
    fprintf(stderr, "\t\t\t\t<Locator>%s</Locator>\n", data->location);
    if (data->keytype == KSM_TYPE_KSK)
    {
        fprintf(stderr, "\t\t\t\t<KSK />\n");
    }
    else
    {
        fprintf(stderr, "\t\t\t\t<ZSK />\n");
    }
    fprintf(stderr, "\t\t\t\t<%s />\n", KsmKeywordStateValueToName(data->state));
    fprintf(stderr, "\t\t\t</Key>\n");
    fprintf(stderr, "\n");

	/*printf("%s %lu %d %d %s\n", KsmKeywordStateValueToName(data->state),
		data->keypair_id, data->keytype, data->algorithm, data->location); */

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
    int     zone_id = 1; /* opendnssec.org */
    int     newDS = 0;

    char*   datetime = DtParseDateTimeString("now");

    /* push a key into some state that update can operate on */
    status = KsmRequestChangeStateN( KSM_TYPE_ZSK, datetime, 1,
        KSM_STATE_GENERATE, KSM_STATE_PUBLISH, zone_id);

	/* Check that keys of a particular type can be requested */
    KsmRequestKeys(keytype, rollover, datetime, TestCallbackFn, NULL, 2, zone_id, 0, &newDS);

	/*CU_ASSERT_EQUAL(status, 1);*/ /* just make sure that something flags this as needing more work */
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
