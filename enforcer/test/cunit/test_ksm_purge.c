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
 * Filename: test_ksm_purge.c - Test Key Purge Module
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
	char*		sql3;		/* Constructed query */
	int			status;		/* Status return */
	int			where = 0;	/* WHERE clause count */

	/* Check that only one key is "dead" (STATE=6) */

	sql = DqsCountInit("dnsseckeys");
	DqsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, 6, where++);
    StrAppend(&sql, " group by id");
	DqsEnd(&sql);
	status = DbIntQuery(DbHandle(), &rowcount, sql);
	DqsFree(sql);

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
    sql3 = DqsCountInit("dnsseckeys");
	DqsConditionInt(&sql3, "STATE", DQS_COMPARE_EQ, 6, 0);
	status = DbIntQuery(DbHandle(), &rowcount, sql3);
	DqsFree(sql3);

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
