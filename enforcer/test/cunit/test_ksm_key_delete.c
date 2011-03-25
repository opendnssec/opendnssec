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
 * Filename: test_ksm_key_delete.c - Test Key Delete Module
 *
 * Description:
 *      This is a short test module to check the functions in the Ksm Key Delete
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
	DqsFree(sql);

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
	DqsFree(sql);

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
	DqsFree(sql);
	CU_ASSERT_EQUAL(status, 0);

	CU_ASSERT_EQUAL(rowcount, 4);

    where = 0;
	sql = DqsCountInit("KEYDATA_VIEW");
	DqsConditionInt(&sql, "ID", DQS_COMPARE_EQ, 11, where++);
	DqsEnd(&sql);
    status = DbIntQuery(DbHandle(), &rowcount, sql);
	DqsFree(sql);
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
