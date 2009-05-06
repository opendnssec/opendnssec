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
 * Filename: test_dd_string.c - Test dd_string
 *
 * Description:
 *      This is a short test module to check the functions in the code that
 *      constructs a DELETE statement.
 *      
 *      The test program makes use of the CUnit framework, as described in
 *      http://cunit.sourceforge.net
-*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "CUnit/Basic.h"

#include "database_statement.h"
#include "test_routines.h"



/*+
 * TestDdsBasic - Test Basic Dds Routines
 *
 * Description:
 *      Constructs a database DELETE statement and checks the string so
 *      constructed.
-*/

static void TestDdsBasic(void)
{
	char*	sql = NULL;

	sql = DdsInit("TEST");
	DdsEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, "DELETE FROM TEST");
	DdsFree(sql);

	return;
}

/*+
 * TestDdsConditionInt - Test Conditional
 *
 * Description:
 * 		Checks that the deletion can be constrained by a WHERE clause comparing
 * 		fields to integers.
-*/

static void TestDdsConditionInt(void)
{
	char*	sql = NULL;
	int		clause = 0;

	sql = DdsInit("TEST");
	DdsConditionInt(&sql, "ALPHA", DQS_COMPARE_LT, 1, clause++);
	DdsConditionInt(&sql, "BETA", DQS_COMPARE_LE, 2, clause++);
	DdsConditionInt(&sql, "GAMMA", DQS_COMPARE_EQ, 3, clause++);
	DdsConditionInt(&sql, "DELTA", DQS_COMPARE_NE, 4, clause++);
	DdsConditionInt(&sql, "EPSILON", DQS_COMPARE_GE, 5, clause++);
	DdsConditionInt(&sql, "ZETA", DQS_COMPARE_GT, 6, clause++);
	DdsEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql,
		"DELETE FROM TEST WHERE ALPHA < 1 AND BETA <= 2 AND GAMMA = 3 "
		"AND DELTA != 4 AND EPSILON >= 5 AND ZETA > 6");
	DdsFree(sql);

	return;
}

/*+
 * TestDdsConditionString - Test Conditional
 *
 * Description:
 * 		Checks that the deletion can be constrained by a WHERE clause comparing
 * 		fields to strings.
-*/

static void TestDdsConditionString(void)
{
	char*	sql = NULL;
	int		clause = 0;
	static const char* TEST = 
		"DELETE FROM TEST WHERE ALPHA < \"PETER\" AND BETA <= \"PIPER\" "
		"AND GAMMA = \"PICKED\" AND DELTA != \"A\" AND EPSILON >= \"PECK\" "
		"AND ZETA > \"OF\"";

	sql = DdsInit("TEST");
	DdsConditionString(&sql, "ALPHA", DQS_COMPARE_LT, "PETER", clause++);
	DdsConditionString(&sql, "BETA", DQS_COMPARE_LE, "PIPER", clause++);
	DdsConditionString(&sql, "GAMMA", DQS_COMPARE_EQ, "PICKED", clause++);
	DdsConditionString(&sql, "DELTA", DQS_COMPARE_NE, "A", clause++);
	DdsConditionString(&sql, "EPSILON", DQS_COMPARE_GE, "PECK", clause++);
	DdsConditionString(&sql, "ZETA", DQS_COMPARE_GT, "OF", clause++);
	DdsEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, TEST);
	DdsFree(sql);

	return;
}

/*+
 * TestDdsConditionKeyword - Test Conditional
 *
 * Description:
 * 		Checks that the deletion can be constrained by a WHERE clause comprising
 * 		an IN clause.
-*/


static void TestDdsConditionKeyword(void)
{
	char*	sql = NULL;
	int		clause = 0;
	static const char* TEST = 
		"DELETE FROM TEST WHERE ALPHA IN (1, 2, 3) "
		"AND BETA IN (\"ALEPH\", \"BETH\")";

	sql = DdsInit("TEST");
	DdsConditionKeyword(&sql, "ALPHA", DQS_COMPARE_IN, "(1, 2, 3)", clause++);
	DdsConditionKeyword(&sql, "BETA", DQS_COMPARE_IN, "(\"ALEPH\", \"BETH\")",
		clause++);
	DdsEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, TEST);
	DdsFree(sql);

	return;
}


/*+
 * TestDds  - Create Test Suite
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

int TestDds(void);	/* Declaration */
int TestDds(void)
{
    struct test_testdef tests[] = {
        {"TestDdsBasic",			TestDdsBasic},
        {"TestDdsConditionInt",		TestDdsConditionInt},
        {"TestDdsConditionString",	TestDdsConditionString},
        {"TestDdsConditionKeyword",	TestDdsConditionKeyword},
        {NULL,                      NULL}
    };

    return TcuCreateSuite("Dds", NULL, NULL, tests);
}
