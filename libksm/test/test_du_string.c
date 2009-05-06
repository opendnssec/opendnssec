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
 * TestDusSetInt - Test Basic Dus SET With Integer
 *
 * Description:
 *      Constructs a database UPDATE statement setting an integer attribute and
 *      checks the string so constructed.
-*/

static void TestDusSetInt(void)
{
	char*	sql = NULL;
	int		set = 0;

	/* Check a single integer update */

	set = 0;
	sql = DusInit("TEST");
	DusSetInt(&sql, "ALPHA", 1, set++);
	DusEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, "UPDATE TEST SET ALPHA = 1");
	DusFree(sql);

	/* Check multiple updates */

	set = 0;
	sql = DusInit("TEST");
	DusSetInt(&sql, "ALPHA", 1, set++);
	DusSetInt(&sql, "BETA",  2, set++);
	DusEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, "UPDATE TEST SET ALPHA = 1, BETA = 2");
	DusFree(sql);

	return;
}



/*+
 * TestDusSetString - Test Basic Dus SET With String
 *
 * Description:
 *      Constructs a database UPDATE statement setting  a string attribute and
 *      checks the string so constructed.
-*/

static void TestDusSetString(void)
{
	char*	sql = NULL;
	int		set = 0;

	/* Check a single string update */

	set = 0;
	sql = DusInit("TEST");
	DusSetString(&sql, "ALPHA", "XYZZY", set++);
	DusEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, "UPDATE TEST SET ALPHA = \"XYZZY\"");
	DusFree(sql);

	/* Check a single string update of a NULL value */

	set = 0;
	sql = DusInit("TEST");
	DusSetString(&sql, "BETA", NULL, set++);
	DusEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, "UPDATE TEST SET BETA = NULL");
	DusFree(sql);

	/* Check a combination */

	set = 0;
	sql = DusInit("TEST");
	DusSetString(&sql, "ALPHA", "XYZZY", set++);
	DusSetString(&sql, "BETA", NULL, set++);
	DusEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql,
		"UPDATE TEST SET ALPHA = \"XYZZY\", BETA = NULL");
	DusFree(sql);

	return;
}

/*+
 * TestDusConditionInt - Test Conditional
 *
 * Description:
 * 		Checks that the deletion can be constrained by a WHERE clause comparing
 * 		fields to integers.
-*/

static void TestDusConditionInt(void)
{
	char*	sql = NULL;
	int		set = 0;
	int		where = 0;
	static const char* TEST = 
		"UPDATE TEST SET ALPHA = 0 WHERE ALPHA < 1 AND BETA <= 2 AND GAMMA = 3 "
		"AND DELTA != 4 AND EPSILON >= 5 AND ZETA > 6";

	sql = DusInit("TEST");
	DusSetInt(&sql, "ALPHA", 0, set++);
	DusConditionInt(&sql, "ALPHA", DQS_COMPARE_LT, 1, where++);
	DusConditionInt(&sql, "BETA", DQS_COMPARE_LE, 2, where++);
	DusConditionInt(&sql, "GAMMA", DQS_COMPARE_EQ, 3, where++);
	DusConditionInt(&sql, "DELTA", DQS_COMPARE_NE, 4, where++);
	DusConditionInt(&sql, "EPSILON", DQS_COMPARE_GE, 5, where++);
	DusConditionInt(&sql, "ZETA", DQS_COMPARE_GT, 6, where++);
	DusEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, TEST);
	DusFree(sql);

	return;
}

/*+
 * TestDusConditionString - Test Conditional
 *
 * Description:
 * 		Checks that the deletion can be constrained by a WHERE clause comparing
 * 		fields to strings.
-*/

static void TestDusConditionString(void)
{
	char*	sql = NULL;
	int		set = 0;
	int		where = 0;
	static const char* TEST = 
		"UPDATE TEST SET ALPHA = 0 "
		"WHERE ALPHA < \"PETER\" AND BETA <= \"PIPER\" "
		"AND GAMMA = \"PICKED\" AND DELTA != \"A\" AND EPSILON >= \"PECK\" "
		"AND ZETA > \"OF\"";

	sql = DusInit("TEST");
	DusSetInt(&sql, "ALPHA", 0, set++);
	DusConditionString(&sql, "ALPHA", DQS_COMPARE_LT, "PETER", where++);
	DusConditionString(&sql, "BETA", DQS_COMPARE_LE, "PIPER", where++);
	DusConditionString(&sql, "GAMMA", DQS_COMPARE_EQ, "PICKED", where++);
	DusConditionString(&sql, "DELTA", DQS_COMPARE_NE, "A", where++);
	DusConditionString(&sql, "EPSILON", DQS_COMPARE_GE, "PECK", where++);
	DusConditionString(&sql, "ZETA", DQS_COMPARE_GT, "OF", where++);
	DusEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, TEST);
	DusFree(sql);

	return;
}

/*+
 * TestDusConditionKeyword - Test Conditional
 *
 * Description:
 * 		Checks that the deletion can be constrained by a WHERE clause comprising
 * 		an IN clause.
-*/


static void TestDusConditionKeyword(void)
{
	char*	sql = NULL;
	int		set = 0;
	int		where = 0;
	static const char* TEST = 
		"UPDATE TEST SET ALPHA = 0, BETA = \"GIMMEL\" WHERE ALPHA IN (1, 2, 3) "
		"AND BETA IN (\"ALEPH\", \"BETH\")";

	sql = DusInit("TEST");
	DusSetInt(&sql, "ALPHA", 0, set++);
	DusSetString(&sql, "BETA", "GIMMEL", set++);
	DusConditionKeyword(&sql, "ALPHA", DQS_COMPARE_IN, "(1, 2, 3)", where++);
	DusConditionKeyword(&sql, "BETA", DQS_COMPARE_IN, "(\"ALEPH\", \"BETH\")",
		where++);
	DusEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, TEST);
	DusFree(sql);

	return;
}


/*+
 * TestDus  - Create Test Suite
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

int TestDus(void);	/* Declaration */
int TestDus(void)
{
    struct test_testdef tests[] = {
        {"TestDusSetInt",			TestDusSetInt},
        {"TestDusSetString",		TestDusSetString},
        {"TestDusConditionInt",		TestDusConditionInt},
        {"TestDusConditionString",	TestDusConditionString},
        {"TestDusConditionKeyword",	TestDusConditionKeyword},
        {NULL,                      NULL}
    };

    return TcuCreateSuite("Dus", NULL, NULL, tests);
}
