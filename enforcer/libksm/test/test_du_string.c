/*+
 * Filename: test_dd_string.c - Test dd_string
 *
 * Description:
 *      This is a short test module to check the functions in the code that
 *      constructs a DELETE statement.
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
