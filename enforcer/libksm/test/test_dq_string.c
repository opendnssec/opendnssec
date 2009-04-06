/*+
 * Filename: test_dq_string.c - Test dq_string
 *
 * Description:
 *      This is a short test module to check the functions in the code that
 *      constructs a SELECT statement.
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
 * TestDqsBasic - Test Basic Dqs Routines
 *
 * Description:
 *      Constructs a database DELETE statement and checks the string so
 *      constructed.
-*/

static void TestDqsBasic(void)
{
	char*	sql = NULL;

	sql = DqsInit("TEST");
	DqsEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, "SELECT * FROM TEST");
	DqsFree(sql);

	sql = DqsCountInit("TEST");
	DqsEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, "SELECT COUNT(*) FROM TEST");
	DqsFree(sql);

	return;
}

/*+
 * TestDqsConditionInt - Test Conditional
 *
 * Description:
 * 		Checks that the deletion can be constrained by a WHERE clause comparing
 * 		fields to integers.
-*/

static void TestDqsConditionInt(void)
{
	char*	sql = NULL;
	int		clause = 0;

	sql = DqsCountInit("TEST");
	DqsConditionInt(&sql, "ALPHA", DQS_COMPARE_LT, 1, clause++);
	DqsConditionInt(&sql, "BETA", DQS_COMPARE_LE, 2, clause++);
	DqsConditionInt(&sql, "GAMMA", DQS_COMPARE_EQ, 3, clause++);
	DqsConditionInt(&sql, "DELTA", DQS_COMPARE_NE, 4, clause++);
	DqsConditionInt(&sql, "EPSILON", DQS_COMPARE_GE, 5, clause++);
	DqsConditionInt(&sql, "ZETA", DQS_COMPARE_GT, 6, clause++);
	DqsEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql,
		"SELECT COUNT(*) FROM TEST WHERE ALPHA < 1 AND BETA <= 2 AND GAMMA = 3 "
		"AND DELTA != 4 AND EPSILON >= 5 AND ZETA > 6");
	DqsFree(sql);

	return;
}

/*+
 * TestDqsConditionString - Test Conditional
 *
 * Description:
 * 		Checks that the deletion can be constrained by a WHERE clause comparing
 * 		fields to strings.
-*/

static void TestDqsConditionString(void)
{
	char*	sql = NULL;
	int		clause = 0;
	static const char* TEST = 
		"SELECT * FROM TEST WHERE ALPHA < \"PETER\" AND BETA <= \"PIPER\" "
		"AND GAMMA = \"PICKED\" AND DELTA != \"A\" AND EPSILON >= \"PECK\" "
		"AND ZETA > \"OF\"";

	sql = DqsInit("TEST");
	DqsConditionString(&sql, "ALPHA", DQS_COMPARE_LT, "PETER", clause++);
	DqsConditionString(&sql, "BETA", DQS_COMPARE_LE, "PIPER", clause++);
	DqsConditionString(&sql, "GAMMA", DQS_COMPARE_EQ, "PICKED", clause++);
	DqsConditionString(&sql, "DELTA", DQS_COMPARE_NE, "A", clause++);
	DqsConditionString(&sql, "EPSILON", DQS_COMPARE_GE, "PECK", clause++);
	DqsConditionString(&sql, "ZETA", DQS_COMPARE_GT, "OF", clause++);
	DqsEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, TEST);
	DqsFree(sql);

	return;
}

/*+
 * TestDqsConditionKeyword - Test Conditional
 *
 * Description:
 * 		Checks that the deletion can be constrained by a WHERE clause comprising
 * 		an IN clause.
-*/


static void TestDqsConditionKeyword(void)
{
	char*	sql = NULL;
	int		clause = 0;
	static const char* TEST = 
		"SELECT * FROM TEST WHERE ALPHA IN (1, 2, 3) "
		"AND BETA IN (\"ALEPH\", \"BETH\")";

	sql = DqsInit("TEST");
	DqsConditionKeyword(&sql, "ALPHA", DQS_COMPARE_IN, "(1, 2, 3)", clause++);
	DqsConditionKeyword(&sql, "BETA", DQS_COMPARE_IN, "(\"ALEPH\", \"BETH\")",
		clause++);
	DqsEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, TEST);
	DqsFree(sql);

	return;
}

/*+
 * TestDqsOrderBy - Test ORDER BY Clause
 *
 * Description:
 * 		Checks that the deletion can be constrained by a WHERE clause comprising
 * 		an IN clause.
-*/


static void TestDqsOrderBy(void)
{
	char*	sql = NULL;
	int		clause = 0;
	static const char* TEST = 
		"SELECT * FROM TEST WHERE ALPHA IN (1, 2, 3) ORDER BY BETA";

	sql = DqsInit("TEST");
	DqsConditionKeyword(&sql, "ALPHA", DQS_COMPARE_IN, "(1, 2, 3)", clause++);
	DqsOrderBy(&sql, "BETA");
	DqsEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, TEST);
	DqsFree(sql);

	return;
}


/*+
 * TestDqs  - Create Test Suite
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

int TestDqs(void);	/* Declaration */
int TestDqs(void)
{
    struct test_testdef tests[] = {
        {"TestDqsBasic",			TestDqsBasic},
        {"TestDqsConditionInt",		TestDqsConditionInt},
        {"TestDqsConditionString",	TestDqsConditionString},
        {"TestDqsConditionKeyword",	TestDqsConditionKeyword},
        {"TestDqsOrderBy",			TestDqsOrderBy},
        {NULL,                      NULL}
    };

    return TcuCreateSuite("Dqs", NULL, NULL, tests);
}
