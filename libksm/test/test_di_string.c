/*+
 * Filename: test_di_string.c - Test di_string
 *
 * Description:
 *      This is a short test module to check the functions in the code that
 *      constructs an INSERT statement.
 *      
 *      The test program makes use of the CUnit framework, as described in
 *      http://cunit.sourceforge.net
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
 * TestDisCreate - Test Dis Routines
 *
 * Description:
 *      Constructs a database INSERT statement and checks the string so
 *      constructed.
-*/

static void TestDisCreate(void)
{
	char*	sql = NULL;

	static const char* TEST =
		"INSERT INTO TEST VALUES (NULL, 1, 'ALPHA', NULL)";

	sql = DisInit("TEST");
	DisAppendInt(&sql, 1);
	DisAppendString(&sql, "ALPHA");
	DisAppendString(&sql, NULL);
	DisEnd(&sql);

	CU_ASSERT_STRING_EQUAL(sql, TEST);
	DisFree(sql);

	return;
}


/*+
 * TestDis  - Create Test Suite
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

int TestDis(void);	/* Declaration */
int TestDis(void)
{
    struct test_testdef tests[] = {
        {"TestDisCreate",			TestDisCreate},
        {NULL,                      NULL}
    };

    return TcuCreateSuite("Dis", NULL, NULL, tests);
}
