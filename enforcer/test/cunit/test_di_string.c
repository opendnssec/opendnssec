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
 * Filename: test_di_string.c - Test di_string
 *
 * Description:
 *      This is a short test module to check the functions in the code that
 *      constructs an INSERT statement.
 *      
 *      The test program makes use of the CUnit framework, as described in
 *      http://cunit.sourceforge.net
-*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "CUnit/Basic.h"

#include "ksm/database_statement.h"
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
