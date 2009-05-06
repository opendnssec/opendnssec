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

#include "ksm.h"
#include "db_fields.h"
#include "test_routines.h"


/*+
 * TestKsmParameterSet - Test Parameter Set code
 *
 * Description:
 *      Tests that a parameter can be set
-*/

static void TestKsmParameterSet(void)
{
	char*		sql;		/* Constructed query */
	int			status;		/* Status return */
	int			where = 0;	/* WHERE clause count */
	char		buffer[2];  /* User buffer */
	DB_RESULT	result;		/* Result object */
	DB_ROW		row;		/* Row object */

	/* Check that a genuine parameter can be set (for the first time) */
    status = KsmParameterSet("Blah","Test", 2, 2);
	CU_ASSERT_EQUAL(status, 0);

	sql = DqsSpecifyInit("PARAMETER_VIEW", DB_PARAMETER_VIEW_FIELDS);
	DqsConditionString(&sql, "NAME", DQS_COMPARE_EQ, "Blah", where++);
	DqsConditionString(&sql, "CATEGORY", DQS_COMPARE_EQ, "Test", where++);
	DqsEnd(&sql);
	status = DbExecuteSql(DbHandle(), sql, &result);
	CU_ASSERT_EQUAL(status, 0);
	DqsFree(sql);

    status = DbFetchRow(result, &row);
	CU_ASSERT_EQUAL(status, 0);
	status = DbStringBuffer(row, DB_PARAMETER_VALUE, buffer, sizeof(buffer));
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_STRING_EQUAL(buffer, "2");

	DbFreeRow(row);
	DbFreeResult(result);

    /* Check that an existing parameter can be overwritten */
    status = KsmParameterSet("Blah2", "Test", 2, 2);
	CU_ASSERT_EQUAL(status, 0);

    where = 0;
	sql = DqsSpecifyInit("PARAMETER_VIEW", DB_PARAMETER_VIEW_FIELDS);
	DqsConditionString(&sql, "NAME", DQS_COMPARE_EQ, "Blah2", where++);
	DqsConditionString(&sql, "CATEGORY", DQS_COMPARE_EQ, "Test", where++);
	DqsEnd(&sql);
	status = DbExecuteSql(DbHandle(), sql, &result);
	CU_ASSERT_EQUAL(status, 0);
	DqsFree(sql);

    status = DbFetchRow(result, &row);
	CU_ASSERT_EQUAL(status, 0);
	status = DbStringBuffer(row, DB_PARAMETER_VALUE, buffer, sizeof(buffer));
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_STRING_EQUAL(buffer, "2");

    /* Check that a non-existing parameter can not be */ 
    status = KsmParameterSet("Blah3", "Test", 2, 2);
	CU_ASSERT_EQUAL(status, 65548);	/* Parameter doesn't exist */

	DbFreeRow(row);
	DbFreeResult(result);
}

/*+
 * TestKsmParameterShow - Test Parameter Show code
 *
 * Description:
 *      Tests that a parameter can be shown
-*/

static void TestKsmParameterShow(void)
{
	int			status;		/* Status return */

	/* 
     * Check that an existing parameter can be shown
     * not sure how useful this is as a test
     */
    status = KsmParameterShow("Blah", "Test", 2);
	CU_ASSERT_EQUAL(status, 0);

}

/*
 * TestKsmParameter - Create Test Suite
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

int TestKsmParameter(void);	/* Declaration */
int TestKsmParameter(void)
{
    struct test_testdef tests[] = {
        {"KsmParameterSet", TestKsmParameterSet},
        {"KsmParameterShow", TestKsmParameterShow},
        {NULL,                      NULL}
    };

    /* TODO 
     * have been a bit lazy here and reuse TdbSetup etc...
     * this has the consequence of all the setups running for each suite
     * if this gets too slow then we will need to separate them out
     * */
    return TcuCreateSuite("KsmParameter", TdbSetup, TdbTeardown, tests);
}
