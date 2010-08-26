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
 * test_database.c - Test Database Functions
 *
 * Description:
 * 		Tests the various database functions.
 *
 * 		There are no separate tests for connection and disconnection; of
 * 		necessity, the tests must connect to the database in order to run.
 *
 * 		N.B.  The various environment variables to control database access must
 * 		be set before running this code - see "test_routines_database" for
 * 		details.
-*/

#include <stdlib.h>

#include "CUnit/Basic.h"

#include "ksm/database.h"
#include "ksm/database_statement.h"
#include "test_routines.h"


/*+
 * TestDbExecuteSql - Check Execution of SQL
 *
 * Description:
 * 		Executes an SQL statement but does not attempt to do anything else.
 * 		This just checks that the basic connection and execution is OK.
-*/

static void TestDbExecuteSql(void)
{
	DB_RESULT	result;		/* Result object */
	char*		sql;		/* Constructed query */
	int			status;		/* Status return */

	sql = DqsCountInit("TEST_BASIC");
	DqsEnd(&sql);
	status = DbExecuteSql(DbHandle(), sql, &result);
	CU_ASSERT_EQUAL(status, 0);
	DqsFree(sql);

	DbFreeResult(result);

	return;
}


/*+
 * TestDatabaseAccess - Check Functions in database_access.c
 *
 * Description:
 * 		Executes an SQL query statement and accesses the result.  This
 * 		checks more or less all the functions in database_access.c
-*/

static void TestDatabaseAccess(void)
{
	DB_RESULT	result;		/* Result object */
	DB_ROW		row;		/* Row object */
	char*		sql;		/* Constructed query */
	int			status;		/* Status return */
	char*		string;		/* String from the row */

	sql = DqsInit("TEST_BASIC");
	DqsOrderBy(&sql, "SVALUE");
	DqsEnd(&sql);
	status = DbExecuteSql(DbHandle(), sql, &result);
	CU_ASSERT_EQUAL(status, 0);
	DqsFree(sql);

	/*
	 * Fetch each row and check the SVALUE field:
	 *
	 * The first fetch checks that the function copes with a NULL field.
	 */

	status = DbFetchRow(result, &row);
	CU_ASSERT_EQUAL(status, 0);
	status = DbString(row, 2, &string);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_PTR_NULL(string);
	DbFreeRow(row);

	/* Second row */

	status = DbFetchRow(result, &row);
	CU_ASSERT_EQUAL(status, 0);
	status = DbString(row, 2, &string);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_STRING_EQUAL(string, "ABC");
	DbStringFree(string);
	DbFreeRow(row);

	/* Last row */

	status = DbFetchRow(result, &row);
	CU_ASSERT_EQUAL(status, 0);
	status = DbString(row, 2, &string);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_STRING_EQUAL(string, "DEF");
	DbStringFree(string);
	DbFreeRow(row);

	/* Fetch again should indicate end of file */

	status = DbFetchRow(result, &row);
	CU_ASSERT_EQUAL(status, -1);
	/* TODO put back
       CU_ASSERT_PTR_NULL(row); */

	/* Free up the result set */

	DbFreeResult(result);

	return;
}


/*+
 * TestDbExecuteSqlNoResult
 *
 * Description:
 * 		Tests the named function by adding a row to the table, and checking
 * 		that the insertion succeeded.
-*/

static void TestDbExecuteSqlNoResult(void)
{
	int			rowcount;	/* Number of rows returned */
	char*		sql;		/* Constructed query */
	int			status;		/* Status return */
	int			where = 0;	/* WHERE clause count */

	sql = DisInit("TEST_BASIC");
	DisAppendInt(&sql, 400);
	DisAppendString(&sql, "GHI");
	DisAppendString(&sql, NULL);
	DisEnd(&sql);
	status = DbExecuteSqlNoResult(DbHandle(), sql);
	CU_ASSERT_EQUAL(status, 0);
	DisFree(sql);

	/* Check that our row got into the table */

	sql = DqsCountInit("TEST_BASIC");
	DqsConditionInt(&sql, "IVALUE", DQS_COMPARE_EQ, 400, where++);
	DqsEnd(&sql);
	status = DbIntQuery(DbHandle(), &rowcount, sql);
	CU_ASSERT_EQUAL(status, 0);
	DqsFree(sql);

	CU_ASSERT_EQUAL(rowcount, 1);

	return;
}


/*+
 * TestDbIntQuery - Check Integer Query
 *
 * Description:
 * 		Extracts a row from the database and extracts an integer field from it.
 * 		This test also checks DbInt().
-*/

static void TestDbIntQuery(void)
{
	int			rowcount;	/* Number of rows returned */
	char*		sql;		/* Constructed query */
	int			status;		/* Status return */
	int			where = 0;	/* WHERE clause count */

	/* Check that only one row has IVALUE = 200 */

	sql = DqsCountInit("TEST_BASIC");
	DqsConditionInt(&sql, "IVALUE", DQS_COMPARE_EQ, 200, where++);
	DqsEnd(&sql);
	status = DbIntQuery(DbHandle(), &rowcount, sql);
	DqsFree(sql);

	CU_ASSERT_EQUAL(status, 0);

	CU_ASSERT_EQUAL(rowcount, 1);

	return;
}


/*+
 * TestDbStringBuffer
 *
 * Description:
 * 		Tests DbStringBuffer by getting a known value into a user buffer.
-*/

static void TestDbStringBuffer(void)
{
	char		buffer[128]; /* User buffer */
	DB_RESULT	result;		/* Result object */
	DB_ROW		row;		/* Row object */
	char*		sql;		/* Constructed query */
	int			status;		/* Status return */
	int			where = 0;	/* WHERE clause index */

	sql = DqsInit("TEST_BASIC");
	DqsConditionString(&sql, "SVALUE", DQS_COMPARE_EQ, "ABC", where++);
	DqsEnd(&sql);
	status = DbExecuteSql(DbHandle(), sql, &result);
	CU_ASSERT_EQUAL(status, 0);
	DqsFree(sql);

	/* Fetch the only row and get the value from the SVALUE field */

	status = DbFetchRow(result, &row);
	CU_ASSERT_EQUAL(status, 0);
	status = DbStringBuffer(row, 2, buffer, sizeof(buffer));
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_STRING_EQUAL(buffer, "ABC");
	DbFreeRow(row);

    /* Fetch again should indicate end of file */

	status = DbFetchRow(result, &row);
	CU_ASSERT_EQUAL(status, -1);
	/* TODO put back
	CU_ASSERT_PTR_NULL(row); */
    
	/* Tidy up */

	DbFreeResult(result);

	return;
}


/*+
 * TestDbLastRowId - Check last Row ID
 *
 * Description:
 * 		Inserts two rows and checks that the row IDs differ by one.  Doing the
 * 		test this way does not assume anything about what is currently in the
 * 		database.
-*/

static void TestDbLastRowId(void)
{
	DB_ID	first_id = 0;	/* ID of first insertion */
	DB_ID	second_id = 0;	/* ID of second insertion */
	char*	sql = NULL;		/* SQL statement */
	int		status;			/* Status return */

	/* Construct the insertion statement */

	sql = DisInit("TEST_BASIC");
	CU_ASSERT_PTR_NOT_NULL(sql);

	DisAppendInt(&sql, 500);
	DisAppendString(&sql, "XYZZY");
	DisAppendString(&sql, "20090101");
	DisEnd(&sql);

	/* Insert and store row IDs */

	status = DbExecuteSqlNoResult(DbHandle(), sql);
	CU_ASSERT_EQUAL(status, 0);

	status = DbLastRowId(DbHandle(), &first_id);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_NOT_EQUAL(first_id, 0);

	status = DbExecuteSqlNoResult(DbHandle(), sql);
	CU_ASSERT_EQUAL(status, 0);

	status = DbLastRowId(DbHandle(), &second_id);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(second_id, (first_id + 1));

	/* ... and tidy up */

	DisFree(sql);

	return;

}
	
static void TestDbCommit(void)
{
	int			rowcount;	/* Number of rows returned */
	char*		sql;		/* Constructed query */
	int			status;		/* Status return */
	int			where = 0;	/* WHERE clause count */

    status = DbBeginTransaction();
	CU_ASSERT_EQUAL(status, 0);

	sql = DisInit("TEST_BASIC");
	DisAppendInt(&sql, 600);
	DisAppendString(&sql, "JKL");
	DisAppendString(&sql, NULL);
	DisEnd(&sql);
	status = DbExecuteSqlNoResult(DbHandle(), sql);
	CU_ASSERT_EQUAL(status, 0);
	DisFree(sql);

    status = DbCommit();
	CU_ASSERT_EQUAL(status, 0);

	/* Check that our row got into the table */

	sql = DqsCountInit("TEST_BASIC");
	DqsConditionInt(&sql, "IVALUE", DQS_COMPARE_EQ, 600, where++);
	DqsEnd(&sql);
	status = DbIntQuery(DbHandle(), &rowcount, sql);
	CU_ASSERT_EQUAL(status, 0);
	DqsFree(sql);

	CU_ASSERT_EQUAL(rowcount, 1);

	return;
}

static void TestDbRollback(void)
{
	int			rowcount;	/* Number of rows returned */
	char*		sql;		/* Constructed query */
	int			status;		/* Status return */
	int			where = 0;	/* WHERE clause count */

    status = DbBeginTransaction();
	CU_ASSERT_EQUAL(status, 0);

	sql = DisInit("TEST_BASIC");
	DisAppendInt(&sql, 700);
	DisAppendString(&sql, "MNO");
	DisAppendString(&sql, NULL);
	DisEnd(&sql);
	status = DbExecuteSqlNoResult(DbHandle(), sql);
	CU_ASSERT_EQUAL(status, 0);
	DisFree(sql);

	/* Check that our row got into the table */
	sql = DqsCountInit("TEST_BASIC");
	DqsConditionInt(&sql, "IVALUE", DQS_COMPARE_EQ, 700, where++);
	DqsEnd(&sql);
	status = DbIntQuery(DbHandle(), &rowcount, sql);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(rowcount, 1);

    /* Do the rollback */
    status = DbRollback();
	CU_ASSERT_EQUAL(status, 0);

	/* Check that our row has now gone */
	status = DbIntQuery(DbHandle(), &rowcount, sql);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(rowcount, 0);
	DqsFree(sql);

	return;
}


/*+
 * TestDdb  - Create Test Suite
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

int TestDb(void);	/* Declaration */
int TestDb(void)
{
    struct test_testdef tests[] = {
        {"TestDbExecuteSql",			TestDbExecuteSql},
        {"TestDatabaseAccess",			TestDatabaseAccess},
        {"TestDbExecuteSqlNoResult",	TestDbExecuteSqlNoResult},
        {"TestDbIntQuery",				TestDbIntQuery},
        {"TestDbStringBuffer",			TestDbStringBuffer},
        {"TestDbLastRowId",				TestDbLastRowId},
        {"TestDbCommit",				TestDbCommit},
        {"TestDbRollback",				TestDbRollback},
        {NULL,                  		NULL}
    };

    return TcuCreateSuite("Db", TdbSetup, TdbTeardown, tests);
}
