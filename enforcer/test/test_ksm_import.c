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
 * Filename: test_ksm_import.c - Test ksm_import Module
 *
 * Description:
 *      This is a short test module to check the function in the Ksm Import
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
#include "ksm/db_fields.h"
#include "test_routines.h"


/*+
 * TestKsmImportRepository - Test
 *
 * Description:
 *      Tests that a) we can create a new repository, and
 *                 b) we can update an existing repository
-*/

static void TestKsmImportRepository(void)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    int         count = 0;      /* Do we already have a repository with this name? */

    char*       repo_name = "myNewRepo";
    char*       repo_capacity = "500";
    
    /* Show that the repository X doesn't exist */
    sql = DqsCountInit(DB_SECURITY_MODULE_TABLE);
    DqsConditionString(&sql, "NAME", DQS_COMPARE_EQ, repo_name, 0);
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), &count, sql);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(count, 0);

    /* Create X */
    status = KsmImportRepository(repo_name, repo_capacity, 0);
	CU_ASSERT_EQUAL(status, 0);

    /* Show that the repository X does now exist */
    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(count, 1);

    /* Get the capacity of X */
    sql = DqsSpecifyInit(DB_SECURITY_MODULE_TABLE,"capacity");
    DqsConditionString(&sql, "name", DQS_COMPARE_EQ, repo_name, 0);
    DqsEnd(&sql);
     
    status = DbIntQuery(DbHandle(), &count, sql);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(count, 500);

    /* update X */
    status = KsmImportRepository(repo_name, "5000", 0);
	CU_ASSERT_EQUAL(status, 0);

    /* Get the new capacity */
    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(count, 5000);


}

/*+
 * TestKsmImportPolicy - Test
 *
 * Description:
 *      Tests that we can create a new policy
-*/
static void TestKsmImportPolicy(void)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    int         count = 0;      /* Do we already have a repository with this name? */

    char*       policy_name = "myNewPolicy";
    char*       policy_desc = "Pretty policy";
    
    /* Show that the policy X doesn't exist */
    sql = DqsCountInit("policies");
    DqsConditionString(&sql, "NAME", DQS_COMPARE_EQ, policy_name, 0);
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), &count, sql);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(count, 0);

    /* Create X */
    status = KsmImportPolicy(policy_name, policy_desc);
	CU_ASSERT_EQUAL(status, 0);

    /* Show that the policy X does now exist */
    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(count, 1);
}

/*+
 * TestKsmImportZone - Test
 *
 * Description:
 *      Tests that a) we can create a new Zone, and
 *                 b) we can update an existing Zone
-*/

static void TestKsmImportZone(void)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    int         count = 0;      /* Do we already have a repository with this name? */

    char*       zone_name = "myNewZone.test";
    int         policy_id = 1;
    int         new_zone = 0;
    
    /* Show that the Zone X doesn't exist */
    sql = DqsCountInit(DB_ZONE_TABLE);
    DqsConditionString(&sql, "NAME", DQS_COMPARE_EQ, zone_name, 0);
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), &count, sql);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(count, 0);

    /* Create X */
    status = KsmImportZone(zone_name, policy_id, 1, &new_zone);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(new_zone, 1);

    /* Show that the Zone X does now exist */
    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(count, 1);

    /* Get the policy of X */
    sql = DqsSpecifyInit(DB_ZONE_TABLE,"policy_id");
    DqsConditionString(&sql, "name", DQS_COMPARE_EQ, zone_name, 0);
    DqsEnd(&sql);
     
    status = DbIntQuery(DbHandle(), &count, sql);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(count, 1);

    /* update X */
    status = KsmImportZone(zone_name, 2, 0, &new_zone);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(new_zone, 0);

    /* Get the new policy */
    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(count, 2);


}

/*+
 * TestKsmSerialIdFromName - Test
 *
 * Description:
 *      Tests that a serial id can be returned
-*/

static void TestKsmSerialIdFromName(void)
{
	int		status;		/* Status return */
    int     serial_id;    /* returned id */

    char*   serial1 = "unixtime";
    char*   serial2 = "somethingElse";

    /* get the first repo */
    status = KsmSerialIdFromName(serial1, &serial_id);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(serial_id, 1);

    /* get the second repo */
    status = KsmSerialIdFromName(serial2, &serial_id);
	CU_ASSERT_EQUAL(status, 65557); /* doesn't exist */

}

/*
 * TestKsmImport - Create Test Suite
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

int TestKsmImport(void);	/* Declaration */
int TestKsmImport(void)
{
    struct test_testdef tests[] = {
        {"KsmImportRepository", TestKsmImportRepository},
        {"KsmImportPolicy", TestKsmImportPolicy},
        {"KsmImportZone", TestKsmImportZone},
        {"KsmSerialIdFromName", TestKsmSerialIdFromName},
        {NULL,                      NULL}
    };

    /* TODO 
     * have been a bit lazy here and reuse TdbSetup etc...
     * this has the consequence of all the setups running for each suite
     * if this gets too slow then we will need to separate them out
     * */
    return TcuCreateSuite("KsmImport", TdbSetup, TdbTeardown, tests);
}
