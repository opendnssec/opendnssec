/*+
 * test_routines_cunit.c
 *
 * Description:
 *      This module contains some shells around the CUnit routines.
 *
 *      The module is not included in libcommon.a, so avoiding the need to
 *      include libcunit.a into any code using the library; it must be included
 *      separately in the link command line.
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

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "CUnit/Automated.h"
#include "CUnit/Basic.h"
#include "CUnit/Console.h"
#include "CUnit/CUCurses.h"

#include "test_routines.h"

/*+
 * TcuInitialize - Initialize CUnit Wrapper
 *
 * Description:
 *      Initializes the CUnit registry.  If the initialization fails, the
 *      program terminates.
 *
 *      This should be called after TestInitialize().
 *
 * Arguments:
 *      None.
 */

void TcuInitialize(void)
{
    if (CU_initialize_registry() != CUE_SUCCESS) {
        fprintf(stderr, "Failed to initialize the CUnit registry.\n");
        exit(1);
    }

    return;
}



/*
 * Tcu - Execute Tests
 *
 * Description:
 *      Executes the tests and cleans up the registry afterwards.
 *
 * Arguments:
 *      None.
 */

void TcuExecute(void)
{
    if (TestGetAutomatic()) {
        if (TestGetFilename()) {
            CU_set_output_filename(TestGetFilename());
        }
        CU_automated_run_tests();
    }
    else if (TestGetBasic()) {
        CU_basic_set_mode(CU_BRM_VERBOSE);
        (void) CU_basic_run_tests();
    }
    else if (TestGetConsole()) {
        CU_console_run_tests();
    }
    else if (TestGetCurses()) {
        CU_curses_run_tests();
    }
    else if (TestGetList()) {
        if (TestGetFilename()) {
            CU_set_output_filename(TestGetFilename());
        }
        (void) CU_list_tests_to_file();
    }

    /* Clean up the registry */

    CU_cleanup_registry();
}


    
/*
 * TcuCreateSuite - Create Suite of Tests
 *
 * Description:
 *      Creates a suite of tests.  This handles the common actions in all test
 *      suite creation routines.
 *
 * Arguments:
 *      const char* title (input)
 *          Title for the suite.
 *
 *      int (*init)() (input)
 *          Pointer to the initialization routine.  This may be NULL if there is
 *          no initialization routine for the suite.
 *
 *      int (*teardown)() (input)
 *          Pointer to the teardown routine.  This may be NULL if there is no
 *          teardown routine for the suite.
 *
 *      struct test_testdef* tests (input)
 *          Pointer to an array of test definitions structures defining the
 *          tests. This array should end with a pair of NULLs.
 *
 * Returns:
 *      int
 *          0   => Success
 *          <>0 => CUnit error code
 */

int TcuCreateSuite(const char* title, int (*init)(), int (*teardown)(),
    struct test_testdef* tests)
{
    int i;                  /* Loop counter */
	CU_pSuite pSuite;		/* Pointer to the test suite */

    /* Create the suite */

    pSuite = CU_add_suite(title, init, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* Add the tests to the suite */

    i = 0;
    while (tests[i].title) {
        if (CU_add_test(pSuite, tests[i].title, tests[i].function) == NULL) {
            CU_cleanup_registry();
            return CU_get_error();
        }
        ++i;
    }

    return 0;
}
