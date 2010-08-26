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
 * test_routines_cunit.c
 *
 * Description:
 *      This module contains some shells around the CUnit routines.
 *
 *      The module is not included in libcommon.a, so avoiding the need to
 *      include libcunit.a into any code using the library; it must be included
 *      separately in the link command line.
-*/

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "CUnit/Automated.h"
#include "CUnit/Basic.h"
#include "CUnit/Console.h"

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
