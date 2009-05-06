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
 * Filename: test_string_util2.c
 *
 * Description:
 *      This module holds the unit tests for the functions in the string_util2.c
 *      module.
 *
 *      The test program makes use of the CUnit framework, as described in
 *      http://cunit.sourceforge.net
-*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "CUnit/Basic.h"

#include "memory.h"
#include "string_util.h"
#include "string_util2.h"
#include "test_routines.h"




/*
 * TestStrAppend - Test StrAppend
 *
 * Description:
 *      Tests the dynamic string append function.
-*/

static void TestStrAppend()
{
    char*   result;

    /* Check that the code doesn't fall over if passed a null target */

    StrAppend(NULL, NULL);
    StrAppend(NULL, "something");

    /* Check the result of trying to append a null string */

    result = NULL;
    StrAppend(&result, NULL);
    CU_ASSERT_PTR_NULL(result);

    /* Now appending to a null string */

    StrAppend(&result, "xyzzy");
    CU_ASSERT_STRING_EQUAL(result, "xyzzy");

    /* Now append to a fixed string */

    result = StrStrdup("xyzzy");
    StrAppend(&result, NULL);
    CU_ASSERT_STRING_EQUAL(result, "xyzzy");
    StrAppend(&result, "");
    CU_ASSERT_STRING_EQUAL(result, "xyzzy");
    StrAppend(&result, "plugh");
    CU_ASSERT_STRING_EQUAL(result, "xyzzyplugh");

    /* ... and check that we can append to an empty string */

    StrFree(result);
    result = StrStrdup("");
    StrAppend(&result, "xyzzy");
    CU_ASSERT_STRING_EQUAL(result, "xyzzy");
    StrFree(result);
}



/*+
 * TestArglistAddFree - Test Arglist Add and Free
 *
 * Description:
 *      Test the addition of elements to the argument list.
-*/

static void TestStrArglistAddFree()
{
    char** argv = NULL;

    /* Add the first string */

    StrArglistAdd(&argv, "alpha");
    CU_ASSERT_PTR_NOT_NULL(argv);
    CU_ASSERT_PTR_NOT_NULL(argv[0]);
    CU_ASSERT_PTR_NULL(argv[1]);
    CU_ASSERT_STRING_EQUAL(argv[0], "alpha");

    /* ...a second */

    StrArglistAdd(&argv, "beta");
    CU_ASSERT_PTR_NOT_NULL(argv);
    CU_ASSERT_PTR_NOT_NULL(argv[0]);
    CU_ASSERT_PTR_NOT_NULL(argv[1]);
    CU_ASSERT_PTR_NULL(argv[2]);
    CU_ASSERT_STRING_EQUAL(argv[0], "alpha");
    CU_ASSERT_STRING_EQUAL(argv[1], "beta");

    /* ... and a third */

    StrArglistAdd(&argv, "gamma");
    CU_ASSERT_PTR_NOT_NULL(argv);
    CU_ASSERT_PTR_NOT_NULL(argv[0]);
    CU_ASSERT_PTR_NOT_NULL(argv[1]);
    CU_ASSERT_PTR_NOT_NULL(argv[2]);
    CU_ASSERT_PTR_NULL(argv[3]);
    CU_ASSERT_STRING_EQUAL(argv[0], "alpha");
    CU_ASSERT_STRING_EQUAL(argv[1], "beta");
    CU_ASSERT_STRING_EQUAL(argv[2], "gamma");

    /* Free up the data */

    StrArglistFree(&argv);
    CU_ASSERT_PTR_NULL(argv);

    return;
}


/*+
 * TestStrArglistCreate - Check Argument List Creation
 */

static void TestStrArglistCreate()
{
    char**  argv;

    /* Check with the corner cases - null and empty strings first */

    argv = NULL;
    argv = StrArglistCreate(NULL);
    CU_ASSERT_PTR_NOT_NULL(argv);
    CU_ASSERT_PTR_NULL(argv[0]);
    StrArglistFree(&argv);
    CU_ASSERT_PTR_NULL(argv);

    argv = StrArglistCreate("       ");
    CU_ASSERT_PTR_NOT_NULL(argv);
    CU_ASSERT_PTR_NULL(argv[0]);
    StrArglistFree(&argv);
    CU_ASSERT_PTR_NULL(argv);

    argv = StrArglistCreate("   \n\t    ");
    CU_ASSERT_PTR_NOT_NULL(argv);
    CU_ASSERT_PTR_NULL(argv[0]);
    StrArglistFree(&argv);
    CU_ASSERT_PTR_NULL(argv);

    /* Now check with command lines */

    argv= StrArglistCreate(" list zone -f -c co.uk  ");
    CU_ASSERT_PTR_NOT_NULL(argv);
    CU_ASSERT_PTR_NOT_NULL(argv[0]);
    CU_ASSERT_STRING_EQUAL(argv[0], "list");
    CU_ASSERT_PTR_NOT_NULL(argv[1]);
    CU_ASSERT_STRING_EQUAL(argv[1], "zone");
    CU_ASSERT_PTR_NOT_NULL(argv[2]);
    CU_ASSERT_STRING_EQUAL(argv[2], "-f");
    CU_ASSERT_PTR_NOT_NULL(argv[3]);
    CU_ASSERT_STRING_EQUAL(argv[3], "-c");
    CU_ASSERT_PTR_NOT_NULL(argv[4]);
    CU_ASSERT_STRING_EQUAL(argv[4], "co.uk");
    CU_ASSERT_PTR_NULL(argv[5]);
    StrArglistFree(&argv);
    CU_ASSERT_PTR_NULL(argv);

    argv= StrArglistCreate("add signature -z co.uk\t-d alpha.dat\tfred");
    CU_ASSERT_PTR_NOT_NULL(argv);
    CU_ASSERT_PTR_NOT_NULL(argv[0]);
    CU_ASSERT_STRING_EQUAL(argv[0], "add");
    CU_ASSERT_PTR_NOT_NULL(argv[1]);
    CU_ASSERT_STRING_EQUAL(argv[1], "signature");
    CU_ASSERT_PTR_NOT_NULL(argv[2]);
    CU_ASSERT_STRING_EQUAL(argv[2], "-z");
    CU_ASSERT_PTR_NOT_NULL(argv[3]);
    CU_ASSERT_STRING_EQUAL(argv[3], "co.uk");
    CU_ASSERT_PTR_NOT_NULL(argv[4]);
    CU_ASSERT_STRING_EQUAL(argv[4], "-d");
    CU_ASSERT_PTR_NOT_NULL(argv[5]);
    CU_ASSERT_STRING_EQUAL(argv[5], "alpha.dat");
    CU_ASSERT_PTR_NOT_NULL(argv[6]);
    CU_ASSERT_STRING_EQUAL(argv[6], "fred");
    CU_ASSERT_PTR_NULL(argv[7]);
    StrArglistFree(&argv);
    CU_ASSERT_PTR_NULL(argv);
}


/*+
 * TestStrKeywordSearch - Test Keyword Search Function
-*/

static void TestStrKeywordSearch()
{
    STR_KEYWORD_ELEMENT keywords[] = {
        {"alpha",   5},
        {"alpine", 10},
        {"beta",   15},
        {"gamma",  20}
    };
    int status;     /* Status return */
    int value;      /* Return value */

    status = StrKeywordSearch("alpha", keywords, &value);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(value, 5);

    status = StrKeywordSearch("beta", keywords, &value);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(value, 15);

    status = StrKeywordSearch("alp", keywords, &value);
    CU_ASSERT_EQUAL(status, -2);

    status = StrKeywordSearch("xyz", keywords, &value);
    CU_ASSERT_EQUAL(status, -1);

    status = StrKeywordSearch("", keywords, &value);
    CU_ASSERT_EQUAL(status, -2);

    status = StrKeywordSearch(NULL, keywords, &value);
    CU_ASSERT_EQUAL(status, -1);

    return;
}

/*+
 * TestStrStrtol - Test String to Long Conversion
-*/

static void TestStrStrtol()
{
    int     status;
    long    value;

    status = StrStrtol("23", &value);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(value, 23L);

    status = StrStrtol(" 34 ", &value);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(value, 34L);

    status = StrStrtol("56\t", &value);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(value, 56L);

    status = StrStrtol("\t-67\t", &value);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(value, -67L);

    status = StrStrtol(" 7 8 ", &value);
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = StrStrtol(" 7a ", &value);
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = StrStrtol("  ", &value);
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = StrStrtol(NULL, &value);
    CU_ASSERT_NOT_EQUAL(status, 0);

    return;
}



/*+
 * TestStrStrtoul - Test String to Unsigned Long Conversion
-*/

static void TestStrStrtoul()
{
    int     		status;
    unsigned long	value;
	union {						/* For testing the reading of signed values */
		long			slong;
		unsigned long	ulong;
		} combined;

    status = StrStrtoul("23", &value);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(value, 23L);

    status = StrStrtoul(" 34 ", &value);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(value, 34L);

    status = StrStrtoul("56\t", &value);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(value, 56L);

    status = StrStrtoul("\t-1\t", &value);
    CU_ASSERT_EQUAL(status, 0);
	combined.ulong = value;
	CU_ASSERT_EQUAL(combined.slong, -1);

    status = StrStrtoul("\t-277983\t", &value);
    CU_ASSERT_EQUAL(status, 0);
	combined.ulong = value;
	CU_ASSERT_EQUAL(combined.slong, -277983);

    status = StrStrtoul(" 7 8 ", &value);
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = StrStrtoul(" 7a ", &value);
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = StrStrtoul("  ", &value);
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = StrStrtoul(NULL, &value);
    CU_ASSERT_NOT_EQUAL(status, 0);

    return;
}

/*+
 * TestStrStrtoi - Test String to Integer Conversion
-*/

static void TestStrStrtoi()
{
    int     status;
    int     value;

    status = StrStrtoi("23", &value);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(value, 23);

    status = StrStrtoi(" 34 ", &value);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(value, 34);

    status = StrStrtoi("56\t", &value);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(value, 56);

    status = StrStrtoi("\t-67\t", &value);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(value, -67);

    status = StrStrtoi(" 7 8 ", &value);
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = StrStrtoi(" 7a ", &value);
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = StrStrtoi("  ", &value);
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = StrStrtoi(NULL, &value);
    CU_ASSERT_NOT_EQUAL(status, 0);

    return;
}

/*+
 * TestStrIsSigits - Test StrIsDigits
-*/

static void TestStrIsDigits()
{
    CU_ASSERT_NOT_EQUAL(StrIsDigits("1234567"), 0);
    CU_ASSERT_NOT_EQUAL(StrIsDigits("17"), 0);

    CU_ASSERT_EQUAL(StrIsDigits(" 17"), 0);
    CU_ASSERT_EQUAL(StrIsDigits("1 7"), 0);
    CU_ASSERT_EQUAL(StrIsDigits("17 "), 0);
    CU_ASSERT_EQUAL(StrIsDigits("A"), 0);
    CU_ASSERT_EQUAL(StrIsDigits("\t"), 0);
    CU_ASSERT_EQUAL(StrIsDigits(""), 0);
    CU_ASSERT_EQUAL(StrIsDigits(NULL), 0);

    return;
}

/*+
 * TestStr2 - Create Test Suite
 *
 * Description:
 *      Adds the string test suite to the CUnit test registry
 *      and adds all the tests to it.
 *
 * Arguments:
 *      None.
 *
 * Returns:
 *      int
 *          Return status.  0 => Success.
-*/

int TestStr2(void);	/* Declaration */
int TestStr2(void)
{
    struct test_testdef tests[] = {
        {"StrAppend",           TestStrAppend},
        {"StrArglistAddFree",   TestStrArglistAddFree},
        {"StrArglistCreate",    TestStrArglistCreate},
        {"StrKeywordSearch",    TestStrKeywordSearch},
        {"StrStrtol",           TestStrStrtol},
        {"StrStrtoul",          TestStrStrtoul},
        {"StrStrtoi",           TestStrStrtoi},
        {"StrIsDigits",         TestStrIsDigits},
        {NULL,                  NULL}
    };

    return TcuCreateSuite("String Utility2", NULL, NULL, tests);
}
