/*+
 * Filename: test_string_util.c
 *
 * Description:
 *      This modules holds the unit tests for the functions in string_util.c.
 *      module.
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

#include "CUnit/Basic.h"

#include "memory.h"
#include "string_util.h"
#include "test_routines.h"




/*
 * TestCompare - Compare Strings
 * TestCompare - Compare Strings N characters
 *
 * Description:
 *      Compares two strings.  Unlike strcmp, this can cope with NULL strings,
 *      and considers both equal if both are NULL.
 *
 *      Although the CU_ASSERT_TRUE of the result could be done here, it
 *      is actually done in the caller so that if a test fails, CUnit will
 *      give some indication of the failing test.
 *
 * Arguments:
 *      const char* actual (input)
 *          The string being compared.
 *
 *      const char* expected (input)
 *          The expected value of the string.
 *
 *      size_t count (TestCompareN only)
 *          Length of sterings to compare.
 *
 * Returns:
 *      int
 *          1   Strings were identical
 *          0   Strings were different
 */

static int TestCompareN(const char* actual, const char* expected, size_t count)
{
    int ok;     /* Success status */

    if ((! actual) && (! expected)) {
        ok = 1;
    }
    else if (actual && (! expected)) {
        ok = 0;
    }
    else if ((! actual) && expected) {
        ok = 0;
    }
    else {
        ok = (memcmp(actual, expected, count) == 0);
    }

    return ok;
}

static int TestCompare(const char* actual, const char* expected)
{
    int ok;     /* Success status */

    if ((! actual) && (! expected)) {
        ok = 1;
    }
    else if (actual && (! expected)) {
        ok = 0;
    }
    else if ((! actual) && expected) {
        ok = 0;
    }
    else {
        ok = (strcmp(actual, expected) == 0);
    }

    return ok;
}



/*
 * TestStrXxx - Test Routines
 *
 * Description:
 *      A set of routines, each testing one particular string utility routine.
 *      Each utility routine is tested by two routines:
 *
 *          TestStrXxx          Tests utillity routine for one string
 *          TestStrXxxExecute   Calls TestStrXxx for a variety of strings.
 *
 * Arguments:
 *      Varies.
 */


/* StrStrdup */

static void TestStrStrdupExecute(const char* test)
{
    char* testdup = StrStrdup(test);
    CU_ASSERT_TRUE(TestCompare(testdup, test == NULL ? "" : test));
    StrFree(testdup);

    return;
}

static void TestStrStrdup(void)
{
    TestStrStrdupExecute(NULL);
    TestStrStrdupExecute("");
    TestStrStrdupExecute(" ");
    TestStrStrdupExecute("a test string");

    return;
}

/* StrStrncpy */

static void TestStrStrncpyExecute(const char* test, const char* expected,
    size_t destlen)
{
    char* dest = MemMalloc(destlen);            /* Create target area */
    StrStrncpy(dest, test, destlen);            /* Copy data */
    CU_ASSERT_TRUE(TestCompare(dest, expected));/* Compare */
    MemFree(dest);                              /* Free up memory */
}

static void TestStrStrncpy(void)
{
    char    dummy[100];
    static const char* TEST = "A dummy string"; /* Must be < sizeof(dummy) */

    TestStrStrncpyExecute("alpha", "alpha", 100); /* More than enough space */
    TestStrStrncpyExecute("beta", "beta", 5);   /* Enough space */
    TestStrStrncpyExecute("gamma", "gamm", 5);  /* 1 character too small */
    TestStrStrncpyExecute("delta", "d", 2);     /* Very small */
    TestStrStrncpyExecute("epsilon", "", 1);    /* Minimum possible */

    /* Finally some tests on what should be no-ops */

    strcpy(dummy, TEST);
    StrStrncpy(dummy, NULL, 100);
    CU_ASSERT_STRING_EQUAL(dummy, "");

    strcpy(dummy, TEST);
    StrStrncpy(dummy, "xyz", 0);
    CU_ASSERT_STRING_EQUAL(dummy, TEST);

    /*
     * The final check tests that the routine does not generate a segmentation
     * fault if the destination is NULL.
     */

    StrStrncpy(NULL, "xyz", 52);

    return;
}

/* StrStrncat */

static void TestStrStrncatExecute(const char* dst, const char* src,
    size_t dstlen, const char* expected)
{
    char*   newdst = NULL;

    if (dst) {
        newdst = MemMalloc(dstlen);         /* Create target area */
        StrStrncpy(newdst, dst, dstlen);    /* Copy data */
    }
    StrStrncat(newdst, src, dstlen);
    CU_ASSERT_TRUE(TestCompare(newdst, expected));/* Compare */

    MemFree(newdst);                    /* Free up memory */
}

static void TestStrStrncat(void)
{
    TestStrStrncatExecute("alpha", "beta", 100, "alphabeta");
    TestStrStrncatExecute("alpha", "beta",   6, "alpha");
    TestStrStrncatExecute("alpha", "beta",   7, "alphab");
    TestStrStrncatExecute("alpha", "beta",   8, "alphabe");
    TestStrStrncatExecute("alpha", "beta",   9, "alphabet");
    TestStrStrncatExecute("alpha", "beta",  10, "alphabeta");
    TestStrStrncatExecute("alpha", "beta",  11, "alphabeta");

    TestStrStrncatExecute("alpha ", "beta",   9, "alpha be");
    TestStrStrncatExecute("alpha ", "beta",  10, "alpha bet");
    TestStrStrncatExecute("alpha ", "beta",  11, "alpha beta");
    TestStrStrncatExecute("alpha ", "beta",  12, "alpha beta");

    TestStrStrncatExecute("", "beta",  1, "");
    TestStrStrncatExecute("", "beta",  2, "b");
    TestStrStrncatExecute("", "beta",  3, "be");
    TestStrStrncatExecute("", "beta",  4, "bet");
    TestStrStrncatExecute("", "beta",  5, "beta");
    TestStrStrncatExecute("", "beta",  6, "beta");

    TestStrStrncatExecute(NULL, "gamma", 6, NULL);

    return;
}

/* StrUncomment */

static void TestStrUncommentExecute(const char* test, const char* expected)
{
    char* testdup = test ? strdup(test) : NULL;

    StrUncomment(testdup);
    CU_ASSERT_TRUE(TestCompare(testdup, expected));

    free(testdup);

    return;
}

static void TestStrUncomment(void)
{
    TestStrUncommentExecute(NULL, NULL);
    TestStrUncommentExecute("", "");
    TestStrUncommentExecute(" \t ", " \t ");
    TestStrUncommentExecute("This is a string with a #comment",
        "This is a string with a ");
    TestStrUncommentExecute("This is a string with a # ## comment",
        "This is a string with a ");
    TestStrUncommentExecute("#This is a leading comment", "");
    TestStrUncommentExecute("\t\t#comment", "\t\t");
    TestStrUncommentExecute("A string with no comment",
        "A string with no comment");

    return;
}

/* StrWhitespace */

static void TestStrWhitespaceExecute(const char* test, const char* expected)
{
    char* testdup = test ? strdup(test) : NULL;

    StrWhitespace(testdup);
    CU_ASSERT_TRUE(TestCompare(testdup, expected));

    free(testdup);

    return;
}

static void TestStrWhitespace(void)
{
    TestStrWhitespaceExecute(NULL, NULL);
    TestStrWhitespaceExecute("", "");
    TestStrWhitespaceExecute(" \t ", "   ");
    TestStrWhitespaceExecute(" \r\n", "   ");
    TestStrWhitespaceExecute("A\tstring\twith\tembedded\ttabs",
        "A string with embedded tabs");
    TestStrWhitespaceExecute("no_whitespace", "no_whitespace");
    TestStrWhitespaceExecute("\r\nwhitespace\t\t", "  whitespace  ");

    return;
}

/* StrTrimR */

static void TestStrTrimRExecute(const char* test, const char* expected)
{
    char* testdup = test ? strdup(test) : NULL;

    StrTrimR(testdup);
    CU_ASSERT_TRUE(TestCompare(testdup, expected));

    free(testdup);

    return;
}

static void TestStrTrimR(void)
{
    TestStrTrimRExecute(NULL, NULL);
    TestStrTrimRExecute("", "");
    TestStrTrimRExecute("\t\tabc", "\t\tabc");
    TestStrTrimRExecute("abc\t\t", "abc");
    TestStrTrimRExecute("  alpha  ", "  alpha");
    TestStrTrimRExecute(" alpha beta\n", " alpha beta");

    return;
}

/* StrTrimL */

static void TestStrTrimLExecute(const char* test, const char* expected)
{
    char* testdup = test ? strdup(test) : NULL;

    char* trimmed = StrTrimL(testdup);
    CU_ASSERT_TRUE(TestCompare(trimmed, expected));

    free(testdup);

    return;
}

static void TestStrTrimL(void)
{
    TestStrTrimLExecute(NULL, NULL);
    TestStrTrimLExecute("", "");
    TestStrTrimLExecute("\t\tabc", "abc");
    TestStrTrimLExecute("abc\t\t", "abc\t\t");
    TestStrTrimLExecute("  alpha  ", "alpha  ");
    TestStrTrimLExecute(" alpha beta\n", "alpha beta\n");

    return;
}

/* StrTrim */

static void TestStrTrimExecute(const char* test, const char* expected)
{
    char* testdup = test ? strdup(test) : NULL;

    char* modstr = StrTrim(testdup);
    CU_ASSERT_TRUE(TestCompare(modstr, expected));

    free(testdup);

    return;
}

static void TestStrTrim(void)
{
    TestStrTrimExecute(NULL, NULL);
    TestStrTrimExecute("", "");
    TestStrTrimExecute("\t\tabc", "abc");
    TestStrTrimExecute("abc\t\t", "abc");
    TestStrTrimExecute("  alpha  ", "alpha");
    TestStrTrimExecute(" alpha beta\n", "alpha beta");

    return;
}

/* StrToLower */

static void TestStrToLowerExecute(const char* test, const char* expected)
{
    char* testdup = test ? strdup(test) : NULL;

    size_t length = StrToLower(testdup);
    CU_ASSERT_TRUE(TestCompare(testdup, expected));
    if (test) {
        CU_ASSERT_EQUAL(length, strlen(expected));
    }
    else {
        CU_ASSERT_EQUAL(length, 0);
    }

    free(testdup);

    return;
}

static void TestStrToLower(void)
{
    TestStrToLowerExecute(NULL, NULL);
    TestStrToLowerExecute("abc", "abc");
    TestStrToLowerExecute("ABC", "abc");
    TestStrToLowerExecute("AbC", "abc");
    TestStrToLowerExecute("AbC d e F", "abc d e f");

    return;
}


/* StrToUpper */

static void TestStrToUpperExecute(const char* test, const char* expected)
{
    char* testdup = test ? strdup(test) : NULL;

    size_t length = StrToUpper(testdup);
    CU_ASSERT_TRUE(TestCompare(testdup, expected));
    if (test) {
        CU_ASSERT_EQUAL(length, strlen(expected));
    }
    else {
        CU_ASSERT_EQUAL(length, 0);
    }

    free(testdup);

    return;
}

static void TestStrToUpper(void)
{
    TestStrToUpperExecute(NULL, NULL);
    TestStrToUpperExecute("abc", "ABC");
    TestStrToUpperExecute("ABC", "ABC");
    TestStrToUpperExecute("AbC", "ABC");
    TestStrToUpperExecute("AbC d e F", "ABC D E F");

    return;
}


/* StrReplaceChar */

static void TestStrReplaceCharExecute(const char* test, const char* expected,
    char search, char replace, int expected_count)
{
    char* testdup = test ? strdup(test) : NULL;

    int count = StrReplaceChar(testdup, search, replace);
    CU_ASSERT_TRUE(TestCompare(testdup, expected));
    CU_ASSERT_EQUAL(count, expected_count);

    free(testdup);

    return;
}

static void TestStrReplaceChar(void)
{
    TestStrReplaceCharExecute(NULL, NULL, 'a', 'b', 0);
    TestStrReplaceCharExecute("ABCDEF", "ABCDEF", 'a', 'b', 0);
    TestStrReplaceCharExecute(",abc", "@abc", ',', '@', 1);
    TestStrReplaceCharExecute("abc,", "abc@", ',', '@', 1);
    TestStrReplaceCharExecute(",abc,", "@abc@", ',', '@', 2);
    TestStrReplaceCharExecute("ab,c", "ab@c", ',', '@', 1);
    TestStrReplaceCharExecute("abacadae", "ebecedee", 'a', 'e', 4);

    return;
}


/* StrReplaceCharN */

static void TestStrReplaceCharNExecute(const char* test, size_t testlen,
    const char* expected, char search, char replace, int expected_count)
{
    int     count = 0;      /* Replacement count */
    char*   testdup = NULL; /* String copy */

    if (test) {
        testdup = MemMalloc(testlen + 1);
        memcpy(testdup, test, testlen);
        testdup[testlen] = '\0';
    }

    count = StrReplaceCharN(testdup, testlen, search, replace);
    CU_ASSERT_TRUE(TestCompareN(testdup, expected, testlen));
    CU_ASSERT_EQUAL(count, expected_count);
    if (testdup) {
        MemFree(testdup);
    }

    return;
}

static void TestStrReplaceCharN(void)
{
    TestStrReplaceCharNExecute(NULL, 5, NULL, 'a', 'b', 0);
    TestStrReplaceCharNExecute("ABCDEF", 6, "ABCDEF", 'a', 'b', 0);
    TestStrReplaceCharNExecute("ABCDEF", 6, "BBCDEF", 'A', 'B', 1);
    TestStrReplaceCharNExecute("ABC\0EF", 6, "ABCCEF", '\0', 'C', 1);
    TestStrReplaceCharNExecute("ABC\0EF\0", 7, "ABCCEFC", '\0', 'C', 2);
    TestStrReplaceCharNExecute("\0", 1, " ", '\0', ' ', 1);

    return;
}


/* StrTrimmedLength */

static void TestStrTrimmedLengthExecute(const char* test, size_t expected)
{
    CU_ASSERT_EQUAL(StrTrimmedLength(test), expected);

    return;
}

static void TestStrTrimmedLength(void)
{
    TestStrTrimmedLengthExecute(NULL, 0);
    TestStrTrimmedLengthExecute("", 0);
    TestStrTrimmedLengthExecute("   ", 0);
    TestStrTrimmedLengthExecute("\n\n\r\t", 0);
    TestStrTrimmedLengthExecute("abc", 3);
    TestStrTrimmedLengthExecute("   abc", 3);
    TestStrTrimmedLengthExecute("defg     \n", 4);
    TestStrTrimmedLengthExecute("\t\tabcdef\t ", 6);
    TestStrTrimmedLengthExecute("   abcdefg   ", 7);
    TestStrTrimmedLengthExecute(" a b c d e f ", 11);
    TestStrTrimmedLengthExecute("    a\r\tb", 4);
    TestStrTrimmedLengthExecute("             xy zzy               ", 6);

    return;
}


/*
 * TestStr - Create Test Suite
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
 */

int TestStr(void);	/* Declaration */
int TestStr(void)
{
    struct test_testdef tests[] = {
        {"StrReplaceCharN", TestStrReplaceCharN},
        {"StrReplaceChar",  TestStrReplaceChar},
        {"StrStrdup",       TestStrStrdup},
        {"StrStrncpy",      TestStrStrncpy},
        {"StrStrncat",      TestStrStrncat},
        {"StrToLower",      TestStrToLower},
        {"StrToUpper",      TestStrToUpper},
        {"StrTrimL",        TestStrTrimL},
        {"StrTrimR",        TestStrTrimR},
        {"StrTrim",         TestStrTrim},
        {"StrTrimmedLength",TestStrTrimmedLength},
        {"StrUncomment",    TestStrUncomment},
        {"StrWhitespace",   TestStrWhitespace},
        {NULL,              NULL}
    };

    return TcuCreateSuite("String Utility", NULL, NULL, tests);
}
