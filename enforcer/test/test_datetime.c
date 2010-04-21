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
 * Filename: test_datetime.c - Test Date and Time
 *
 * Description:
 *      This is a short test module to check the functions in the date/time
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

#include "ksm/datetime.h"
#include "ksm/string_util.h"
#include "test_routines.h"




/*+
 * CmpDtTm - Test Date/Time Structure
 *
 * Description:
 *      Checks the contents of a date/time structure.
 *
 * Arguments:
 *      struct tm* test
 *          Structure to test.
 *
 *      int year, month, day, hour, minute, second
 *          Expected values of these fields.  if a value is -1, the field is
 *          not checked.
-*/

static void CmpDtTm(struct tm* datetime, int year, int month, int day, int hour,
    int minute, int second)
{
    if (year != -1) CU_ASSERT_EQUAL(year, 1900 + datetime->tm_year);
    if (month != -1) CU_ASSERT_EQUAL(month, datetime->tm_mon + 1);
    if (day != -1) CU_ASSERT_EQUAL(day, datetime->tm_mday);
    if (hour != -1) CU_ASSERT_EQUAL(hour, datetime->tm_hour);
    if (minute != -1) CU_ASSERT_EQUAL(minute, datetime->tm_min);
    if (second != -1) CU_ASSERT_EQUAL(second, datetime->tm_sec);

    return;
}



/*+
 * TestDtNumeric - Test Numeric Date/Time
 *
 * Description:
 *      Test date/time where specified as numeric.
-*/

static void TestDtNumeric(void)
{
    int     status;     /* Status return */
    struct tm datetime; /* Date/time structure returned */

    /* Valid date/time values */

    status = DtNumeric("20080102030405", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtNumeric("200801020304", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 0);

    status = DtNumeric("2008010203", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 0, 0);

    status = DtNumeric("20080102", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 0, 0, 0);

    /* Some invalid dates */

    status = DtNumeric("2008", &datetime);  /* Too short */
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtNumeric("2008010203040506", &datetime);  /* Too long */
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtNumeric("200801020", &datetime); /* Odd no. of chars */
    CU_ASSERT_NOT_EQUAL(status, 0);

    return;
}


/*+
 * TestDtAppendTime - Test Time Appending
 *
 * Description:
 *      Tests whether tiem can be successfully appended to the date.
-*/

static void TestDtAppendTime(void)
{
    char    fulldt[64];
    int     status;

    strcpy(fulldt, "A");
    status = DtAppendTime(fulldt, NULL);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_STRING_EQUAL(fulldt, "A 00:00:00");

    strcpy(fulldt, "A");
    status = DtAppendTime(fulldt, "");
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_STRING_EQUAL(fulldt, "A 00:00:00");

    strcpy(fulldt, "A");
    status = DtAppendTime(fulldt, " 12");
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_STRING_EQUAL(fulldt, "A 12:00:00");

    strcpy(fulldt, "A");
    status = DtAppendTime(fulldt, ":12");
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_STRING_EQUAL(fulldt, "A:12:00:00");

    strcpy(fulldt, "A");
    status = DtAppendTime(fulldt, ":12:34");
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_STRING_EQUAL(fulldt, "A:12:34:00");

    strcpy(fulldt, "A");
    status = DtAppendTime(fulldt, ":12:34:56");
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_STRING_EQUAL(fulldt, "A:12:34:56");

    strcpy(fulldt, "A");
    status = DtAppendTime(fulldt, "*12:34:56"); /* Invalid separator */
    CU_ASSERT_NOT_EQUAL(status, 0);

    strcpy(fulldt, "A");
    status = DtAppendTime(fulldt, ":1234:56");  /* Wrong length */
    CU_ASSERT_NOT_EQUAL(status, 0);

    return;
}



/*+
 * TestDtGeneral - Test General Date/Time
 *
 * Description:
 *      Test date/time where specified as numeric.
-*/

static void TestDtGeneral(void)
{
    int     status;     /* Status return */
    struct tm datetime; /* Date/time structure returned */

    /* Valid date/time values */

    status = DtGeneral("2-Jan-2008 03:04:05", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtGeneral("02-Jan-2008 03:04:05", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtGeneral("02-Jan-2008:03:04:05", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtGeneral("02-Jan-2008:03:04", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 0);

    status = DtGeneral("02-Jan-2008:03", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 0, 0);

    status = DtGeneral("02-Jan-2008", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 0, 0, 0);

    /* More valid date/time values */

    status = DtGeneral("2-01-2008 03:04:05", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtGeneral("02-01-2008 03:04:05", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtGeneral("02-01-2008:03:04:05", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtGeneral("02-01-2008:03:04", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 0);

    status = DtGeneral("02-01-2008:03", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 0, 0);

    status = DtGeneral("02-01-2008", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 0, 0, 0);

    /* More valid date/time values, year first */

    status = DtGeneral("2008-Jan-02 03:04:05", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtGeneral("2008-Jan-02:03:04:05", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtGeneral("2008-Jan-02:03:04", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 0);

    status = DtGeneral("2008-Jan-02:03", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 0, 0);

    status = DtGeneral("2008-Jan-02", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 0, 0, 0);

    /* More valid date/time values, year first */

    status = DtGeneral("2008-01-02 03:04:05", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtGeneral("2008-01-02:03:04:05", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtGeneral("2008-01-02:03:04", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 0);

    status = DtGeneral("2008-01-02:03", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 0, 0);

    status = DtGeneral("2008-01-02", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 0, 0, 0);

    /* Some zero dates */

    status = DtGeneral("00-00-0000:00:00:00", &datetime);
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtGeneral("0000-00-00", &datetime);
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtGeneral("00000000", &datetime);
    CU_ASSERT_NOT_EQUAL(status, 0);

    /* Some invalid dates */

    status = DtGeneral("13-Jan", &datetime);    /* Too short */
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtGeneral("02-Xxx-2008", &datetime); /* Month invalid */
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtGeneral("02-Feb-2008:", &datetime); /* Trailing : */
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtGeneral("02-Jan-2008:03-04-05", &datetime);
    CU_ASSERT_NOT_EQUAL(status, 0);     /* Wrong separator */

    return;
}



/*+
 * TestDtGeneralStringTest - Test General String
 *
 * Description:
 *      Individual test for TestDtGeneralString.
-*/

static void GeneralStringTest(const char* what, const char* expected)
{
    char*   actual;

    actual = DtGeneralString(what);
    if (expected == NULL) {
        CU_ASSERT_PTR_NULL(actual);
    }
    else {
        CU_ASSERT_PTR_NOT_NULL(actual);
        CU_ASSERT_STRING_EQUAL(actual, expected);
        StrFree(actual);
    }

    return;
}

/*+
 * TestDtGeneral - Test General Date/Time
 *
 * Description:
 *      Test date/time where specified as numeric.
-*/

static void TestDtGeneralString(void)
{
    /* Valid date/time values */

    GeneralStringTest("2-Jan-2008 03:04:05",  "2008-01-02 03:04:05");
    GeneralStringTest("02-Jan-2008 03:04:05", "2008-01-02 03:04:05");
    GeneralStringTest("02-Jan-2008:03:04:05", "2008-01-02 03:04:05"); 
    GeneralStringTest("02-Jan-2008:03:04",    "2008-01-02 03:04:00");
    GeneralStringTest("02-Jan-2008:03",       "2008-01-02 03:00:00");
    GeneralStringTest("02-Jan-2008",          "2008-01-02 00:00:00");

    /* More valid date/time values */

    GeneralStringTest("2-01-2008 03:04:05",   "2008-01-02 03:04:05");
    GeneralStringTest("02-01-2008 03:04:05",  "2008-01-02 03:04:05");
    GeneralStringTest("02-01-2008:03:04:05",  "2008-01-02 03:04:05");
    GeneralStringTest("02-01-2008:03:04",     "2008-01-02 03:04:00");
    GeneralStringTest("02-01-2008:03",        "2008-01-02 03:00:00");
    GeneralStringTest("02-01-2008",           "2008-01-02 00:00:00");

    /* More valid date/time values, year first */

    GeneralStringTest("2008-Jan-02 03:04:05", "2008-01-02 03:04:05");
    GeneralStringTest("2008-Jan-02:03:04:05", "2008-01-02 03:04:05");
    GeneralStringTest("2008-Jan-02:03:04",    "2008-01-02 03:04:00");
    GeneralStringTest("2008-Jan-02:03",       "2008-01-02 03:00:00");
    GeneralStringTest("2008-Jan-02",          "2008-01-02 00:00:00");

    /* More valid date/time values, year first */

    GeneralStringTest("2008-01-02 03:04:05", "2008-01-02 03:04:05");
    GeneralStringTest("2008-01-02:03:04:05", "2008-01-02 03:04:05");
    GeneralStringTest("2008-01-02:03:04",    "2008-01-02 03:04:00");
    GeneralStringTest("2008-01-02:03",       "2008-01-02 03:00:00");
    GeneralStringTest("2008-01-02",          "2008-01-02 00:00:00");

    /* Some zero dates */

    GeneralStringTest("00-00-0000:00:00:00", NULL);
    GeneralStringTest("0000-00-00",          NULL);
    GeneralStringTest("00000000",            NULL);

    /* Some invalid dates */

    GeneralStringTest("13-Jan", NULL);              /* Too short */
    GeneralStringTest("02-Xxx-2008", NULL);         /* Month invalid */
    GeneralStringTest("02-Feb-2008:", NULL);        /* Trailing : */
    GeneralStringTest("02-Jan-2008:03-04-05", NULL); /* Wrong separator */

    return;
}



/*+
 * TestDtParseDateTime - Test Parsing Date/Time
 *
 * Description:
 *      Test date/time where specified as general.  This is just a concatenation
 *      of the two previous tests using the general function.
-*/

static void TestDtParseDateTime(void)
{
    int     status;     /* Status return */
    struct tm datetime; /* Date/time structure returned */

    /* Valid date/time values.  A few have leading.trailing spaces */

    status = DtParseDateTime("   20080102030405  ", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtParseDateTime("200801020304  ", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 0);

    status = DtParseDateTime("2008010203", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 0, 0);

    status = DtParseDateTime("  20080102", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 0, 0, 0);

    status = DtParseDateTime("2-Jan-2008 03:04:05", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtParseDateTime(" 02-JAN-2008 03:04:05 ", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtParseDateTime("02-jan-2008:03:04:05", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 5);

    status = DtParseDateTime("02-Jan-2008:03:04", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 4, 0);

    status = DtParseDateTime("02-Jan-2008:03", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 3, 0, 0);

    status = DtParseDateTime("02-Jan-2008", &datetime);
    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&datetime, 2008, 1, 2, 0, 0, 0);

    /* Some invalid dates */

    status = DtParseDateTime(NULL, &datetime);      /* Null string */
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtParseDateTime("", &datetime);        /* Too short */
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtParseDateTime("     ", &datetime);       /* Too short */
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtParseDateTime("2008", &datetime);    /* Too short */
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtParseDateTime("2008010203040506", &datetime);    /* Too long */
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtParseDateTime("200801020", &datetime);   /* Odd no. of chars */
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtParseDateTime("13-Jan", &datetime);  /* Too short */
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtParseDateTime("02-Xxx-2008", &datetime); /* Month invalid */
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtParseDateTime("02-Feb-2008:", &datetime); /* Trailing : */
    CU_ASSERT_NOT_EQUAL(status, 0);

    status = DtParseDateTime("02-Jan-2008:03-04-05", &datetime);
    CU_ASSERT_NOT_EQUAL(status, 0);     /* Wrong separator */

    return;
}



/*
 * TestDtNow - Check DtNow Function
 *
 * Description:
 *      Tests the "Now" function by getting the time twice and executing the
 *      "Now" function between the two times.  Where the fields of the
 *      two times are the same, compare the result from the "Now" with that.
-*/

static void TestDtNow(void)
{
    struct tm   time1;
    struct tm   time2;
    struct tm   test;
    time_t      curtime;
    int         status;

    (void) time(&curtime);
    (void) localtime_r(&curtime, &time1);
    status = DtNow(&test);
    (void) time(&curtime);
    (void) localtime_r(&curtime, &time2);

    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&test,
        time1.tm_year == time2.tm_year ? time1.tm_year + 1900 : -1,
        time1.tm_mon == time2.tm_mon ? time1.tm_mon + 1 : -1,
        time1.tm_mday == time2.tm_mday ? time1.tm_mday : -1,
        time1.tm_hour == time2.tm_hour ? time1.tm_hour : -1,
        time1.tm_min == time2.tm_min ? time1.tm_min : -1,
        time1.tm_sec == time2.tm_sec ? time1.tm_sec : -1
    );

    (void) time(&curtime);
    (void) localtime_r(&curtime, &time1);
    status = DtParseDateTime("  NOW ", &test);
    (void) time(&curtime);
    (void) localtime_r(&curtime, &time2);

    CU_ASSERT_EQUAL(status, 0);
    CmpDtTm(&test,
        time1.tm_year == time2.tm_year ? time1.tm_year + 1900 : -1,
        time1.tm_mon == time2.tm_mon ? time1.tm_mon + 1 : -1,
        time1.tm_mday == time2.tm_mday ? time1.tm_mday : -1,
        time1.tm_hour == time2.tm_hour ? time1.tm_hour : -1,
        time1.tm_min == time2.tm_min ? time1.tm_min : -1,
        time1.tm_sec == time2.tm_sec ? time1.tm_sec : -1
    );
}





/*+
 * CheckValidIntervalSeconds - Perform Test on Valid String
 *
 * Description:
 *      Performs the tests on DtIntervalSecond son the strings that are supposed
 *      to be valid.
 *
 * Arguments:
 *      const char* string
 *          String to test.
 *
 *      long einterval
 *          Expected interval.
-*/

static void CheckValidIntervalSeconds(const char* string, int einterval)
{
    int interval;
    int status;

    status = DtIntervalSeconds(string, &interval);
    CU_ASSERT_EQUAL(status, 0);
    CU_ASSERT_EQUAL(interval, einterval);

    return;
}

/*+
 * TestDtIntervalSeconds - Test DtIntervalSeconds
-*/

static void TestDtIntervalSeconds(void)
{
    int     interval;
    int     status;

    /* Valid values */

    CheckValidIntervalSeconds("1", 1L);
    CheckValidIntervalSeconds("234", 234L);
    CheckValidIntervalSeconds("1223s", 1223L);
    CheckValidIntervalSeconds("1m", 60L);
    CheckValidIntervalSeconds("15m", 900L);
    CheckValidIntervalSeconds("2h", 7200L);
    CheckValidIntervalSeconds("24h", 86400L);
    CheckValidIntervalSeconds("1d", 86400L);
    CheckValidIntervalSeconds("7d", 604800L);
    CheckValidIntervalSeconds("1w", 604800L);
    CheckValidIntervalSeconds("52w", 31449600L);

    /* Invalid ones */

    status = DtIntervalSeconds(NULL, NULL);
    CU_ASSERT_EQUAL(status, 4);
    status = DtIntervalSeconds("1d", NULL);
    CU_ASSERT_EQUAL(status, 4);
    status = DtIntervalSeconds(NULL, &interval);
    CU_ASSERT_EQUAL(status, 4);
    status = DtIntervalSeconds("", &interval);
    CU_ASSERT_EQUAL(status, 4);

    status = DtIntervalSeconds("1234567890123456789012345678901234567890",
        &interval);
    CU_ASSERT_EQUAL(status, 3);
    status = DtIntervalSeconds("1234567890123456789012345678901",
        &interval);
    CU_ASSERT_EQUAL(status, 2);     /* Overflow */

    status = DtIntervalSeconds("1ww", &interval);
    CU_ASSERT_EQUAL(status, 2);
    status = DtIntervalSeconds("2 2w", &interval);
    CU_ASSERT_EQUAL(status, 2);

    status = DtIntervalSeconds("2a", &interval);
    CU_ASSERT_EQUAL(status, 1);

    return;
}


/*+
 * TestDtSecondsInterval
-*/

static void TestDtSecondsInterval(void)
{
    char    buffer[32];

    DtSecondsInterval(1209601, buffer, sizeof(buffer));
    CU_ASSERT_STRING_EQUAL(buffer, "1209601s");

    DtSecondsInterval(1209600, buffer, sizeof(buffer));
    CU_ASSERT_STRING_EQUAL(buffer, "2w");

    DtSecondsInterval(1209599, buffer, sizeof(buffer));
    CU_ASSERT_STRING_EQUAL(buffer, "1209599s");

    DtSecondsInterval(259201, buffer, sizeof(buffer));
    CU_ASSERT_STRING_EQUAL(buffer, "259201s");

    DtSecondsInterval(259200, buffer, sizeof(buffer));
    CU_ASSERT_STRING_EQUAL(buffer, "3d");

    DtSecondsInterval(259199, buffer, sizeof(buffer));
    CU_ASSERT_STRING_EQUAL(buffer, "259199s");

    DtSecondsInterval(14401, buffer, sizeof(buffer));
    CU_ASSERT_STRING_EQUAL(buffer, "14401s");

    DtSecondsInterval(14400, buffer, sizeof(buffer));
    CU_ASSERT_STRING_EQUAL(buffer, "4h");

    DtSecondsInterval(14399, buffer, sizeof(buffer));
    CU_ASSERT_STRING_EQUAL(buffer, "14399s");

    DtSecondsInterval(301, buffer, sizeof(buffer));
    CU_ASSERT_STRING_EQUAL(buffer, "301s");

    DtSecondsInterval(300, buffer, sizeof(buffer));
    CU_ASSERT_STRING_EQUAL(buffer, "5m");

    DtSecondsInterval(299, buffer, sizeof(buffer));
    CU_ASSERT_STRING_EQUAL(buffer, "299s");

    DtSecondsInterval(0, buffer, sizeof(buffer));
    CU_ASSERT_STRING_EQUAL(buffer, "0s");

    return;
}



/*
 * CheckDtDateDiff - Check Date Difference Code
 * TestDtDateDiff - Check Date Difference Code
 *
 * Arguments to CheckDtDateDiff are:
 *
 *      const char* date1, const char* date2
 *          Dates to test
 *
 *      int status
 *          Expected status return.
 *
 *      int result
 *          Expected result, only valid if status is zero.
 */

static void CheckDtDateDiff(const char* date1, const char* date2, int status,
    int result)
{
    int act_status = 0;     /* Actual status */
    int act_result = 0;     /* Actual result */

    act_status = DtDateDiff(date1, date2, &act_result);
    CU_ASSERT_EQUAL(status, act_status);
    if (status == 0) {
        CU_ASSERT_EQUAL(result, act_result);
    }

    return;
}

static void TestDtDateDiff(void)
{
    /* Valid dates on same day */

    CheckDtDateDiff("2001-01-01 00:00:02", "2001-01-01 00:00:01", 0, 1);
    CheckDtDateDiff("2001-01-01 00:00:01", "2001-01-01 00:00:02", 0, -1);

    CheckDtDateDiff("2001-01-01 00:01:02", "2001-01-01 00:00:01", 0, 61);
    CheckDtDateDiff("2001-01-01 00:00:01", "2001-01-01 00:01:02", 0, -61);

    CheckDtDateDiff("2001-01-01 02:01:02", "2001-01-01 00:00:01", 0, 7261);
    CheckDtDateDiff("2001-01-01 00:00:01", "2001-01-01 02:01:02", 0, -7261);

    CheckDtDateDiff("2001-01-02 02:01:02", "2001-01-01 00:00:01", 0, 93661);
    CheckDtDateDiff("2001-01-01 00:00:01", "2001-01-02 02:01:02", 0, -93661);

    /* Invalid dates */

    CheckDtDateDiff(NULL, NULL, 3, 0);
    CheckDtDateDiff("2001-01-01 23:12:22", NULL, 3, 0);
    CheckDtDateDiff("2001-01-01 23:12:22", "", 3, 0);
    CheckDtDateDiff(NULL, "2001-01-01 23:12:22", 3, 0);
    CheckDtDateDiff("", "2001-01-01 23:12:22", 3, 0);
    CheckDtDateDiff("2001-01-01 23:12:22", "fred", 2, 0);
    CheckDtDateDiff("fred", "2001-01-01 23:12:22", 1, 0);
}

/*+
 * CheckValidXMLIntervalSeconds - Perform Test on Valid String
 *
 * Description:
 *      Performs the tests on DtXMLIntervalSecond son the strings that are supposed
 *      to be valid.
 *
 * Arguments:
 *      const char* string
 *          String to test.
 *
 *      long einterval
 *          Expected interval.
-*/

static void CheckValidXMLIntervalSeconds(const char* string, int einterval, int estatus)
{
    int interval;
    int status;

    status = DtXMLIntervalSeconds(string, &interval);
    CU_ASSERT_EQUAL(status, estatus);
    CU_ASSERT_EQUAL(interval, einterval);

    return;
}

/*+
 * TestDtXMLIntervalSeconds - Test DtXMLIntervalSeconds
-*/

static void TestDtXMLIntervalSeconds(void)
{
    int     interval;
    int     status;

    /* Valid values, return status = 0 */

    CheckValidXMLIntervalSeconds("P1", 1L, 0);
    CheckValidXMLIntervalSeconds("P234", 234L, 0);
    CheckValidXMLIntervalSeconds("P1223S", 1223L, 0);
    CheckValidXMLIntervalSeconds("PT1M", 60L, 0);
    CheckValidXMLIntervalSeconds("PT15M", 900L, 0);
    CheckValidXMLIntervalSeconds("P2H", 7200L, 0);
    CheckValidXMLIntervalSeconds("PT2H", 7200L, 0);
    CheckValidXMLIntervalSeconds("P24H", 86400L, 0);
    CheckValidXMLIntervalSeconds("PT24H", 86400L, 0);
    CheckValidXMLIntervalSeconds("P1D", 86400L, 0);
    CheckValidXMLIntervalSeconds("P7D", 604800L, 0);
    CheckValidXMLIntervalSeconds("P1W", 604800L, 0);
    CheckValidXMLIntervalSeconds("P52W", 31449600L, 0);
    CheckValidXMLIntervalSeconds("-PT1M", -60L, 0);
    CheckValidXMLIntervalSeconds("PT1223S", 1223L, 0);
		

    /* Valid but return -1 */
/* TODO put back
    CheckValidXMLIntervalSeconds("P1M", 2592000L, -1);
    CheckValidXMLIntervalSeconds("P15M", 38880000L, -1); */
    CheckValidXMLIntervalSeconds("P1Y", 31536000L, -1);


    /* Invalid ones */

    status = DtXMLIntervalSeconds(NULL, NULL);
    CU_ASSERT_EQUAL(status, 4);
    status = DtXMLIntervalSeconds("1d", NULL);
    CU_ASSERT_EQUAL(status, 4);
    status = DtXMLIntervalSeconds(NULL, &interval);
    CU_ASSERT_EQUAL(status, 4);
    status = DtXMLIntervalSeconds("", &interval);
    CU_ASSERT_EQUAL(status, 4);

    status = DtXMLIntervalSeconds("1234567890123456789012345678901234567890",
        &interval);
    CU_ASSERT_EQUAL(status, 3);
    status = DtXMLIntervalSeconds("1234567890123456789012345678901",
        &interval);
    CU_ASSERT_EQUAL(status, 2);     /* Overflow */

    status = DtXMLIntervalSeconds("1WW", &interval);
    CU_ASSERT_EQUAL(status, 2);
    status = DtXMLIntervalSeconds("2 2W", &interval);
    CU_ASSERT_EQUAL(status, 2);

    status = DtXMLIntervalSeconds("2a", &interval);
    CU_ASSERT_EQUAL(status, 1);

    return;
}

/*
 * TestDt - Create Test Suite
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

int TestDt(void);	/* Declaration */
int TestDt(void)
{
    struct test_testdef tests[] = {
        {"DtNumeric",           TestDtNumeric},
        {"DtAppendTime",        TestDtAppendTime},
        {"DtGeneral",           TestDtGeneral},
        {"DtGeneralString",     TestDtGeneralString},
        {"DtParseDateTime",     TestDtParseDateTime},
        {"DtNow",               TestDtNow},
        {"DtIntervalSeconds",   TestDtIntervalSeconds},
        {"DtSecondsInterval",   TestDtSecondsInterval},
        {"DtDateDiff",          TestDtDateDiff},
        {"DtXMLIntervalSeconds",TestDtXMLIntervalSeconds},
        {NULL,                  NULL}
    };

    return TcuCreateSuite("Date/Time", NULL, NULL, tests);
}
