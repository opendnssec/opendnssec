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
 * datetime - Miscellaneous Date/Time Utilities
 *
 * Description:
 *      Miscellaneous date/time utility functions used by the commands.
-*/

#define _GNU_SOURCE /* glibc2 needs this */
#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include "compat.h"

#include "ksm/ksm.h"
#include "ksm/datetime.h"
#include "ksm/message.h"
#include "ksm/kmedef.h"
#include "ksm/string_util.h"
#include "ksm/string_util2.h"

/* Macros to copy characters from one array to another */

#define COPY1(src, srcidx, dst, dstidx) \
    { \
        (dst)[(dstidx)] = (src)[(srcidx)];\
    }
#define COPY2(src, srcidx, dst, dstidx) \
    { \
        COPY1((src), (srcidx), (dst), (dstidx)); \
        COPY1((src), (srcidx) + 1, (dst), (dstidx) + 1); \
    }
#define COPY3(src, srcidx, dst, dstidx) \
    { \
        COPY2((src), (srcidx), (dst), (dstidx)); \
        COPY1((src), (srcidx) + 2, (dst), (dstidx) + 2); \
    }
#define COPY4(src, srcidx, dst, dstidx) \
    { \
        COPY3((src), (srcidx), (dst), (dstidx)); \
        COPY1((src), (srcidx) + 3, (dst), (dstidx) + 3); \
    }



/*+
 * DtDateTimeNow - Return Current Date and Time
 *
 * Description:
 *      Returns a structure containing the current date and time.
 *
 * Arguments:
 *      struct tm* datetime
 *          Returned structure holding the current date and time.
 *
 * Returns:
 *      int
 *          0       Success
 *          1       Some error
-*/

int DtNow(struct tm* datetime)
{
    time_t  curtime;    /* Current time */
    struct tm *ptr;     /* Pointer to returned result */

#ifdef ENFORCER_TIMESHIFT
    char *override;
    int status;

    override = getenv("ENFORCER_TIMESHIFT");
    if (override) {
        (void) MsgLog(KME_TIMESHIFT, override);
        status = DtParseDateTime(override, datetime);

        if (status) {
                printf("Couldn't turn \"%s\" into a date, quitting...\n", override);
                exit(1);
        }

        return status;
    }
#endif /* ENFORCER_TIMESHIFT */

    (void) time(&curtime);
    ptr = localtime_r(&curtime, datetime);
    return (ptr ? 0 : 1);
}




/*+
 * DtNumeric - Parse Numeric Date and Timestrncat
 *
 * Description:
 *      Given a string of the form YYYY[MM[DD[HH[MM[SS]]]]], return a struct tm
 *      structure holding the interpreted date and time.
 *
 * Arguments:
 *      const char* string
 *          String.  All the characters are known to be digits.
 *
 *      struct tm* datetime
 *          Returned structure holding the current date and time.
 *
 * Returns:
 *      int
 *          0       Success
 *          1       Some error
-*/

int DtNumeric(const char* string, struct tm* datetime)
{
    int     i;              /* Loop counter */
    int     length;         /* Length of the string */
    char    buffer[15];     /* Fully expanded string */
    char    ebuffer[20];    /* Expanded string with spaces between */
    int     status = 0;     /* Assumed success return */
    char*   ptr;            /* Result pointer */

    /*
     * A numeric string is only valid if:
     *
     * a) it contains an even number of characters.
     * b) It has a minimum of 8 characters
     * c) It has a maximum of 14 characters.
     */

    length = strlen(string);
    if ((length >= 8) && (length <= 14) && ((length % 2) == 0)) {

        /* Valid string length, pad out to 14 characters with zeroes */

        strlcpy(buffer, string, 15);
        for (i = length; i < (int) (sizeof(buffer) - 1); ++i) {
            buffer[i] = '0';
        }
        buffer[sizeof(buffer) - 1] = '\0';

        /* Expand the character array to allow strptime to work */

        memset(ebuffer, ' ', sizeof(ebuffer));
        ebuffer[sizeof(ebuffer) - 1] = '\0';

        COPY4(buffer,  0, ebuffer,  0);
        COPY2(buffer,  4, ebuffer,  5);
        COPY2(buffer,  6, ebuffer,  8);
        COPY2(buffer,  8, ebuffer, 11);
        COPY2(buffer, 10, ebuffer, 14);
        COPY2(buffer, 12, ebuffer, 17);

        /* ... and convert */

        ptr = strptime(ebuffer, "%Y %m %d %H %M %S", datetime);
        status = ptr ? 0 : 1;
    }
    else {

        /* Wrong number of characters */

        status = 1;
    }

    return status;
}


/*+
 * DtAppendTime - Append Time to Date
 *
 * Description:
 *      Interprets the time part of a date/time string and appends it to the
 *      normalized date/time field.
 *
 * Arguments:
 *      char* fulldt
 *          Full date and time.  On entry, this points to a buffer holding the
 *          date part of the full date and time.  On exit, the data in the
 *          buffer is extended to include the time part.
 *
 *          Note: The buffer holding the full date and time is assumed to be
 *          big enough to allow the string in it to be extended by nine
 *          characters (i.e. _00:00:00).
 *
 *      const char* timepart
 *          Time part to append.  This must be one of the following allowed time
 *          formats:
 *
 *                  [[:| ]hh[:mm[:ss]]]
 *
 *          i.e. the first characters is a space or a colon, followed by a two-
 *          digit hour.  If minutes are present, they are separated from the
 *          hour by a colon, and likewise for seconds.
 *
 *          Any absent fields are assumed to be "00".
 *
 * Returns:
 *      int
 *          Status return
 *              0       Success
 *              1       Some problem with the date
-*/

int DtAppendTime(char* fulldt, const char* timepart)
{
    int     length;         /* Length of the time part */
    int     status = 0;     /* Return status, assumed success */

    if (fulldt == NULL) {
        return 1;
    }

    if ((timepart == NULL) || (*timepart == '\0')) {

        /* No time part, set default */

        strcat(fulldt, " 00:00:00");
    }
    else {
        if ((*timepart == ' ') || (*timepart == ':')) {

            /* Valid separator */

            length = strlen(timepart);  /* Must be > 0 */

            /*
             * Now just check lengths.  If the length is correct
             * but the string is incorrect, it will be caught when
             * we try to interpret the time.
             */

            if (length == 3) {
                strcat(fulldt, timepart);
                strcat(fulldt, ":00:00");
            }
            else if (length == 6) {
                strcat(fulldt, timepart);
                strcat(fulldt, ":00");
            }
            else if (length == 9) {
                strcat(fulldt, timepart);
            }
            else {
                status = 1;
            }
        }
        else {

            /* Time part did not start with ' ' or ':' */

            status = 1;
        }
    }

    return status;
}



/*+
 * DtGeneral - Parse Date and Time
 *
 * Description:
 *      Given a string that represents a date, parse it and fill in a struct tm
 *      tm structure holding the interpreted date and time.
 *
 *      Allowed date/time strings are of the form:
 *
 *      YYYYMMDD[HH[MM[SS]]]                (all numeric)
 *
 *      or  D-MMM-YYYY[:| ]HH[:MM[:SS]]     (alphabetic  month)
 *      or  DD-MMM-YYYY[:| ]HH[:MM[:SS]]    (alphabetic  month)
 *      or  YYYY-MMM-DD[:| ]HH[:MM[:SS]]    (alphabetic month)
 *
 *          D-MM-YYYY[:| ]HH[:MM[:SS]]      (numeric month)
 *          DD-MM-YYYY[:| ]HH[:MM[:SS]]     (numeric month)
 *      or  YYYY-MM-DD[:| ]HH[:MM[:SS]]     (numeric month)
 *
 *      ... and the distinction between them is given by the location of the
 *      hyphens.
 *
 * Arguments:
 *      const char* string (input)
 *          String to check.  This is known to be non-null and not all spaces.
 *
 *      struct tm* datetime (modified)
 *          Structure which is returned holding the current date and time.
 *
 * Returns:
 *      int
 *          0       Success
 *          <>0     Some error
-*/

int DtGeneral(const char* string, struct tm* datetime)
{
    int     alphadate = 0;      /* Set 1 if alphabetic form of the date */
    int     length;             /* Length of the string */
    char    copy[32];           /* Copy of input string */
    char    fulldt[32];         /* Full date and time */
    char*   ptr;                /* Pointer to tm structure */
    int     status = 0;         /* Return status */
    int     timeoff;            /* Offset of time part in given string */

    /* Assert what we know about the input */

    if (string == NULL || *string == '\0') {
        return 1;
    }

    /* Check the string */

    if (StrIsDigits(string)) {

        /* Possibly a numeric date/time - perform analysis */

        status = DtNumeric(string, datetime);
    }
    else {
        length = strlen(string);
        if (length >= 9) {

            /*
             * String has minimum length to be valid.  Copy it to a buffer of
             * a known length to ensure that all future index references are
             * valid (even if they do reference null characters).
             */

            memset(copy, 0, sizeof(copy));
            StrStrncpy(copy, string, sizeof(copy));

            /*
             * Normalize alphabetic dates to DD-MMM-YYYY, and numeric dates to
             * [D]D-MM-YYYY.  Characters are copied via individual assignments, 
             * this being assumed to be faster than copying via memcpy when the
             * call/return overhead is taken into account.
             */

            if ((copy[1] == '-')  && (copy[5] == '-')) {    /* D-MMM-YYYY */
                strcpy(fulldt, "0");                
                strlcat(fulldt + 1, copy, 11);
                /* *(fulldt + 11) = '\0';  */
                timeoff = 10;
                alphadate = 1;
            }
            else if ((copy[1] == '-')  && (copy[4] == '-')) {   /* D-MM-YYYY */
                strcpy(fulldt, "0");                
                strlcat(fulldt + 1, copy, 10);
                /* *(fulldt + 10) = '\0';  */
                timeoff = 9;
                alphadate = 0;
            }
            else if ((copy[2] == '-') && (copy[6] == '-')) {/* DD-MMM-YYYY */
                strlcpy(fulldt, copy, 12);
                /* *(fulldt + 11) = '\0'; */
                timeoff = 11;
                alphadate = 1;
            }
            else if ((copy[2] == '-')  && (copy[5] == '-')) {   /* DD-MM-YYYY */
                strlcpy(fulldt, copy, 11);
                /* *(fulldt + 10) = '\0';  */
                timeoff = 10;
                alphadate = 0;
            }
            else if ((copy[4] == '-') && (copy[8] == '-')) {/* YYYY-MMM-DD */
                COPY2(copy, 9, fulldt, 0);
                *(fulldt + 2) = '-';
                COPY3(copy, 5, fulldt, 3);
                *(fulldt + 6) = '-';
                COPY4(copy, 0, fulldt, 7);
                *(fulldt + 11) = '\0';  
                timeoff = 11;
                alphadate = 1;
            }
            else if ((copy[4] == '-')  && (copy[7] == '-')) {/* YYYY-MM-DD */
                COPY2(copy, 8, fulldt, 0);
                *(fulldt + 2) = '-';
                COPY2(copy, 5, fulldt, 3);
                *(fulldt + 5) = '-';
                COPY4(copy, 0, fulldt, 6);
                *(fulldt + 10) = '\0';
                timeoff = 10;
                alphadate = 0;
            }
            else {
                status = 1;     /* Unrecognised format */
            }

            if (status == 0) {

                /* Date OK, so process time part (if any). First set delimiter to space if it is ':' */
				if (copy[timeoff] == ':') {
					copy[timeoff] = ' ';
				}

                status = DtAppendTime(fulldt, &copy[timeoff]);
                if (status == 0) {
                    if (alphadate) {
                        ptr = strptime(fulldt, "%d-%b-%Y %H:%M:%S", datetime);
                    }
                    else {
                        ptr = strptime(fulldt, "%d-%m-%Y %H:%M:%S", datetime);
                    }
                    status = ptr ? 0 : 2;
                }
            }
            else {

                /* String is too short to be a valid date/time */

                status = 3;
            }
        }
        else {
            status = 3;     /* Too short */
        }
    }

    return status;
}


/*+
 * DtGeneralString - Parse Date and Time
 *
 * Description:
 *      As DtGeneral, but returns the result in a string of the form
 *
 *          YYYY-MM-DD HH:MM:SS
 *
 *      ... which is suitable for ASCII input into MySql (after surrounding it
 *      with quotes).
 *
 * Arguments:
 *      const char* string (input)
 *          String to analyze.  This is known to be non-null and not all spaces.
 *
 * Returns:
 *      char*
 *          String of the form YYYY-MM-DD HH:MM:SS representing the date
 *          and time.  If NULL, there was some error.
 *
 *          The string should be freed via a call to StrFree.
-*/

char* DtGeneralString(const char* string)
{
    struct tm   datetime;       /* Used for getting the date/time */
    char        buffer[KSM_TIME_LENGTH]; /* YYYY-MM-DD HH:MM:SS + NULL */
    char*       retval = NULL;  /* Returned string */
    int         status;         /* Status return */

    if (string == NULL) {
        return NULL;
    }

    status = DtGeneral(string, &datetime);
    if (status == 0) {
        snprintf(buffer, KSM_TIME_LENGTH, "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
            datetime.tm_year + 1900, datetime.tm_mon + 1, datetime.tm_mday,
            datetime.tm_hour, datetime.tm_min, datetime.tm_sec);
        retval = StrStrdup(buffer);
    }

    return retval;
}



/*+
 * DtParseDateTime - Parse Date and Time
 *
 * Description:
 *      Date/times can be specified in one of several formats:
 *
 *          now
 *          YYYYMMDDHHMMSS
 *          YYYY-MM-DD HH:MM:SS
 *          DD-MMM-YYYY HH:MM:SS
 *          DD-MMM-YYYY:HH:MM:SS
 *          DD-MM-YYYY HH:MM:SS
 *          DD-MM-YYYY:HH:MM:SS
 *
 *      In the all strings, trailing time fields can be omitted and default to
 *      00:00:00 on the current day.
 *
 *          YYYY-MM-DD  Defaults to 00:00:00 on the day specified.
 *          YYYYMMDD    Defaults to 00:00:00 on the day specified.
 *          DD-MM-YYYY  Defaults to 00:00:00 on the day specified.
 *          YYYYMMDDHH  Defaults to 00:00:00 on the day specified.
 *          DD-MM-YYYY:HH Defaults to HH o'clock of the day specified
 *
 *      Also, leading DDs can be abbreviated to a single character.
 *
 *      The other specification is:
 *
 *          now         The date/time at which the command is executed
 *
 * Arguments:
 *      const char* string
 *          The input string to parse.
 *
 *      struct tm* datetime
 *          Output time/date
 *
 * Returns:
 *      int
 *          0   Success
 *          1   Parse error
-*/

int DtParseDateTime(const char* string, struct tm* datetime)
{
    char*   buffer;     /* Duplicate of the string to parse */
    int     len;        /* Length of the string */
    int     status = 0; /* Return status */
    char*   text;       /* First non-blank character in duplicated string */

    /* Can only work if the string is non-null */

    if (string) {

        /* Normalise the string */

        buffer = StrStrdup(string);
        StrTrimR(buffer);
        text = StrTrimL(buffer);
        StrToLower(text);

        len = strlen(text);
        if (len != 0) {

            /* Something in the string, decide what to do */

            if (strcmp(text, "now") == 0) {
                status = DtNow(datetime);
            }
            else {
                status = DtGeneral(text, datetime);
            }
        }
        else {

            /* Nothing in the normalized string */

            status = 1;
        }

        /* Free up allocated memory */

        StrFree(buffer);
    }
    else {

        /* Passed pointer is NULL */

        status = 1;
    }

    return status;
}


/*+
 * DtParseDateTimeString - Parse Date And Time
 *
 * Description:
 *      As DtParseDateTime, but returns the result in a dynamically-allocated
 *      string.
 *
 * Arguments:
 *      const char* string (input)
 *          String to analyze.
 *
 * Returns:
 *      char*
 *          String of the form YYYY-MM-DD HH:MM:SS representing the date
 *          and time.  If NULL, there was some error.
 *
 *          The string should be freed via a call to StrFree.
-*/

char* DtParseDateTimeString(const char* string)
{
    char    buffer[KSM_TIME_LENGTH]; /* Length of YYYY-MM-DD HH:MM:SS + NULL */
    struct  tm datetime;         /* Local date and time */
    char*   retval = NULL;      /* Result string */
    int     status;             /* Status return from called function */

    if (string && *string) {
        status = DtParseDateTime(string, &datetime);
        if (status == 0) {
            snprintf(buffer, KSM_TIME_LENGTH, 
                    "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
                    datetime.tm_year + 1900, datetime.tm_mon + 1, 
                    datetime.tm_mday, datetime.tm_hour, datetime.tm_min, 
                    datetime.tm_sec);
            retval = StrStrdup(buffer);
        }
    }

    return retval;
}


/*+
 * DtIntervalSeconds - Parse Interval String
 *
 * Description:
 *      Parses an interval string which is of the form:
 *
 *          <number>
 *      or  <number><interval-type>
 *
 *      Without an interval type, the interval is assumed to be in seconds.
 *      Otherwise, the following interval types recognised are:
 *
 *          s       Seconds
 *          m       Minutes - multiply number by 60 (no. seconds in a minute)
 *          h       Hours - multiple number by 3600 (no. seconds in an hour)
 *          d       Day - multiple number by 86400 (no. seconds in a day)
 *          w       Week - multiple number by 604,800 (no. seconds in a week)
 *
 *      Upper-case characters are not recognised.
 *
 *      Example: The string 2d would translate to 172,800
 *
 * Arguments:
 *      const char* text
 *          Interval as a string.
 *
 *      long* interval
 *          Returned interval.
 *
 * Returns:
 *      int
 *          0       Success, string translated OK
 *          1       Error - invalid interval-type
 *          2       Error - unable to translate string.
 *          3       Error - string too long to be a number.
 *          4       Error - invalid pointers or text string NULL.
-*/

int DtIntervalSeconds(const char* text, int* interval)
{
    char    number[32];     /* Long enough for any number */
    int     status = 0;     /* Status return */
    int     length;         /* Lengthof the string */
    long    multiplier = 1; /* Multiplication factor */

    if (text && interval && *text) {

        /* Is there a multiplier? If so, interpret it. */

        length = strlen(text);
        if (isdigit(text[length - 1])) {
            multiplier = 1;     /* No, set the factor to 1 */
        }
        else {
            switch (text[length - 1]) {
            case 's':
                multiplier = 1;
                break;

            case 'm':
                multiplier = 60;
                break;

            case 'h':
                multiplier = 60 * 60;
                break;

            case 'd':
                multiplier = 24 * 60 * 60;
                break;

            case 'w':
                multiplier = 7 * 24 * 60 * 60;
                break;

            default:
                status = 1;
            }
            --length;           /* Reduce bytes we are going to copy */
        }

        if (status == 0) {

            /* Copy all but the multiplier to the buffer for interpretation */

            if (length <= (long) (sizeof(number) - 1)) {
                (void) memcpy(number, text, length);
                number[length] = '\0';
                status = StrStrtoi(number, interval);
                if (status == 0) {

                    /* Successful, conversion, factor in the multiplier */

                    *interval *= multiplier;
                }
                else {
                    status = 2;     /* Can't translate string/overflow */
                }
            }
            else {

                /* String is too long to be a valid number */

                status = 3;
            }
        }
    }
    else {

        /* Input pointers NULL or empty string */

        status = 4;
    }

    return status;
}


/*+
 * DtSecondsInterval - Convert Seconds to Interval
 *
 * Description:
 *      Given an interval in seconds, convert to an interval if possible.
 *      A suffix is added to indicate the result.
 *
 * Arguments:
 *      int interval
 *          Interval to convert.
 *
 *      char* text
 *          Converted text (possibly truncated) is placed here.  The buffer
 *          should be about 32 characters long (maximum).
 *
 *      size_t textlen
 *          Length of the buffer pointed to by "text".
-*/

void DtSecondsInterval(int interval, char* text, size_t textlen)
{
    char    buffer[64];

    if (text && (textlen > 0)) {
        if (interval != 0) {
            if (interval % (60 * 60 * 24 * 7) == 0) {
                snprintf(buffer, 64, "%dw", interval / (60 * 60 * 24 * 7));
            }
            else if (interval % (60 * 60 * 24) == 0) {
                snprintf(buffer, 64,"%dd", interval / (60 * 60 * 24));
            }
            else if (interval % (60 * 60) == 0) {
                snprintf(buffer, 64, "%dh", interval / (60 * 60));
            }
            else if (interval % 60 == 0) {
                snprintf(buffer, 64, "%dm", interval / 60);
            }
            else {
                snprintf(buffer, 64, "%ds", interval);
            }
        }
        else {
            strcpy(buffer, "0s");
        }

        StrStrncpy(text, buffer, textlen);
    }

    return;
}


/*+
 * DtDateDiff - Return Different in Dates
 *
 * Description:
 *      Returns the different between two dates as the number of seconds.
 *
 * Arguments:
 *      const char* date1, const char* date2
 *          Dates, given in the form "YYYY-MM-DD HH:MM:SS"
 *
 *      int* result
 *          Seconds between the two dates.
 *
 * Returns:
 *      int
 *          Status return.  0 => success, other => some error in the input.
-*/

int DtDateDiff(const char* date1, const char* date2, int* result)
{
    static const char* FORMAT = "%Y-%m-%d %H:%M:%S";
    char*   cstatus;        /* Character status return */
    int     status;         /* Status return */
    struct tm tm1;          /* Converted first time */
    struct tm tm2;          /* Converted second time */
    time_t    t1;           /* First time as seconds */
    time_t    t2;           /* Second time as seconds */

    /* Do sanity check on the argument */
    if (result == NULL) {
        return 4;
    }

    if (date1 && *date1 && date2 && *date2) {

        /* Convert dates to struct tm */

        memset(&tm1, 0, sizeof(tm1));
        cstatus = strptime(date1, FORMAT, &tm1);
        if (cstatus) {
            memset(&tm2, 0, sizeof(tm2));
            cstatus = strptime(date2, FORMAT, &tm2);
            if (cstatus) {

                /*
                 * tm1 and tm2 contain valid dates.  Convert to seconds since
                 * 1 Jan 1970.
                 */

                t1 = mktime(&tm1);
                t2 = mktime(&tm2);
                *result = (int) (t1 - t2);
                status = 0;
            }
            else {
                status = 2;     /* Second date is invalid */
            }
        }
        else {
            status = 1;         /* First date is invalid */
        }
    }
    else {
        status = 3;             /* One or both dates are NULL or empty */
    }

    return status;
}

/*+
 * DtXMLIntervalSeconds - Parse xsd:durations Interval String
 *
 * Description:
 *      Parses an interval string which is of the form:
 *
 *          P<number>
 *      or  P<number><interval-type>
 *      or  PT<number><interval-type> (if the interval-type is H, M or S)
 *
 *      Without an interval type, the interval is assumed to be in seconds.
 *      Otherwise, the following interval types recognised are:
 *
 *          S       Seconds
 *          M       Minutes - multiply number by 60 (no. seconds in a minute)
 *          H       Hours - multiply number by 3600 (no. seconds in an hour)
 *          D       Day - multiply number by 86400 (no. seconds in a day)
 *          W       Week - multiply number by 604,800 (no. seconds in a week)
 *          M       Month - multiply number by 2,678,400 (no. seconds in 31 days)
 *          Y       Year - multiply number by 31,536,000 (no. seconds in 365 days)
 *
 *      Lower-case characters are not recognised.
 *
 *      Example: The string P2D would translate to 172,800
 *
 * Arguments:
 *      const char* text
 *          Interval as a string.
 *
 *      long* interval
 *          Returned interval.
 *
 * Returns:
 *      int
 *         -1       Success, string translated OK _BUT_ may not be what was expected
 *                          (Year or Month used which gives approximate answer).
 *          0       Success, string translated OK
 *          1       Error - invalid interval-type
 *          2       Error - unable to translate string.
 *          3       Error - string too long to be a number.
 *          4       Error - invalid pointers or text string NULL.
 *
 * Known issues:
 * 
 *      1. Years and months are only approximate as it has no concept of "now"
 *         We use 30 days = 1 month and 365 days = 1 year.
 *      2. Can not parse mixed format, e.g. P1Y5M
 *      3. The "T" only effects the value of "M" (P1S should be illegal as correctly
 *         it would be PT1S)
-*/

int DtXMLIntervalSeconds(const char* text, int* interval)
{
    char    number[32];     /* Long enough for any number */
    int     status = 0;     /* Status return */
    int     length;         /* Length of the string */
    int     length_mod = 0; /* How many characters have we chopped off the start? */
    long    multiplier = 1; /* Multiplication factor */
    long    temp_interval = 1; /* Long version of the int we will send back */
    short   is_time = 0;    /* Do we have a Time section or not */
    short   warning = 0;    /* Do we need to a warning code for duration approximation? */
    short   negative = 0;   /* Is the value negative ? */     
    const char  *ptr = text;    /* allow us to skip leading characters */

    if (text && interval && *text) {

        length = strlen(text);
        /* do we have a negative number? */
        if (*ptr == '-') {
            negative = 1;
            ptr++;
            length_mod++;
        }

        /* Can I have a 'P' please Bob? */
        if (*ptr == 'P') {
            ptr++;
            length_mod++;
        }

        /* if the next char is a T then we have a time, this changes the meaning of 'M' */
        if (*ptr == 'T') {
            is_time = 1;
            ptr++;
            length_mod++;
        }

        /* Is there a multiplier? If so, interpret it. */

        if (isdigit(text[length - 1])) {
            multiplier = 1;     /* No, set the factor to 1 */
        }
        else {
            switch (text[length - 1]) {
            case 'S':
                multiplier = 1;
                break;

            case 'M':
                if (is_time) {
                    multiplier = 60;
                } else {
                    multiplier = 31 * 24 * 60 * 60;
                    warning = 1;
                }
                break;

            case 'H':
                multiplier = 60 * 60;
                break;

            case 'D':
                multiplier = 24 * 60 * 60;
                break;

            case 'W':
                multiplier = 7 * 24 * 60 * 60;
                break;

            case 'Y':
                multiplier = 365 * 24 * 60 * 60;
                warning = 1;
                break;

            default:
                status = 1;
            }
            --length;           /* Reduce bytes we are going to copy */
        }

        if (status == 0) {

            /* Copy all but the multiplier to the buffer for interpretation */

            if (length <= (long) (sizeof(number) - 1)) {
                (void) memcpy(number, ptr, length - length_mod);
                number[length - length_mod] = '\0';
                status = StrStrtol(number, &temp_interval);
                if (status == 0) {

                    /* Successful, conversion, factor in the multiplier */

                    temp_interval *= multiplier;

                    if (negative == 1) {
                        temp_interval = 0 - temp_interval;
                    }

                    if (warning == 1) {
                        status = -1;
                    }

                    if ((temp_interval >= INT_MIN) && (temp_interval <= INT_MAX)) {
                        *interval = (int) temp_interval;
                    }
                    else {
                        status = 3;     /* Integer overflow */
                    }
                    
                }
                else {
                    status = 2;     /* Can't translate string/overflow */
                }
            }
            else {

                /* String is too long to be a valid number */

                status = 3;
            }
        }
    }
    else {

        /* Input pointers NULL or empty string */

        status = 4;
    }

    return status;
}
