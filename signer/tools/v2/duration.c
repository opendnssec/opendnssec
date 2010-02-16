/*
 * $Id$
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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

/**
 *
 * Durations.
 */

#include "v2/duration.h"
#include "v2/se_malloc.h"

#include <stdio.h>
#include <stdlib.h> /* atoi() */
#include <string.h> /* strncat() */
#include <time.h> /* time() */


/**
 * Create a new 'instant' duration.
 *
 */
duration_type*
duration_create(void)
{
    duration_type* duration = (duration_type*)
        se_malloc(sizeof(duration_type));
    duration->years = 0;
    duration->months = 0;
    duration->weeks = 0;
    duration->days = 0;
    duration->hours = 0;
    duration->minutes = 0;
    duration->seconds = 0;
    return duration;
}

/**
 * Create a duration from string.
 *
 */
duration_type*
duration_create_from_string(const char* str)
{
    duration_type* duration = duration_create();
    char* P, *X, *T, *W;
    int not_weeks = 0;

    if (!str)
        return duration;

    P = strchr(str, 'P');
    if (!P) {
        fprintf(stderr, "unable to create duration from string '%s'\n", str);
        duration_cleanup(duration);
        return NULL;
    }

    T = strchr(str, 'T');
    X = strchr(str, 'Y');
    if (X) {
        duration->years = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    X = strchr(str, 'M');
    if (X && (!T || (size_t) (X-P) < (size_t) (T-P))) {
        duration->months = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    X = strchr(str, 'D');
    if (X) {
        duration->days = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    if (T) {
        str = T;
        not_weeks = 1;
    }
    X = strchr(str, 'H');
    if (X && T) {
        duration->hours = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    X = strrchr(str, 'M');
    if (X && T && (size_t) (X-P) > (size_t) (T-P)) {
        duration->minutes = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    X = strchr(str, 'S');
    if (X && T) {
        duration->seconds = atoi(str+1);
        str = X;
        not_weeks = 1;
    }

    W = strchr(str, 'W');
    if (W) {
        if (not_weeks) {
            fprintf(stderr, "unable to create duration from string '%s'\n", P);
            duration_cleanup(duration);
            return NULL;
        } else {
            duration->weeks = atoi(str+1);
            str = W;
        }
    }
    return duration;
}


/**
 * Get the number of digits in a number.
 *
 */
static size_t
digits_in_number(time_t duration)
{
    uint32_t period = (uint32_t) duration;
    size_t count = 0;

    while (period > 0) {
        count++;
        period /= 10;
    }
    return count;
}


/**
 * Convert a duration to a string.
 *
 */
char*
duration2string(duration_type* duration)
{
    char* str = NULL, *num = NULL;
    size_t count = 2;
    int T = 0;

    if (!duration) {
        str = (char*) se_calloc(5, sizeof(char));
        str[0] = '\0';
        str = strncat(str, "None", 4);
        return str;
    }

    if (duration->years > 0) {
        count = count + 1 + digits_in_number(duration->years);
    }
    if (duration->months > 0) {
        count = count + 1 + digits_in_number(duration->months);
    }
    if (duration->weeks > 0) {
        count = count + 1 + digits_in_number(duration->weeks);
    }
    if (duration->days > 0) {
        count = count + 1 + digits_in_number(duration->days);
    }
    if (duration->hours > 0) {
        count = count + 1 + digits_in_number(duration->hours);
        T = 1;
    }
    if (duration->minutes > 0) {
        count = count + 1 + digits_in_number(duration->minutes);
        T = 1;
    }
    if (duration->seconds > 0) {
        count = count + 1 + digits_in_number(duration->seconds);
        T = 1;
    }
    if (T) {
        count++;
    }

    str = (char*) se_calloc(count, sizeof(char));
    str[0] = 'P';
    str[1] = '\0';

    if (duration->years > 0) {
        count = digits_in_number(duration->years);
        num = (char*) se_calloc(count+2, sizeof(char));
        snprintf(num, count+2, "%uY", (uint32_t) duration->years);
        str = strncat(str, num, count+2);
        se_free((void*) num);
    }
    if (duration->months > 0) {
        count = digits_in_number(duration->months);
        num = (char*) se_calloc(count+2, sizeof(char));
        snprintf(num, count+2, "%uM", (uint32_t) duration->months);
        str = strncat(str, num, count+2);
        se_free((void*) num);
    }
    if (duration->weeks > 0) {
        count = digits_in_number(duration->weeks);
        num = (char*) se_calloc(count+2, sizeof(char));
        snprintf(num, count+2, "%uW", (uint32_t) duration->weeks);
        str = strncat(str, num, count+2);
        se_free((void*) num);
    }
    if (duration->days > 0) {
        count = digits_in_number(duration->days);
        num = (char*) se_calloc(count+2, sizeof(char));
        snprintf(num, count+2, "%uD", (uint32_t) duration->days);
        str = strncat(str, num, count+2);
        se_free((void*) num);
    }
    if (T) {
        str = strncat(str, "T", 1);
    }
    if (duration->hours > 0) {
        count = digits_in_number(duration->hours);
        num = (char*) se_calloc(count+2, sizeof(char));
        snprintf(num, count+2, "%uH", (uint32_t) duration->hours);
        str = strncat(str, num, count+2);
        se_free((void*) num);
    }
    if (duration->minutes > 0) {
        count = digits_in_number(duration->minutes);
        num = (char*) se_calloc(count+2, sizeof(char));
        snprintf(num, count+2, "%uM", (uint32_t) duration->minutes);
        str = strncat(str, num, count+2);
        se_free((void*) num);
    }
    if (duration->seconds > 0) {
        count = digits_in_number(duration->seconds);
        num = (char*) se_calloc(count+2, sizeof(char));
        snprintf(num, count+2, "%uS", (uint32_t) duration->seconds);
        str = strncat(str, num, count+2);
        se_free((void*) num);
    }

    return str;
}


/**
 * Convert a duration to a time.
 *
 */
time_t
duration2time(duration_type* duration)
{
    time_t period = 0;

    if (duration) {
        period += (duration->seconds);
        period += (duration->minutes)*60;
        period += (duration->hours)*3600;
        period += (duration->days)*86400;
        period += (duration->weeks)*86400*7;
        period += (duration->months)*86400*31;
        period += (duration->years)*86400*365;

        if (duration->months || duration->years) {
            /* [TODO] calculate correct number of days in this month/year */
            fprintf(stderr, "warning: converting duration to approximate value\n");
        }
    }
    return period;
}

/**
 * Return the shortest time.
 *
 */
time_t
time_minimum(time_t a, time_t b)
{
    return (a < b ? a : b);
}

/**
 * Return the longest time.
 *
 */
time_t
time_maximum(time_t a, time_t b)
{
    return (a > b ? a : b);
}

/**
 * copycode: This code is based on the EXAMPLE in the strftime manual.
 *
 */
uint32_t
time_datestamp(time_t tt, const char* format, char** str)
{
    time_t t;
    struct tm *tmp;
    uint32_t ut = 0;
    char outstr[32];

    if (tt) {
        t = tt;
    } else {
        t = time(NULL);
    }

    tmp = localtime(&t);
    if (tmp == NULL) {
        fprintf(stderr, "time_datestamp: localtime() failed\n");
        return 0;
    }

    if (strftime(outstr, sizeof(outstr), format, tmp) == 0) {
        fprintf(stderr, "time_datestamp: strftime() failed\n");
        return 0;
    }

    ut = (uint32_t) atol(outstr);
    if (str) {
        *str = se_strdup(outstr);
    }

    return ut;
}

/**
 * Clean up duration.
 *
 */
void
duration_cleanup(duration_type* duration)
{
    if (duration) {
        se_free((void*) duration);
    }
}
