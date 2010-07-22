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

#ifndef UTIL_DURATION_H
#define UTIL_DURATION_H

#include "config.h"

#include <stdint.h>
#include <time.h>

/**
 * Duration.
 *
 */
typedef struct duration_struct duration_type;
struct duration_struct
{
    time_t years;
    time_t months;
    time_t weeks;
    time_t days;
    time_t hours;
    time_t minutes;
    time_t seconds;
};

/**
 * Create a new 'instant' duration.
 * \return duration_t* the created duration
 *
 */
duration_type* duration_create(void);

/**
 * Create a duration from string.
 * \param[in] str string-format duration
 * \return duration_t* the created duration
 *
 */
duration_type* duration_create_from_string(const char* str);

/**
 * Convert a duration to a string.
 * \param[in] duration duration to be converted
 * \return char* string-format duration
 *
 */
char* duration2string(duration_type* duration);

/**
 * Convert a duration to a time.
 * \param[in] duration duration to be converted
 * \return time_t time-format duration
 *
 */
time_t duration2time(duration_type* duration);

/**
 * Return a random time.
 * \param[in] mod modulo
 * \return time_t random time
 *
 */
time_t se_rand(time_t mod);

/**
 * Return the shortest time.
 * \param[in] a one time
 * \param[in] b another time
 * \return time_t the shortest time
 *
 */
time_t time_minimum(time_t a, time_t b);

/**
 * Return the longest time.
 * \param[in] a one time
 * \param[in] b another time
 * \return time_t the shortest time
 *
 */
time_t time_maximum(time_t a, time_t b);

/**
 * Convert time into string.
 * \param[in] n time
 * \param[in] s string
 *
 */
void time_itoa(time_t n, char* s);

/**
 * Return time in datestamp.
 * \param[in] tt time
 * \param[in] format stamp format
 * \param[out] str store string
 * \return uint32_t integer based datestamp.
 *
 */
uint32_t time_datestamp(time_t tt, const char* format, char** str);

/**
 * Convert time iin string format into seconds.
 * \param[in] time time in string format
 * return time_t time in seconds
 */
time_t timeshift2time(const char *time);

/**
 * Return the time since Epoch, measured in seconds.
 * If the timeshift is enabled, return the environment variable.
 * \return time_t now (or timeshift).
 *
 */
time_t time_now(void);

/**
 * Clean up duration.
 * \param[in] duration duration to be cleaned up
 *
 */
void duration_cleanup(duration_type* duration);

#endif /* UTIL_DURATION_H */
