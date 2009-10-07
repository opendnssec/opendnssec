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
 * ksm_keyword - Keyword/Value Conversions
 *
 * Description:
 *      Some values in the database are numeric but need to be translated to
 *      and from strings.  This module does that.
 *
 *      Although the translations are held in tables, this nmodule hard-codes
 *      the strings in the code.
-*/

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ksm/ksm.h"
#include "ksm/string_util.h"
#include "ksm/string_util2.h"

/* Mapping of keywords to values */

static STR_KEYWORD_ELEMENT m_algorithm_keywords[] = {
    {KSM_ALGORITHM_RSAMD5_STRING,              KSM_ALGORITHM_RSAMD5},
    {KSM_ALGORITHM_DH_STRING,                  KSM_ALGORITHM_DH},
    {KSM_ALGORITHM_DSASHA1_STRING,             KSM_ALGORITHM_DSASHA1},
    {KSM_ALGORITHM_RSASHA1_STRING,             KSM_ALGORITHM_RSASHA1},
    {KSM_ALGORITHM_DSA_NSEC3_SHA1_STRING,      KSM_ALGORITHM_DSA_NSEC3_SHA1},
    {KSM_ALGORITHM_RSASHA1_NSEC3_SHA1_STRING,  KSM_ALGORITHM_RSASHA1_NSEC3_SHA1},
    {KSM_ALGORITHM_RSASHA256_STRING,           KSM_ALGORITHM_RSASHA256},
    {KSM_ALGORITHM_RSASHA512_STRING,           KSM_ALGORITHM_RSASHA512},
    {KSM_ALGORITHM_INDIRECT_STRING,            KSM_ALGORITHM_INDIRECT},
    {KSM_ALGORITHM_PRIVDOM_STRING,             KSM_ALGORITHM_PRIVDOM},
    {KSM_ALGORITHM_PRIVOID_STRING,             KSM_ALGORITHM_PRIVOID},
    {NULL,                                     -1}
};

static STR_KEYWORD_ELEMENT m_format_keywords[] = {
    {KSM_FORMAT_FILE_STRING,        KSM_FORMAT_FILE},
    {KSM_FORMAT_HSM_STRING,         KSM_FORMAT_HSM},
    {KSM_FORMAT_URI_STRING,         KSM_FORMAT_URI},
    {NULL,                          -1}
};

static STR_KEYWORD_ELEMENT m_state_keywords[] = {
    {KSM_STATE_GENERATE_STRING,     KSM_STATE_GENERATE},
    {KSM_STATE_PUBLISH_STRING,      KSM_STATE_PUBLISH},
    {KSM_STATE_READY_STRING,        KSM_STATE_READY},
    {KSM_STATE_ACTIVE_STRING,       KSM_STATE_ACTIVE},
    {KSM_STATE_RETIRE_STRING,       KSM_STATE_RETIRE},
    {KSM_STATE_DEAD_STRING,         KSM_STATE_DEAD},
    {NULL,                          -1}
};

static STR_KEYWORD_ELEMENT m_type_keywords[] = {
    {KSM_TYPE_KSK_STRING,           KSM_TYPE_KSK},
    {KSM_TYPE_ZSK_STRING,           KSM_TYPE_ZSK},
    {NULL,                          -1}
};

/*
 * Parameters do not have an associated number; instead, the numeric field
 * is the default value used if the parameter is not set.
 */

static STR_KEYWORD_ELEMENT m_parameter_keywords[] = {
    {KSM_PAR_CLOCKSKEW_STRING,  KSM_PAR_CLOCKSKEW},
    {KSM_PAR_STANDBYKSKS_STRING,  KSM_PAR_STANDBYKSKS},
    {KSM_PAR_STANDBYZSKS_STRING,  KSM_PAR_STANDBYZSKS},
    {KSM_PAR_KSKLIFE_STRING,    KSM_PAR_KSKLIFE},
    {KSM_PAR_PROPDELAY_STRING,  KSM_PAR_PROPDELAY},
    {KSM_PAR_SIGNINT_STRING,    KSM_PAR_SIGNINT},
    {KSM_PAR_SOAMIN_STRING,     KSM_PAR_SOAMIN},
    {KSM_PAR_SOATTL_STRING,     KSM_PAR_SOATTL},
    {KSM_PAR_ZSKSIGLIFE_STRING, KSM_PAR_ZSKSIGLIFE},
    {KSM_PAR_ZSKLIFE_STRING,    KSM_PAR_ZSKLIFE},
    {KSM_PAR_ZSKTTL_STRING,     KSM_PAR_ZSKTTL},
    {NULL,                      -1}
};

static STR_KEYWORD_ELEMENT m_serial_keywords[] = {
    {KSM_SERIAL_UNIX_STRING,        KSM_SERIAL_UNIX},
    {KSM_SERIAL_COUNTER_STRING,     KSM_SERIAL_COUNTER},
    {KSM_SERIAL_DATE_STRING,        KSM_SERIAL_DATE},
    {KSM_SERIAL_KEEP_STRING,        KSM_SERIAL_KEEP},
    {NULL,                          -1}
};

/*+
 * KsmKeywordNameToValue - Convert Name to Value
 * KsmKeywordValueToName - Convert Value to Name
 *
 * Description:
 *      Converts between keywords and associated values for the specific
 *      element.
 *
 *      When searching for a keyword, the given string need only be an
 *      unambiguous abbreviation of one of the keywords in the list.  For
 *      example, given the keywords
 *
 *              taiwan, tanzania, uganda
 *
 *      ... then "t" or "ta" are ambiguous but "tai" matches taiwan.  "u" (a
 *      single letter) will match uganda.
 *
 * Arguments:
 *      STR_KEYWORD_ELEMENT* elements
 *          Element list to search.
 *
 *      const char* name -or- int value
 *          Name or value to convert.
 *
 * Returns:
 *      int -or- const char*
 *          Converted value.  The return value is NULL or 0 if no conversion is
 *          found. (This implies that no keyword should have a value of 0.)
 *
 *          Note that the returned string pointer is a pointer to a static
 *          string in this module.  It should not be freed by the caller.
-*/

static int KsmKeywordNameToValue(STR_KEYWORD_ELEMENT* elements, const char* name)
{
    int     status = 1;     /* Status return - assume error */
    int     value;          /* Return value */

    if (name) {
        status = StrKeywordSearch(name, elements, &value);
    }
    return (status == 0) ? value : 0;
}

static const char* KsmKeywordValueToName(STR_KEYWORD_ELEMENT* elements, int value)
{
    int     i;                  /* Loop counter */
    const char* string = NULL;  /* Return value */

    if (elements == NULL) {
        return NULL;
    }

    for (i = 0; elements[i].string; ++i) {
        if (value == elements[i].value) {
            string = elements[i].string;
            break;
        }
    }

    return string;
}

/*+
 * KsmKeyword<type>NameToValue - Convert Name to Value
 * KsmKeyword<type>ValueToName - Convert Value to Name
 *
 * Description:
 *      Converts between keywords and associated values for the specific
 *      element.
 *
 * Arguments:
 *      const char* name -or- int value
 *          Name of ID to convert.
 *
 * Returns:
 *      int -or- const char*
 *          Converted value.  The return value is NULL or 0 if no conversion is
 *          found.
-*/

int KsmKeywordAlgorithmNameToValue(const char* name)
{
    return KsmKeywordNameToValue(m_algorithm_keywords, name);
}

int KsmKeywordFormatNameToValue(const char* name)
{
    return KsmKeywordNameToValue(m_format_keywords, name);
}

int KsmKeywordParameterNameToValue(const char* name)
{
    return KsmKeywordNameToValue(m_parameter_keywords, name);
}

int KsmKeywordStateNameToValue(const char* name)
{
    return KsmKeywordNameToValue(m_state_keywords, name);
}

int KsmKeywordTypeNameToValue(const char* name)
{
    return KsmKeywordNameToValue(m_type_keywords, name);
}

const char* KsmKeywordAlgorithmValueToName(int value)
{
    return KsmKeywordValueToName(m_algorithm_keywords, value);
}

const char* KsmKeywordFormatValueToName(int value)
{
    return KsmKeywordValueToName(m_format_keywords, value);
}

const char* KsmKeywordStateValueToName(int value)
{
    return KsmKeywordValueToName(m_state_keywords, value);
}

const char* KsmKeywordTypeValueToName(int value)
{
    return KsmKeywordValueToName(m_type_keywords, value);
}

const char* KsmKeywordSerialValueToName(int value)
{
    return KsmKeywordValueToName(m_serial_keywords, value);
}


/*+
 * KsmKeywordParameterExists - Check if Keyword Exists
 *
 * Description:
 *      Checks if the keyword is the name of a parameter, returning true (1) if
 *      it is and false (0) if it isn't.
 *
 *      Unlike the other keyword checks, the match must be exact.
 *
 * Arguments:
 *      const char* name
 *          Name of the keyword to check.
 *
 * Returns:
 *      int
 *          1   Keyword exists
 *          0   Keyword does not exist
-*/

int KsmKeywordParameterExists(const char* name)
{
    int     exists = 0;
    int     i;

    if (name) {
        for (i = 0; m_parameter_keywords[i].string; ++i) {
            if (strcmp(name, m_parameter_keywords[i].string) == 0) {
                exists = 1;
                break;
            }
        }
    }

    return exists;
}
