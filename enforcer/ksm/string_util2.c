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
 * string_util2 - Additional String Functions
 *
 * Description:
 *      Additional functions for string processing.  In general, these
 *      functions operate on dynamically-allocated strings, but this is
 *      not a hard and fast rule.
 *
 *      They have been put into a separate module so as not to have to modify
 *      string_util.c, which was taken from another (open-source) package.
-*/

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#include "ksm/ksmdef.h"
#include "ksm/memory.h"
#include "ksm/message.h"
#include "ksm/string_util.h"
#include "ksm/string_util2.h"


/*+
 * StrAppend - Append String with Reallocation
 *
 * Description:
 *      Appends the given string to a dynamically-allocated string, reallocating
 *      the former as needed.
 *
 *      The function is a no-op if either of its arguments are NULL.
 *
 * Arguments:
 *      char** str1
 *          On input this holds the current string.  It is assumed that the
 *          string has been dynamically allocated (with malloc or the like).
 *          On output, this holds the concatenation of the two strings.
 *
 *          If, on input, the string is NULL (i.e. *str is NULL, *not* str1 is
 *          NULL), a new string is allocated and str2 copied to it.
 *
 *          On exit, the string can be freed via a call to StrFree.
 *
 *      const char* str2
 *          The string to be appended.
-*/

void StrAppend(char** str1, const char* str2)
{
    int len1;   /* Length of string 1 */
    int len2;   /* Length of string 2 */

    if (str1 && str2) {

        /* Something to append and we can append it */

        len2 = strlen(str2);
        if (*str1) {
            len1 = strlen(*str1);

            /* Allocate space for combined string and concatenate */

            *str1 = MemRealloc(*str1, (len1 + len2 + 1) * sizeof(char));
            strcat(*str1, str2);
        }
        else {

            /* Nothing in string 1, so just duplicate string 2 */

            *str1 = StrStrdup(str2);
        }
    }

    return;
}


/*+
 * StrArglistAdd - Add Argument to Arglist
 *
 * Description:
 *      This function (and its companion, StrArglistFree) tackle the problem
 *      raised by the fact that tokenising the string with strtok returns
 *      the tokens one at a time, yet many functions require a set of tokens in
 *      an "arglist" array, as given to main(), i.e.
 *
 *               +---+       +----+       +-+-+-+-+-
 *      arglist: |   |------>|    |------>| | | | |...
 *               +---+       +----+       +-+-+-+-+-     +-+-+-+-
 *                           |    |--------------------->| | | |...
 *                           +----+                      +-+-+-+-
 *                           | :  |
 *                           | :  |
 *                           +----+
 *                           |NULL|
 *                           +----+
 *
 *      This function is used to add an argument to a dynamically-created
 *      argument list.  It duplicates the string, expands the list, and
 *      adds a pointer to the new string.
 *
 *      Unlike most arglists, this one is always terminated by a NULL element.
 *
 * Arguments:
 *      char*** argv
 *          Address of the pointer to the argument list.  The arglist is char**,
 *          hence this is char***.  If the arglist (i.e. *argv) is NULL, a new
 *          one is created.
 *
 *      const char* string
 *          String to add.
-*/

void StrArglistAdd(char*** argv, const char* string)
{
    char*   copy = NULL;    /* Newly allocated string */
    size_t  count = 0;      /* Number of elements in list */

    /* Create the new string */

    copy = StrStrdup(string);

    /* Now extend the list and point to this string */

    if (*argv) {

        /* Work out how many elements are in the list */

        for (count = 0; (*argv)[count]; ++count) {
            ;
        }

        /*
         * There are (count + 1) elements in the list, including the
         * trailing NULL.
         */

        *argv = MemRealloc(*argv, (count + 2) * sizeof(char*));
        (*argv)[count] = copy;
        (*argv)[count + 1] = NULL;  /* Realloc doesn't zero memory */
    }
    else {

        /* List is NULL, so allocate something */

        *argv = MemCalloc(sizeof(char*), 2);
        (*argv)[0] = copy;
    }

    return;
}



/*+
 * StrArglistFree - Free Argument List
 *
 * Description:
 *      Frees the memory allocated to the argument list.
 *
 * Arguments:
 *      char*** arglist (modified)
 *          Address of the argument list.  This is freed, as are all strings it
 *          points to.
 *
 *          On exit, this is set to NULL.
-*/

void StrArglistFree(char*** argv)
{
    int i;      /* Index into option list */

    if (*argv) {

        /* Points to a list, so we can start freeing it */

        for (i = 0; (*argv)[i]; ++i) {
            if ((*argv)[i]) {
                StrFree((*argv)[i]);
            }
        }

        /* ... and the list itself */

        MemFree(*argv);
    }

    return;
}


/*+
 * StrArglistCreate - Create Argument List
 *
 * Description:
 *      Creates an argument list from a command line.  It does this by
 *      tokenising the command line, using a whitespace characters as the
 *      separator.  Multiple contiguous spaces are treated as a single space.
 *
 * Arguments:
 *      const char* string
 *          String to split.  If NULL, an empty arglist is returned.
 *
 * Returns:
 *      char**
 *          Pointer to the dynamically-created argument list.  This should be
 *          freed using StrArglistFree.
-*/

char** StrArglistCreate(const char* string)
{
    char** argv;        /* Returned argument list */
    char* copy;         /* Copy of the given string */
    char* start;        /* Location of start of string */
    char* token;        /* Current token */

    /* Ensure that we have something to return, even if it is an empty list */

    argv = MemCalloc(sizeof(char*), 1);
    if (string) {

        /* Duplicate the string so that we can modify it */

        copy = StrStrdup(string);

        /* Convert whitespace to spaces, and trim the string */

        StrWhitespace(copy);
        StrTrimR(copy);
        start = StrTrimL(copy);

        if (*start) {

            /* String is not all empty, so we can tokenise it */

            token = NULL;
            while ((token = strtok(start, " "))) {

                /* If the token is not the empty string, add to the arglist */

                if (*token) {
                    StrArglistAdd(&argv, token);
                }
                
                /* Zero the pointer for the next call */

                start = NULL;
            }
        }

        /* Tidy up */

        StrFree(copy);
    }

    return argv;
}


/*+
 * StrKeywordSearch - Search for Keyword
 *
 * Description:
 *      Searches through a list of keywords for a match and returns the associated
 *      value.
 *
 *      The search is made on leading substrings, i.e. the supplied string is
 *      matched with the leading substrings of all values.  If the match is
 *      unique, the ID is returned, otherwise an indication that the string
 *      was not found or was ambiguous.
 *
 * Arguments:
 *      const char* search
 *          Search string.
 *
 *      STR_KEYWORD_ELEMENT* keywords
 *          List of keywords to search.  The list is terminated with an element
 *          containing a NULL string.
 *
 *      int *value
 *          Returned value.  This will be undefined if there is no match or if
 *          an ambiguous string was returned.
 *
 * Returns:
 *      int
 *          0       Success, match found
 *          -1      No match found
 *          -2      Ambiguous match found
-*/

int StrKeywordSearch(const char* search, STR_KEYWORD_ELEMENT* keywords, int* value)
{
    int i;              /* Index into keyword search */
    int status = -1;    /* Returned status, initialized to nothing found */

    if (value == NULL) {
        MsgLog(KSM_INVARG, "NULL value");
        return -1;
    }

    if (keywords && search) {
        for (i = 0; keywords[i].string; ++i) {
            if (strstr(keywords[i].string, search) == keywords[i].string) {

                /* Match found of leading substring */

                if (status == -1) {

                    /* Not found before, so not the fact */

                    *value = keywords[i].value;
                    status = 0;
                }
                else {

                    /* Have found before, so mark as ambiguous */

                    status = -2;
                    break;
                }
            }
        }
    }
    else {
        status = -1;        /* No keywords, so no match */
    }

    return status;
}


/*+
 * StrStrtol - Convert String to long
 *
 * Description:
 *      Converts a string to a "long".  It uses strtol, but also passes
 *      back a status code to indicate if the conversion was successful.
 *
 *      This version strips out tabs and whitespace characters.
 *
 * Arguments:
 *      const char* string (input)
 *          String to convert.
 *
 *      long* value (returned)
 *          Return value.
 *
 * Returns:
 *      int
 *          0   Success
 *          1   Conversion failed
-*/

int StrStrtol(const char* string, long* value)
{
    char*   endptr;         /* End of string pointer */
    int     status = 1;     /* Assume failure */
    char*   copy;           /* Copy of the string */
    char*   start;          /* Start of the trimmed string */

    if (value == NULL) {
        MsgLog(KSM_INVARG, "NULL value");
        return 1;
    }
    if (string) {
        copy = StrStrdup(string);
        StrTrimR(copy);             /* Remove trailing spaces */
        start = StrTrimL(copy);     /* ... and leading ones */
        if (*start) {

            /* String is not NULL, so try a conversion */

            errno = 0;
            *value = strtol(start, &endptr, 10);

            /* Only success if all characters converted */

            if (errno == 0) {
                status = (*endptr == '\0') ? 0 : 1;
            }
            else {
                status = 1;
            }
        }
        StrFree(copy);
    }

    return status;
}


/*+
 * StrStrtoul - Convert String to unsigned long
 *
 * Description:
 *      Converts a string to a "unsigned long".  It uses strtoul, but also
 *      passes back a status code to indicate if the conversion was successful.
 *
 *      This version strips out tabs and whitespace characters.
 *
 * Arguments:
 *      const char* string (input)
 *          String to convert.
 *
 *      unsigned long* value (returned)
 *          Return value.
 *
 * Returns:
 *      int
 *          0   Success
 *          1   Conversion failed
-*/

int StrStrtoul(const char* string, unsigned long* value)
{
    char*   endptr;         /* End of string pointer */
    int     status = 1;     /* Assume failure */
    char*   copy;           /* Copy of the string */
    char*   start;          /* Start of the trimmed string */

    if (value == NULL) {
        MsgLog(KSM_INVARG, "NULL value");
        return 1;
    }
    if (string) {
        copy = StrStrdup(string);
        StrTrimR(copy);             /* Remove trailing spaces */
        start = StrTrimL(copy);     /* ... and leading ones */
        if (*start) {

            /* String is not NULL, so try a conversion */

            errno = 0;
            *value = strtoul(start, &endptr, 10);

            /* Only success if all characters converted */

            if (errno == 0) {
                status = (*endptr == '\0') ? 0 : 1;
            }
            else {
                status = 1;
            }
        }
        StrFree(copy);
    }

    return status;
}


/*+
 * StrStrtoi - Convert String to int
 *
 * Description:
 *      Converts a string to a "int".
 *
 *      This version strips out tabs and whitespace characters.
 *
 * Arguments:
 *      const char* string (input)
 *          String to convert.
 *
 *      int* value (returned)
 *          Return value.
 *
 * Returns:
 *      int
 *          0   Success
 *          1   Conversion failed
-*/

int StrStrtoi(const char* string, int* value)
{
    long    longval;    /* "long" to be passed to StrStrtol */
    int     status;     /* Status return */

    if (value == NULL) {
        MsgLog(KSM_INVARG, "NULL value");
        return 1;
    }
    status = StrStrtol(string, &longval);
    if (status == 0) {
        if ((longval >= INT_MIN) && (longval <= INT_MAX)) {
            *value = (int) longval;
        }
        else {
            status = 1;     /* Integer overflow */
        }
    }

    return status;
}



/*+
 * StrIsDigits - Check String for All Digits
 *
 * Description:
 *      Checks a string and returns whether the string is all digits (i.e.
 *      all ASCII 0 to 9) or not.
 *
 * Arguments:
 *      const char* string
 *          String to check.
 *
 * Returns:
 *      int
 *          1 (true)    All digits
 *          0 (false)   Not all digits.  A NULL or empty string will return 0.
-*/

int StrIsDigits(const char* string)
{
    int     i;          /* Loop counter */
    int     numeric;    /* 1 if string is numeric, 0 if not */

    if (string && *string) {

        /* String is not NULL and not empty */

        numeric = 1;
        for (i = 0; string[i]; ++i) {
            if (! isdigit(string[i])) {
                numeric = 0;
                break;
            }
        }
    }
    else {

        /* NULL or empty */

        numeric = 0;
    }

    return numeric;
}
