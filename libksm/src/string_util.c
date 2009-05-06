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

/*++
 * Filename: string_util.c
 *
 * Description:
 *      String utility functions used by the whois programs.
-*/

#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "string_util.h"



/*+
 * StrUncomment - Uncomment Line
 *
 * Description:
 *      Locates the first comment character in the line, and truncates the line
 *      at that point.  The comment character is hard-coded as the hash (#)
 *      character.
 *
 * Arguments:
 *      char* line (modified)
 *          Line to check.  If a comment introducer exists, it is replaced with
 *          a null character.  If the line is NULL, the routine is a no-op.
 *
 * Returns:
 *      void
-*/

void StrUncomment(char* line)
{
    char *comment;      /* Pointer to first comment character */

    if (line && (comment = strstr(line, COMMENT_CHAR))) {

        /* comment points to character, or null if not found */

        *comment = '\0';
    }
}



/*+
 * StrWhitespace - Replace Whitespace
 *
 * Description:
 *      Replaces every whitespace characters with a space.  This conversion is
 *      usually done to simplify future processing.
 *
 * Arguments:
 *      char* line (modified)
 *          Line to modify.
 *
 * Returns:
 *      void
-*/

void StrWhitespace(char* line)
{
    if (line) {
        while (*line) {
            if (isspace((int) *line)) {
                *line = ' ';
            }
            ++line;
        }
    }
}


/*+
 * StrStrdup - Duplicate String
 *
 * Description:
 *      Wrapper for "strdup" that always returns, or exits the program (after
 *      outputting a message to stderr) if the string duplication fails.
 *
 * Arguments:
 *      const char* string (input)
 *          String to be duplicated.
 *
 * Returns:
 *      char*
 *          Pointer to duplicated string (guaranteed to be non-null).  The
 *          string should be freed with StrFree() - a macro wrapper for "free".
-*/

char* StrStrdup(const char* string)
{
    char* duplicate = NULL; /* Pointer to the duplicated string */

    if (string) {
        duplicate = strdup(string);
        if (duplicate == NULL) {
            fprintf(stderr, "StrStrdup: Call to malloc() returned null - out of swap space?");
            exit(1);
        }
    }
    else {
        duplicate = MemCalloc(1, 1);    /* Allocate a single zeroed byte */
    }

    return duplicate;
}


/*+
 * StrStrncpy - Copy String
 * StrStrncat - Concatenate String
 *
 * Description:
 *      Wrapper for "strncpy"/"strncat" that guarantees that:
 *
 *      (a) As much of the source string as possible is copied to the
 *          destination.
 *      (b) The destination string is terminated by a null byte (something not
 *          guaranteed by the standard functions).
 *
 *      Also, the function is void, unlike the standard library counterparts
 *      that return a pointer to the destination string.
 *
 * Arguments:
 *      char* dst (output)
 *          Destination string.  The final byte of this string will always be
 *          set to NULL.  If this argument is NULL, the routine is a no-op.
 *
 *      const char* src (input)
 *          Source string.  If NULL, the routine is a no-op (StrStrncat) or
 *          the destination is set to the empty string (StrStrncpy).
 *
 *      size_t dstlen (input)
 *          Total amount of space allocated for the destination, including the
 *          terminating null byte.  If this is zero, the routine is a no-op.
 *          Note that in the case of StrStrncat, this is the total amount of
 *          space IGNORING the current contents of "dst" - it is just the total
 *          space available to hold the entire resultant string.
-*/

void StrStrncpy(char* dst, const char* src, size_t dstlen)
{
    if (dst && (dstlen > 0)) {
        if (src) {
            (void) strlcpy(dst, src, dstlen);
            /* dst[dstlen - 1] = '\0'; */
        }
        else {
            dst[0] = '\0';
        }
    }

    return;
}

void StrStrncat(char* dst, const char* src, size_t dstlen)
{
    size_t  length;     /* Amount of space used in dst */
    size_t  remain;     /* Remaining space in dst */

    if (dst) {
        length = strlen(dst);
        remain = dstlen - length;
        if (remain > 1) {

            /* More space than just the trailing NULL */

            StrStrncpy(&dst[length], src, remain);
        }
    }

    return;
}



/*+
 * StrTrimR - Trim Right
 *
 * Description:
 *      Modifies a string by trimming white-space characters from the right of
 *      the string.  It does this by modifying the string, inserting a null
 *      character after the last non white-space character.
 *
 * Arguments:
 *      char *text (modified)
 *          Text to modify.  If this is NULL, the routine is a no-op.
 *
 * Returns:
 *      void
-*/

void StrTrimR(char *text)
{
    if (text) {

        /* Work backwards through the string */

        int textlen = strlen(text);
        while (-- textlen >= 0) {
            if (! isspace((int) text[textlen])) {
                text[textlen + 1] = '\0';
                return;
            }
        }

        /* Get here if the entire string is white space */

        text[0] = '\0';
    }
    return;
}



/*+
 * StrTrimL - Trim Left
 *
 * Description:
 *      Searches a string and returns a pointer to the first non white-space
 *      character in it.
 *
 * Arguments:
 *      char* text (input)
 *          Text to search.
 *
 * Returns:
 *      char* 
 *          Pointer to first non white-space character in the string.  If the
 *          string is NULL, NULL is returned.  If the string is all white space,
 *          a pointer to the trailing null character is returned.
-*/

char* StrTrimL(char* text)
{
    if (text) {
        while (*text && isspace((int) *text)) {
            ++text;
        }
    }

    return text;
}


/*+
 * StrTrim - Trim String
 *
 * Description:
 *      A combination of StrTrimL and StrTrimR, this routine modifies the passed
 *      string by inserting the null character after the last non-space in the
 *      string, then returning a pointer into the string to the first non
 *      white-space character.
 *
 * Arguments:
 *      char *text (modified)
 *          Text to be trimmed.  The text may be modified.
 *
 * Returns:
 *      char*
 *          Pointer into text of the first non white-space character.  If the
 *          input string is NULL, NULL is returned.
-*/

char* StrTrim(char* text)
{
    StrTrimR(text);
    return StrTrimL(text);
}


/*+
 * StrToLower - Convert to Lower Case
 *
 * Description:
 *      Converts the passed string to lowercase characters.  As a side-effect it
 *      also returns the length of the string.
 *
 * Arguments:
 *      char *text (modified)
 *          String to be modified.  If NULL, this routine is a no-op.
 *
 * Returns:
 *      size_y
 *          Length of the string.
-*/

size_t StrToLower(char* string)
{
    char* ptr = string;
    if (ptr) {
        while (*ptr) {
            *ptr = tolower((int) *ptr);
            ++ptr;
        }
    }

    return (size_t) (ptr - string);
}


/*+
 * StrToUpper - Convert to Upper Case
 *
 * Description:
 *      Converts the passed string to uppercase characters.  As a side-effect it
 *      also returns the length of the string.
 *
 * Arguments:
 *      char *text (modified)
 *          String to be modified.  If NULL, this routine is a no-op.
 *
 * Returns:
 *      size_t
 *          Length of the string.
-*/

size_t StrToUpper(char* string)
{
    char* ptr = string;
    if (ptr) {
        while (*ptr) {
            *ptr = toupper((int) *ptr);
            ++ptr;
        }
    }

    return (size_t) (ptr - string);
}



/*+
 * StrReplaceChar - Replace Character - Null-Terminated String
 * StrReplaceCharN - Replace Character - Length Given
 *
 * Description:
 *      Replaces all occurrences of a given character in a string by the given
 *      character.
 *
 *      StrReplaceCharN is generally used where the string may contain embedded
 *      null characters in order to remove them.
 *
 * Arguments:
 *      char* string (modified)
 *          String in which the replacement is to take place.
 *
 *      size_t len (input, StrReplaceCharN only)
 *          Lenght of input string.
 *
 *      char search (input)
 *          Character to search for.
 *
 *      char replace (input)
 *          Replacement chaaracter.
 *
 * Returns:
 *      size_t
 *          Number of replacements.
-*/

size_t StrReplaceCharN(char* string, size_t len, char search, char replace)
{
    size_t count = 0;   /* Replacement count */
    size_t i;           /* Loop counter */

    if (string) {
        for (i = 0; i < len; ++i) {
            if (string[i] == search) {
                string[i] = replace;
                ++count;
            }
        }
    }
    return count;
}

size_t StrReplaceChar(char* string, char search, char replace)
{
    size_t count = 0;   /* Replacement count */

    if (string) {
        count = StrReplaceCharN(string, strlen(string), search, replace);
    }
    return count;
}



/*+
 * StrTrimmedLength
 *
 * Description:
 *      Searches the string and returns the length of the string less leading
 *      and trailing spaces.  Essentially, this will be the result of a call to
 *      strlen() after the string has been passed through StrTrim().
 *
 * Arguments:
 *      const char* string (input)
 *          String to search.
 *
 * Returns:
 *      size_t
 *          Size of the string.
-*/

size_t StrTrimmedLength(const char* string)
{
    size_t  length = 0;     /* Length of trimmed string */
    size_t  in_length;      /* Length of input string */
    size_t  first_char;     /* Position of first non-space character */
    size_t  last_char;      /* Position of last non-space character */

    if (string) {
        in_length = strlen(string);

        /*
         * Get offset of first non-space character.  If the string does not
         * contain any such characters, first_char will equal "length".
         */

        first_char = 0;
        while (first_char < in_length) {
            if (! isspace((int) string[first_char])) {
                break;
            }
            ++first_char;
        }

        if (first_char < in_length) {

            /*
             * Must be a printable character, so find the offset of the last
             * such character.
             */

            last_char = in_length - 1;
            while (isspace((int) string[last_char])) {
                --last_char;
            }

            /* ... and work out the length */

            length = last_char - first_char + 1;
            assert(length > 0);
        }

        /* No "else" - length is set to zero on enty */
    }

    return length;
}
