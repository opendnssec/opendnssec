/*
 * Copyright (c) 2011-2018 NLNet Labs.
 * All rights reserved.
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
 */

/**
 *
 * String utilities
 */

#include "config.h"
#include "str.h"
#include "log.h"

#include <errno.h>
#include <assert.h>
#include <stdio.h> /* snprintf() */
#include <stdlib.h>
#include <string.h> /* strlen(), strcpy() */
#include <ctype.h> /* isspace() */

#include <unistd.h>
#include <getopt.h>

static const char *module_str = "str";

/**
 * Concatenate characters without custom allocators.
 * 
 * Will always allocate at least 1 byte (when catting empty strings) so
 * result should always be freed by the caller.
 * 
 * \param[in] argc, number of strings in argv.
 * \param[in] argv, storage of strings. Must not be NULL;
 * \param[in] delim, delimiter used to join the strings.
 * \return string, may be empty string.
 */
char *
ods_strcat_delim(int argc, char* argv[], char delim)
{
    int i, pos = 0, len = 1;
    char *cat;
    
    assert(argv);
    
    for (i = 0; i < argc; i++)
        len += strlen(argv[i]) + 1;
    cat = (char *) malloc(len * sizeof (char));
    memset(cat, delim, len-1);
    for (i = 0; i < argc; i++) {
        memcpy(cat+pos, argv[i], strlen(argv[i]));
        pos += strlen(argv[i]) + 1;
    }
    cat[len-1] = '\0';
    return cat;
}

/**
 * Remove leading and trailing whitespace.
 * enforcer used ods_str_trim(s,0)
 */
char *
ods_str_trim(char *str, int keep_newline)
{
    int has_newline = 0;
    char *start, *end;
    if (str) {
        end = str + strlen(str); /* points at \0 */
    
        for (start = str; start<end; start++) {
            if (!isspace(*start)) break;
        }
        for (; end > start; end--) {
            if (*(end-1) == '\n') has_newline = 1;
            if (!isspace(*(end-1))) break;
        }
        memmove(str, start, end-start);
        if(has_newline && keep_newline) {
            str[(end++)-start] = '\n';
        }
        str[end-start] = '\0';
    }
    return str;
}

/**
 * Version of ctime_r that does not feature a trailing '\n' character
 *
 */
char *
ods_ctime_r(char *buf, size_t nbuf, time_t t)
{
#if 0
    struct tm datetime;
    if (localtime_r(&t,&datetime) == NULL) {
        ods_log_error("[%s] time_datestamp: localtime_r() failed", 
                      module_str);
        return NULL;
    }
    snprintf(buf, nbuf, "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
             1900+datetime.tm_year, datetime.tm_mon + 1, datetime.tm_mday,
             datetime.tm_hour, datetime.tm_min, datetime.tm_sec);
    return buf;
#else
    if (nbuf>=26 && buf!=NULL) { 
        char *p;
        char *pbeg = ctime_r(&t,buf);
        char *pend = pbeg ? (pbeg+strlen(pbeg)) : pbeg;
        if (pbeg >= pend) {
            ods_log_error("[%s] time_datestamp: ctime_r() failed", 
                          module_str);
            return NULL;
        }
        /* strip trailing space characters including '\n' from time string */
        for (p=pend-1; p>=pbeg && isspace(*p); --p) {
            *p = '\0';
        }
    }
    return buf;
#endif
}
