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

int
ods_str_explode(char *buf, int argc, const char *argv[])
{
    int narg = 0;
    char *p = strtok(buf, " ");
    while(p != NULL) {
        if (narg > argc)
            return -1;
        argv[narg] = p;
        p = strtok(NULL, " ");
        narg++;
    }
    return narg;
}

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

