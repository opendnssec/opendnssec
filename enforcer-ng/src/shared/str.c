/*
 * $Id$
 *
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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
 * String utilities
 */

#include "config.h"
#include "shared/str.h"
#include "shared/log.h"

#include <errno.h>
#include <stdio.h> /* snprintf() */
#include <string.h> /* strlen(), strcpy() */
#include <ctype.h> /* isspace() */

static const char *module_str = "str";

int ods_str_explode(char *buf, int argc, const char *argv[])
{
    int narg = 0;
    if (buf && strlen(buf)) { 
        char *p = buf;
        char *pend = p+strlen(p);
        do {
            for (; p<pend && isspace(*p); ++p) {
                *p = '\0'; /* zero-out space characters */
            }
            if (p < pend) {
                if (narg < argc) {
                    argv[narg++] = p;
                } else {
                    ++narg;
                }
                for (; p<pend && !isspace(*p); ++p) {
                    /* skip argv value itself */
                }
            }
        } while (p<pend);
    }
    return narg;
}

/**
 * Join arguments together with a join character into a single string.
 *
 */
char *
ods_str_join(allocator_type* allocator, int argc, char *argv[], char cjoin)
{
    char* buf = NULL;
    int c;
    int options_size = 0;
    for (c = 0; c < argc; ++c)
		options_size += strlen(argv[c]) + 1;
    if (options_size > 0) {
        buf = (char*) allocator_alloc(allocator, (options_size+1) * sizeof(char));
		/*	allocator_alloc will terminate on memory allocation
		 *	problems, so buf is always assigned when we get here.
		 */

		options_size = 0;
		for (c = 0; c < argc; ++c) {
			(void)strcpy(&buf[options_size], argv[c]);
			options_size += strlen(argv[c])+1;
			buf[options_size-1] = cjoin; /* put join character instead of 0 */
		}
		buf[options_size-1] = '\0'; /* replace join character with 0 */
		buf[options_size] = '\0'; /* set last character in buf to 0 */
    }
	return buf;
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

const char *ods_check_command(const char *cmd, int cmdsize, const char *scmd)
{
    size_t ncmd = strlen(scmd);
    if (cmdsize < ncmd || strncmp(cmd, scmd, ncmd) != 0) return 0;
    if (cmd[ncmd] == '\0') {
        cmd = "";
    } else if (cmd[ncmd] != ' ') {
        return NULL;
    } else {
        cmd = &cmd[ncmd+1];
    }
    return cmd;
}

int ods_find_arg(int *pargc, const char *argv[],
                 const char *longname, const char *shortname)
{
    int i;
    for (i=0; i<*pargc; ++i) {
        const char *a = argv[i];
        if (a[0] == '-') {
            /* we found an option, now try to match it */
            int bmatch = 0;
            if (a[1] == '-')
                bmatch = strcmp(&a[2],longname)==0; /* longopt */
            else
                bmatch = strcmp(&a[1],shortname)==0; /* shortopt */
            if (bmatch) {
                int j;
                /* remove matching option from argv */
                --(*pargc);
                for (j=i; j<*pargc; ++j)
                    argv[j] = argv[j+1];
                return i;
            }
        }
    }
    return -1;
}

int ods_find_arg_and_param(int *pargc, const char *argv[],
                           const char *longname, const char *shortname,
                           const char **pvalue)
{
    int j;
    const char *a;
    int i = ods_find_arg(pargc,argv,longname,shortname);
    if (i<0)
        return i;
    a = argv[i];
    /* check that the argv entry is not an option itself. */
    if (a[0] == '-') {
        *pvalue = NULL;
        return i;
    }
    /* set the value to the argv */
    *pvalue = a;
    /* remove parameter from argv */
    --(*pargc);
    for (j=i; j<*pargc; ++j)
        argv[j] = argv[j+1];
    return i;
}

