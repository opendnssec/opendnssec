/*
 * $Id$
 *
 * Copyright (c) 2009-2011 NLNet Labs. All rights reserved.
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
 * Adapter utilities.
 */

#include "config.h"
#include "adapter/adutil.h"
#include "shared/file.h"
#include "shared/log.h"

#include <ldns/ldns.h>

static const char* adapter_str = "adapter";


/**
 * Lookup SOA RR.
 *
 */
ldns_rr*
adutil_lookup_soa_rr(FILE* fd)
{
    ldns_rr *cur_rr = NULL;
    char line[SE_ADFILE_MAXLINE];
    ldns_status status = LDNS_STATUS_OK;
    int line_len = 0;
    unsigned int l = 0;

    while (line_len >= 0) {
        line_len = adutil_readline_frm_file(fd, (char*) line, &l);
        adutil_rtrim_line(line, &line_len);

        if (line_len > 0) {
            if (line[0] != ';') {
                status = ldns_rr_new_frm_str(&cur_rr, line, 0, NULL, NULL);
                if (status == LDNS_STATUS_OK) {
                    if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_SOA) {
                        return cur_rr;
                    } else {
                        ldns_rr_free(cur_rr);
                        cur_rr = NULL;
                    }
                }
            }
        }
    }
    return NULL;
}


/**
 * Read one line from zone file.
 *
 */
int
adutil_readline_frm_file(FILE* fd, char* line, unsigned int* l)
{
    int i = 0;
    int li = 0;
    int in_string = 0;
    int depth = 0;
    int comments = 0;
    char c = 0;
    char lc = 0;

    for (i = 0; i < SE_ADFILE_MAXLINE; i++) {
        c = (char) ods_fgetc(fd, l);
        if (comments) {
            while (c != EOF && c != '\n') {
                c = (char) ods_fgetc(fd, l);
            }
        }

        if (c == EOF) {
            if (depth != 0) {
                ods_log_error("[%s] read line: bracket mismatch discovered at "
                    "line %i, missing ')'", adapter_str, l&&*l?*l:0);
            }
            if (li > 0) {
                line[li] = '\0';
                return li;
            } else {
                return -1;
            }
        } else if (c == '"' && lc != '\\') {
            in_string = 1 - in_string; /* swap status */
            line[li] = c;
            li++;
        } else if (c == '(') {
            if (in_string) {
                line[li] = c;
                li++;
            } else if (lc != '\\') {
                depth++;
                line[li] = ' ';
                li++;
            } else {
                line[li] = c;
                li++;
            }
        } else if (c == ')') {
            if (in_string) {
                line[li] = c;
                li++;
            } else if (lc != '\\') {
                if (depth < 1) {
                    ods_log_error("[%s] read line: bracket mismatch "
                        "discovered at line %i, missing '('", adapter_str,
                        l&&*l?*l:0);
                    line[li] = '\0';
                    return li;
                }
                depth--;
                line[li] = ' ';
                li++;
            } else {
                line[li] = c;
                li++;
            }
        } else if (c == ';') {
            if (in_string) {
                line[li] = c;
                li++;
            } else if (lc != '\\') {
                comments = 1;
            } else {
                line[li] = c;
                li++;
            }
        } else if (c == '\n' && lc != '\\') {
            comments = 0;
            /* if no depth issue, we are done */
            if (depth == 0) {
                break;
            }
            line[li] = ' ';
            li++;
        } else if (c == '\t' && lc != '\\') {
            line[li] = ' ';
            li++;
        } else {
            line[li] = c;
            li++;
        }
        /* continue with line */
        lc = c;
    }

    /* done */
    if (depth != 0) {
        ods_log_error("[%s] read line: bracket mismatch discovered at line %i,"
            " missing ')'", adapter_str, l&&*l?*l:0);
        return li;
    }
    line[li] = '\0';
    return li;
}


/*
 * Trim trailing whitespace.
 *
 */
void
adutil_rtrim_line(char* line, int* line_len)
{
    int i = strlen(line), nl = 0;
    int trimmed = 0;

    while (i>0) {
        --i;
        if (line[i] == '\n') {
            nl = 1;
        }
        if (line[i] == ' ' || line[i] == '\t' || line[i] == '\n') {
            line[i] = '\0';
            trimmed++;
        } else {
            break;
        }
    }
    if (nl) {
        line[++i] = '\n';
    }
    *line_len -= trimmed;
    return;
}


/**
 * Check for white space.
 *
 */
int
adutil_whitespace_line(char* line, int line_len)
{
    int i;
    for (i = 0; i < line_len; i++) {
        if (!isspace((int)line[i])) {
            return 0;
        }
    }
    return 1;
}
