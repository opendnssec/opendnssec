/*
 * Copyright (c) 2009-2018 NLNet Labs.
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
 * Adapter utilities.
 */

#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "adapter/adutil.h"
#include "file.h"
#include "log.h"

#include <ldns/ldns.h>

static const char* adapter_str = "adapter";


/**
 * Read one line from zone file.
 *
 */
int
adutil_readline_frm_file(FILE* fd, char* line, unsigned int* l,
    int keep_comments)
{
    int i = 0;
    int li = 0;
    int in_string = 0;
    int depth = 0;
    int comments = 0;
    int c = 0;
    int lc = 0;

    for (i = 0; i < SE_ADFILE_MAXLINE; i++) {
        c = ods_fgetc(fd, l);
        if (comments) {
            while (c != EOF && (char)c != '\n') {
                c = ods_fgetc(fd, l);
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
        } else if ((char)c == '"' && (char)lc != '\\') {
            in_string = 1 - in_string; /* swap status */
            line[li] = (char)c;
            li++;
        } else if ((char)c == '(') {
            if (in_string) {
                line[li] = (char)c;
                li++;
            } else if ((char)lc != '\\') {
                depth++;
                line[li] = ' ';
                li++;
            } else {
                line[li] = (char)c;
                li++;
            }
        } else if ((char)c == ')') {
            if (in_string) {
                line[li] = (char)c;
                li++;
            } else if ((char)lc != '\\') {
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
                line[li] = (char)c;
                li++;
            }
        } else if ((char)c == ';') {
            if (in_string) {
                line[li] = (char)c;
                li++;
            } else if ((char)lc != '\\' && !keep_comments) {
                comments = 1;
            } else {
                line[li] = (char)c;
                li++;
            }
        } else if ((char)c == '\n' && (char)lc != '\\') {
            comments = 0;
            /* if no depth issue, we are done */
            if (depth == 0) {
                break;
            }
            line[li] = ' ';
            li++;
        } else {
            line[li] = (char)c;
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

FILE*
getxfr(zone_type* zone, const char* suffix, time_t* serial)
{
    names_view_type view;
    char *filename;
    names_iterator iter;
    char* soa1;
    char* soa2;
    char*apex;
    recordset_type record;
    ldns_rr* rr;
    FILE* fp;
    int fd;
    asprintf(&filename, "%s%s", zone->name, suffix);
    fd = open(filename, O_RDWR|O_CREAT|O_EXCL, 0666);
    fp = fdopen(fd, "w+");
    if(!serial) {
        view = zonelist_obtainresource(NULL, zone, NULL, offsetof(zone_type,outputview));
        names_viewreset(view);
        writezoneapex(view, fp);
        writezonecontent(view, fp);
        writezoneapex(view, fp);
        zonelist_releaseresource(NULL, zone, NULL, offsetof(zone_type,outputview), view);
    } else {
        view = zonelist_obtainresource(NULL, zone, NULL, offsetof(zone_type,changesview));
        names_viewreset(view);
        apex = ldns_rdf2str(zone->apex);
        iter = names_viewiterator(view,names_iteratorchanges,apex,(int)*serial);
        if(names_iterate(&iter,&record)) {
            names_recordlookupone(record, LDNS_RR_TYPE_SOA, NULL, &rr);
            soa1 = ldns_rr2str(rr);
        } else
            soa1 = NULL;
        soa2 = NULL;
        while(names_advance(&iter,&record)) {
            names_recordlookupone(record, LDNS_RR_TYPE_SOA, NULL, &rr);
            soa2 = ldns_rr2str(rr);
        }
        names_end(&iter);
        free(apex);
        assert(soa1);
        assert(soa2);
        fprintf(fp, "%s", soa2);
        fprintf(fp, "%s", soa1);
        for(iter=names_viewiterator(view,names_iteratorchangedeletes,(int)*serial); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
            writerecordcontent(record, fp);
        }
        fprintf(fp, "%s", soa2);
        for(iter=names_viewiterator(view,names_iteratorchangeinserts,(int)*serial); names_iterate(&iter,&record); names_advance(&iter,NULL)) {
            writerecordcontent(record, fp);
        }
        fprintf(fp, "%s", soa2);
        zonelist_releaseresource(NULL, zone, NULL, offsetof(zone_type,changesview), view);
    }
    lseek(fd, SEEK_SET, 0);
    rewind(fp);
    unlink(filename);
    free(filename);
    return fp;
}
