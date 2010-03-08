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
 * File Adapters.
 *
 */

#include "config.h"
#include "util.h"
#include "v2/adapter.h"
#include "v2/adfile.h"
#include "v2/zone.h"
#include "v2/duration.h"
#include "v2/se_malloc.h"


static int
se_fgetc(FILE* fd, unsigned int* l)
{
    int c;
    c = fgetc(fd);
    if (c == '\n')
        (*l)++;
    return c;
}

/**
 * Check for DNSSEC type.
 *
 */
static int
is_dnssec_rr(ldns_rr* rr)
{
    ldns_rr_type type = 0;

    type = ldns_rr_get_type(rr);
    return (type == LDNS_RR_TYPE_NSEC ||
            type == LDNS_RR_TYPE_NSEC3 ||
            type == LDNS_RR_TYPE_NSEC3PARAMS);
}

/**
 * Check for white space.
 *
 */
static int
line_contains_space_only(char* line, int line_len)
{
    int i;
    for (i = 0; i < line_len; i++) {
        if (!isspace(line[i])) {
            return 0;
        }
    }
    return 1;
}

/**
 * Read one line from zone file.
 *
 */
static int
adapter_file_read_line(FILE* fd, char* line, unsigned int* l)
{
    int i = 0, li = 0, in_string = 0, depth = 0;
    char c = 0, lc = 0;
    int comments = 0;

    for (i = 0; i < MAX_LINE_LEN; i++) {
        c = (char) se_fgetc(fd, l);
        if (comments) {
            while (c != EOF && c != '\n') {
                c = (char) se_fgetc(fd, l);
            }
        }

        if (c == EOF) {
            if (depth != 0) {
                fprintf(stderr, "read line: bracket mismatch discovered at line %i, "
                    "missing ')'\n", *l);
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
                    fprintf(stderr, "read line: bracket mismatch discovered at line %i, "
                        "missing '('\n", *l);
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
        } else if (c == ';' && lc != '\\') {
            comments = 1;
        } else if (c == '\n' && lc != '\\') {
            comments = 0;
            /* if no depth issue, we are done */
            if (depth == 0) {
                break;
            }
        } else {
            line[li] = c;
            li++;
        }
        /* continue with line */
        lc = c;
    }

    /* done */
    if (depth != 0) {
        fprintf(stderr, "read line: bracket mismatch discovered at line %i, "
            "missing ')'\n", *l);
        return li;
    }
    line[li] = '\0';
    return li;
}


/**
 * Read the next RR from zone file.
 *
 */
static ldns_rr*
adapter_file_read_rr(FILE* fd, zone_type* zone_in, char* line, ldns_rdf** orig,
    ldns_rdf** prev, uint32_t* ttl, ldns_status* status, unsigned int* l)
{
    ldns_rr* rr = NULL;
    ldns_rdf* tmp = NULL;
    FILE* fd_include = NULL;
    int len = 0, error = 0;
    const char *endptr;  /* unused */
    uint32_t new_ttl = 0;

    if (ttl && *ttl) {
        new_ttl = *ttl;
    }

adfile_read_line:
    len = adapter_file_read_line(fd, line, l);

    if (len >= 0) {
        switch (line[0]) {
            /* directive */
            case '$':
                if (strncmp(line, "$ORIGIN", 7) == 0) {
                    /* copy from ldns */
                    if (*orig) {
                        ldns_rdf_deep_free(*orig);
                        *orig = NULL;
                    }
                    tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, line + 8);
                    if (!tmp) {
                        /* could not parse what next to $ORIGIN */
                        *status = LDNS_STATUS_SYNTAX_DNAME_ERR;
                        return NULL;
                    }
                    *orig = tmp;
                    /* end copy from ldns */
                } else if (strncmp(line, "$TTL", 4) == 0) {
                    /* override default ttl */
                    if (ttl) {
                        *ttl = ldns_str2period(line + 5, &endptr);
                    }
                } else if (strncmp(line, "$INCLUDE", 8) == 0) {
                    /* dive into this file */
                    fd_include = fopen(line + 9, "r");
                    if (fd_include) {
                        error = adapter_file_read(fd_include, zone_in, 1);
                        fclose(fd_include);
                    } else {
                        fprintf(stderr, "cannot open include file '%s'\n", line + 9);
                        *status = LDNS_STATUS_SYNTAX_ERR;
                        return NULL;
                    }
                    if (error) {
                        *status = LDNS_STATUS_ERR;
                        fprintf(stderr, "error in include file '%s'\n", line + 9);
                        return NULL;
                    }
                } else {
                    fprintf(stderr, "warning: skipping unknown directive '%s'\n", line);
                }

                goto adfile_read_line; /* perhaps next line is rr */
                break;
            /* comments, empty lines */
            case ';':
            case '\n':
                goto adfile_read_line; /* perhaps next line is rr */
                break;
            /* let's hope its a RR */
            default:
                if (line_contains_space_only(line, len)) {
                    goto adfile_read_line; /* perhaps next line is rr */
                    break;
                }

                *status = ldns_rr_new_frm_str(&rr, line, &new_ttl, *orig, prev);
                if (ttl && *ttl) {
                    *ttl = new_ttl;
                }
                if (*status == LDNS_STATUS_OK) {
                    return rr;
                } else if (*status == LDNS_STATUS_SYNTAX_EMPTY) {
                    *status = LDNS_STATUS_OK;
                    goto adfile_read_line; /* perhaps next line is rr */
                    break;
                } else {
                    fprintf(stderr, "error parsing RR at line %i (%s): %s\n", *l,
                        ldns_get_errorstr_by_id(*status), line);
                    if (rr) {
                        ldns_rr_free(rr);
                    }
                    return NULL;
                }
                break;
        }
    }

    /* -1, EOF */
    *status = LDNS_STATUS_OK;
    return NULL;
}

/**
 * Read zone file.
 *
 */
int
adapter_file_read(FILE* fd, struct zone_struct* zone, int include)
{
    int result = 0;
    uint32_t soa_min = 0;
    zone_type* zone_in = zone;
    ldns_rr* rr = NULL;
    ldns_rdf* prev = NULL, *orig = NULL;
    ldns_status status = LDNS_STATUS_OK;
    char line[MAX_LINE_LEN];
    unsigned int l = 0;

    if (!include) {
        /* get rid of old zone data */
        if (zone_in->zonedata) {
            zonedata_cleanup(zone_in->zonedata);
            zone_in->zonedata = zonedata_create();
        }

        /* default TTL */
        if (zone_in->signconf->soa_min) {
            soa_min = (uint32_t) duration2time(zone_in->signconf->soa_min);
        } else {
            soa_min = lookup_minimum(fd);
            rewind(fd);
        }
        zone->default_ttl = soa_min;
    }

    /* $ORIGIN <zone name> */
    orig = ldns_rdf_clone(zone_in->dname);

    /* read records */
    while ((rr = adapter_file_read_rr(fd, zone_in, line, &orig, &prev,
        &(zone_in->default_ttl), &status, &l)) != NULL) {

        if (status != LDNS_STATUS_OK) {
            fprintf(stderr, "error reading RR at line %i (%s): %s\n", l,
                ldns_get_errorstr_by_id(status), line);
            result = 1;
            break;
        }

        /* filter out DNSSEC RRs (except DNSKEY) */
        if (is_dnssec_rr(rr)) {
            ldns_rr_free(rr);
            continue;
        }

        /* add to the zonedata */
        result = zone_add_rr(zone_in, rr);
        if (result != 0) {
            fprintf(stderr, "error adding RR at line %i: %s\n", l,
               line);
            break;
        }
    }

    /* and done */
    ldns_rdf_deep_free(orig);
    if (prev) {
        ldns_rdf_deep_free(prev);
    }

    if (!result && status != LDNS_STATUS_OK) {
        fprintf(stderr, "error reading RR at line %i (%s): %s\n", l,
            ldns_get_errorstr_by_id(status), line);
        result = 1;
    }

    /* reset the default ttl (directives only affect the zone file) */
    zone->default_ttl = soa_min;

    return result;
}

/**
 * Read zone file.
 *
 */
int
adapter_file_write(FILE* fd, struct zone_struct* zone)
{
    zone_type* zone_out = zone;
    zone_print(fd, zone_out, 0);
    return 0;
}
