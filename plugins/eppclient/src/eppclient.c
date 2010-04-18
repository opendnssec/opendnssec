/*
 * $Id$
 *
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation).
 * All rights reserved.
 *
 * Written by Björn Stenberg <bjorn@haxx.se> for .SE
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <ldns/ldns.h>

#include "eppconfig.h"

#define MIN(_x_, _y_) (_x_ < _y_ ? _x_ : _y_)

void usage()
{
    printf("OpenDNSSEC EPP plugin\n");
    printf("Usage: eppclient [OPTIONS]\n");
    printf("Options:\n");
    printf("  -h                Show this help screen.\n");
    printf("  --help            Show this help screen.\n");
    printf("  -v                Show version info.\n");
    printf("  --version         Show version info.\n");
    printf("\n");
    printf("\n");
    printf("eppclient reads DNSKEY RR lines from stdin and sends them to eppclientd.\n");
    printf("More information is available in the corresponding man page.\n");
}

enum {
    OPT_HELP = 0x100,
    OPT_VERSION
};

static const struct option long_options[] = {
    { "help",            0, NULL, OPT_HELP },
    { "version",         0, NULL, OPT_VERSION },
    { NULL,              0, NULL, 0 }
};

int main(int argc, char *argv[])
{
    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "hv", long_options, &option_index)) != -1) {
        switch (opt) {
            case OPT_VERSION:
            case 'v':
                printf("%s\n", PACKAGE_VERSION);
                exit(0);
                break;
            case OPT_HELP:
            case 'h':
            default:
                usage();
                exit(0);
                break;
        }
    }

    read_config();

    char* pipename = config_value("/eppclient/pipe");
    int fd = open(pipename, O_RDWR);
    if (fd < 0) {
        perror(pipename);
        exit(-1);
    }

    int linenum = 1;
    char line[1024];
    ldns_rr* first_rr = NULL;
    ldns_buffer* outbuf = ldns_buffer_new(1024);
    while (fgets(line, sizeof line, stdin)) {
        char* eol = strchr(line, '\n');
        if (eol)
            *eol = 0;

        /* parse it to find errors */
        ldns_rr* rr;
        ldns_status rc = ldns_rr_new_frm_str(&rr, line, 0, NULL, NULL);
        if (rc != LDNS_STATUS_OK) {
            fprintf(stderr, "Error in line %d: %s\n",
                    linenum, ldns_get_errorstr_by_id(rc));
            return -1;
        }

        /* we only support DNSKEY right now */
        if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_DNSKEY) {
            fprintf(stderr,
                    "Error in line %d: Only RR type DNSKEY is supported.\n",
                    linenum);
            ldns_rr_free(rr);
            return -1;
        }

        if (linenum == 1) {
            /* keep first RR for zone name */
            first_rr = rr;
        }
        else {
            /* check that this RR is the same zone as the first RR */
            ldns_rdf* owner1 = ldns_rr_owner(rr);
            ldns_buffer* obuf1 = ldns_buffer_new(256);
            ldns_rdf2buffer_str(obuf1, owner1);

            ldns_rdf* owner2 = ldns_rr_owner(first_rr);
            ldns_buffer* obuf2 = ldns_buffer_new(256);
            ldns_rdf2buffer_str(obuf2, owner2);
            
            if ((obuf1->_position != obuf2->_position) ||
                memcmp(obuf1->_data, obuf2->_data, obuf1->_position))
            {
                fprintf(stderr,
                        "Error in line %d: owner mismatch: '%*s' vs '%*s'\n",
                        linenum,
                        (int)obuf1->_position, obuf1->_data,
                        (int)obuf2->_position, obuf2->_data);
                ldns_buffer_free(obuf1);
                ldns_buffer_free(obuf2);
                return -1;
            }
            ldns_buffer_free(obuf1);
            ldns_buffer_free(obuf2);
            ldns_rr_free(rr);
        }

        ldns_buffer_printf(outbuf, "%s\n", line);
        linenum++;
    }
    ldns_rr_free(first_rr);

    int len = outbuf->_position;
    int rc = write(fd, outbuf->_data, len);
    if (rc < len) {
        if (rc < 0)
            perror(pipename);
        else
            fprintf(stderr,
                    "Error: Short write to pipe. Only %d of %d bytes written.\n",
                    rc, len);
        return -1;
    }
    ldns_buffer_free(outbuf);
    
    close(fd);

    return 0;
}
