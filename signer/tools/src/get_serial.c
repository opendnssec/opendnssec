/*
 * $Id: license.txt 570 2009-05-04 08:52:38Z jakob $
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

/*
 * get_serial
 * 
 * This tool takes a zone file and prints the serial number found
 * in the (first) SOA rr it reads
 * 
 * by default, it will read a zone from stdin
 * if the file is not found, or there is no soa record, 0 will be
 * printed (and non-zero returned)
 */

#include <errno.h>
#include <getopt.h>

#include <ldns/ldns.h>
#include "util.h"

uint32_t get_serial(ldns_rr *rr) 
{
	uint32_t serial = 0;
	if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_SOA) {
		serial = ldns_rdf2native_int32(ldns_rr_rdf(rr, 2));
	}
	return serial;
}

void 
usage(FILE *out)
{
	fprintf(out, "Usage: get_serial [options]\n");
	fprintf(out, "options:\n");
	fprintf(out, "-f <file>: read zone from file instead of stdin\n");
	fprintf(out, "-h: show this text\n");
}

int main(int argc, char **argv)
{
	ldns_rr *cur_rr;
	char line[MAX_LINE_LEN];
	int line_len = 0;
	FILE *input_file = stdin;
	FILE *output_file = stdout;
	ldns_status status;
	uint32_t serial;
	char c;
	
	while ((c = getopt(argc, argv, "f:h")) != -1) {
		switch(c) {
		case 'f':
			input_file = fopen(optarg, "r");
			if (!input_file) {
				fprintf(stderr,
				        "Unable to open %s for reading: %s\n",
				        optarg,
				        strerror(errno));
				fprintf(output_file, "0\n");
				exit(1);
			}
			break;
		case 'h':
			usage(stdout);
			exit(0);
			break;
		}
	}

	while (line_len >= 0) {
		line_len = read_line(input_file, line);
		if (line_len > 0) {
			if (line[0] != ';') {
				status = ldns_rr_new_frm_str(&cur_rr, line, 0, NULL, NULL);
				if (status == LDNS_STATUS_OK) {
					serial = get_serial(cur_rr);
					ldns_rr_free(cur_rr);
					if (serial != 0) {
						fprintf(output_file, "%u\n", (unsigned int) serial);
						return 0;
					}
				}
			}
		}
	}
	fprintf(output_file, "0\n");
	return 1;
}

