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

/*
 * An ldns-based zone 'un'sorter
 *
 * This tool takes output from the OpenDNSSEC signer engine tools chain
 * And sanitizes it somewhat so that DNS servers can parse it
 *
 * It does two things:
 * - Move the SOA record so that is the first actual record
 * - Uncomments glue record comments
 *
 * Written by Jelte Jansen
 */

#include <stdio.h>
#include <stdlib.h>
#include <ldns/ldns.h>
#include <getopt.h>

#include "util.h"

void
usage(FILE *out)
{
	fprintf(out, "Usage: finalizer [options]\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-f <file>\tRead from file instead of stdin\n");
	fprintf(out, "-x <file>\tRead OptOut file from file instead of stdin\n");
	fprintf(out, "-h\t\tShow this help\n");
}

void
handle_line(char *line) {
	if (strlen(line) > 8 && strncmp("; Glue: ", line, 8) == 0) {
		printf("%s\n", line+8);
	} else {
		/* do we want to print out-of-zone data, empty non-terminals? */
		printf("%s\n", line);
	}
}

int
main(int argc, char **argv)
{
	int c;
	FILE *input_file = stdin;
	FILE *optout_file = NULL;
	char line[MAX_LINE_LEN];
	int line_len = 0;
	size_t line_count = 0, soa_line = 0;
	ldns_rr *rr;

	while ((c = getopt(argc, argv, "f:hx:")) != -1) {
		switch(c) {
			case 'f':
				input_file = fopen(optarg, "r");
				if (!input_file) {
					fprintf(stderr, "Error opening %s: %s\n",
					        optarg, strerror(errno));
					exit(1);
				}
				break;
			case 'x':
				optout_file = fopen(optarg, "r");
				if (!optout_file) {
					fprintf(stderr, "Error opening %s: %s\n",
					        optarg, strerror(errno));
					exit(1);
				}
				break;
			case 'h':
				usage(stdout);
				exit(0);
		}
	}

	while (line_len >= 0) {
		line_len = read_line(input_file, line, 0, 0);
		if (line_len > 0) {
			if (line[0] != ';') {
				(void) ldns_rr_new_frm_str(&rr, line, 0, NULL, NULL);
				if (rr && ldns_rr_get_type(rr) == LDNS_RR_TYPE_SOA) {
					printf("%s\n", line);
					soa_line = line_count;
					break;
				}
			}
		}
		line_count++;
	}

	rewind(input_file);
	line_count = 0;

	while (line_len >= 0) {
		line_len = read_line(input_file, line, 0, 0);
		if (soa_line == line_count) /* we have already printed the SOA */
		{
			line_count++;
			continue;
		}

		if (line_len > 0) {
			handle_line(line);
		}
		line_count++;
	}

	if (input_file != stdin) {
		fclose(input_file);
	}

	if (optout_file) {
		line_len = 0;
		while (line_len >= 0) {
			line_len = read_line(optout_file, line, 0, 0);
			if (line_len > 0) {
				handle_line(line);
			}
			line_count++;
		}

		fclose(optout_file);
	}
	return 0;
}
