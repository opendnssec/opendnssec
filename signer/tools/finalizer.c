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

#include "ldns_pkcs11.h"
#include "util.h"

void
usage(FILE *out)
{
	fprintf(out, "Usage: finalizer [options]\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-f <file>\tRead from file instead of stdin\n");
	fprintf(out, "-h\t\tShow this help\n");
}

void
handle_line(char *line) {
	if (strlen(line) > 8 && strncmp("; Glue: ", line, 8) == 0) {
		printf("%s\n", line+8);
	} else {
		printf("%s\n", line);
	}
}

int
main(int argc, char **argv)
{
	int c;
	FILE *input_file = stdin;
	char line[MAX_LINE_LEN];
	int line_len = 0;
	char *pre_soa_lines[MAX_LINE_LEN];
	size_t pre_count = 0, i;
	ldns_rr *rr;
	
	while ((c = getopt(argc, argv, "f:h")) != -1) {
		switch(c) {
			case 'f':
				input_file = fopen(optarg, "r");
				if (!input_file) {
					fprintf(stderr, "Error opening %s: %s\n",
					        optarg, strerror(errno));
					exit(1);
				}
				break;
			case 'h':
				usage(stdout);
				break;
		}
	}

	while (line_len >= 0) {
		line_len = read_line(input_file, line);
		if (line_len > 0) {
			if (line[0] != ';') {
				(void) ldns_rr_new_frm_str(&rr, line, 0, NULL, NULL);
				if (rr && ldns_rr_get_type(rr) == LDNS_RR_TYPE_SOA) {
					printf("%s\n", line);
					break;
				}
			}
			pre_soa_lines[pre_count++] = strdup(line);
		}
	}

	/* do the skipped lines */
	for (i = 0; i < pre_count; i++) {
		handle_line(pre_soa_lines[i]);
		free(pre_soa_lines[i]);
	}

	/* and finish off the rest */
	while (line_len >= 0) {
		line_len = read_line(input_file, line);
		if (line_len > 0) {
			handle_line(line);
		}
	}

	if (input_file != stdin) {
		fclose(input_file);
	}
	return 0;
}
