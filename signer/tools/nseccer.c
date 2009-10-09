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
 * This tool creates NSEC records
 *
 * This code is provided AS-IS, you know the drill, use at own risk
 *
 * Input must be sorted
 *
 * Written by Jelte Jansen
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <ldns/ldns.h>
#include "util.h"

uint32_t nsec_counter = 0;

bool
is_same_name(ldns_rr *a, ldns_rr *b)
{
	if (!a || !b) {
		return false;
	} else if (ldns_dname_compare(ldns_rr_owner(a),
	                              ldns_rr_owner(b)) != 0) {
		return false;
	} else {
		return true;
	}
}

void
usage(FILE *out)
{
	fprintf(out, "Usage: nseccer [options]\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-f <file>\tRead RR's from file instead of stdin\n");
	fprintf(out, "-h\t\tShow this text\n");
	fprintf(out, "-n\t\tDon't echo the input records\n");
	fprintf(out, "-m <minimum>\tUse this value for the NSEC TTL\n"");
	fprintf(out, "-v <level>\tVerbosity level\n");
	fprintf(out, "\n");
	fprintf(out, "When a new owner name is read (or input stops),\n");
	fprintf(out, "an NSEC record is created from the previous to\n");
	fprintf(out, "the new owner name. All rr types seen with the\n");
	fprintf(out, "previous owner name are added to this new NSEC\n");
	fprintf(out, "Resource Record\n");
	fprintf(out, "These records are then printed to stdout\n");
}

void
make_nsec(FILE *out_file, ldns_rr *to, uint32_t ttl, ldns_rr_list *rr_list, ldns_rr **first_nsec)
{
	ldns_rr *nsec_rr;

	/* handle rrset */
	if (1) {
		ldns_rr_list_print(out_file, rr_list);
	}

	/* create nsec and print it */
	nsec_rr = ldns_create_nsec(ldns_rr_list_owner(rr_list),
							   ldns_rr_owner(to),
							   rr_list);
	ldns_rr_set_ttl(nsec_rr, ttl);
	ldns_rr_print(out_file, nsec_rr);

    nsec_counter++;

	if (first_nsec && !(*first_nsec)) {
		*first_nsec = ldns_rr_clone(nsec_rr);
	}

	/* clean for next set */
	rr_list_clear(rr_list);
	ldns_rr_free(nsec_rr);
	ldns_rr_list_push_rr(rr_list, to);
}

void
handle_name(FILE *out_file, ldns_rr *rr, uint32_t soa_min_ttl, ldns_rr_list *rr_list, ldns_rr **prev_nsec, ldns_rr **first_nsec)
{
	/* Unused parameter */
	(void)prev_nsec;

	if (rr && ldns_rr_list_rr_count(rr_list) > 0) {
		if (ldns_dname_compare(ldns_rr_owner(rr), ldns_rr_list_owner(rr_list)) == 0) {
			ldns_rr_list_push_rr(rr_list, rr);
		} else {
			make_nsec(out_file, rr, soa_min_ttl, rr_list, first_nsec);
		}
	} else if (rr) {
		ldns_rr_list_push_rr(rr_list, rr);
	}
}

ldns_status
handle_line(FILE *out_file,
            const char *line,
            int line_len,
            uint32_t soa_min_ttl,
            ldns_rr_list *rr_list,
            ldns_rr **prev_nsec,
            ldns_rr **first_nsec)
{
	ldns_rr *rr;
	ldns_status status;

	if (line_len > 0) {
		if (line[0] != ';') {
			status = ldns_rr_new_frm_str(&rr, line, 0, NULL, NULL);
			if (status == LDNS_STATUS_OK) {
				handle_name(out_file, rr, soa_min_ttl, rr_list, prev_nsec, first_nsec);
			} else {
				fprintf(stderr, "Error parsing RR (%s):\n; %s\n",
						ldns_get_errorstr_by_id(status), line);
				return status;
			}
		} else {
			/* comment line. pass */
			fprintf(out_file, "%s\n", line);
		}
	}
	return LDNS_STATUS_OK;
}

ldns_status
create_nsec_records(FILE *input_file,
                    FILE *out_file,
                    uint32_t soa_min_ttl)
{
	char line[MAX_LINE_LEN];
	int line_len = 0;
	ldns_status result = LDNS_STATUS_OK;
	ldns_rr *rr;
	ldns_rr_list *rr_list;
	ldns_rr *prev_nsec;
	ldns_rr *first_nsec = NULL;

	if (soa_min_ttl == 0) {
		line_len = 0;
		while (line_len >= 0 && soa_min_ttl == 0) {
			line_len = read_line(input_file, line, 0, 0);
			if (line_len > 0 && line[0] != ';') {
				result = ldns_rr_new_frm_str(&rr, line, 0, NULL, NULL);
				if (result == LDNS_STATUS_OK &&
					ldns_rr_get_type(rr) == LDNS_RR_TYPE_SOA) {
					soa_min_ttl = ldns_rdf2native_int32(ldns_rr_rdf(rr, 6));
					/* dont need to check SOA TTL with SOA Minimum (story 1434332) */
/*
					if (ldns_rr_ttl(rr) < soa_min_ttl) {
						soa_min_ttl = ldns_rr_ttl(rr);
					}
*/
				}
				if (result == LDNS_STATUS_OK)
					ldns_rr_free(rr);
				else {
					fprintf(stderr, "Error parsing RR (%s):\n; %s\n",
						ldns_get_errorstr_by_id(result), line);
					return result;
				}
			}
		}
	}

	result = LDNS_STATUS_OK;
	rr_list = ldns_rr_list_new();

	rewind(input_file);

	/* and do the rest of the file */
	while (line_len >= 0) {
		line_len = read_line(input_file, line, 0, 0);
		if (line_len > 0) {
			handle_line(out_file, line, line_len, soa_min_ttl, rr_list, &prev_nsec, &first_nsec);
		}
	}

	/* and loop to start */
	if (ldns_rr_list_rr_count(rr_list) > 0 && first_nsec) {
		make_nsec(out_file, first_nsec, soa_min_ttl, rr_list, &first_nsec);
	}
	ldns_rr_list_deep_free(rr_list);

	return result;
}

int
main(int argc, char **argv)
{
	int verbosity = 5;
	int c;
	bool echo_input = true;
	FILE *input_file = stdin;
	FILE *out_file = stdout;
	/* For timing statistics */
	struct timeval t_start, t_end;
	double elapsed;

	ldns_status status;
	uint32_t soa_min_ttl = 0;

	while ((c = getopt(argc, argv, "f:m:nv:w:")) != -1) {
		switch(c) {
			case 'f':
				input_file = fopen(optarg, "r");
				if (!input_file) {
					fprintf(stderr,
					        "Error opening %s: %s\n",
					        optarg,
					        strerror(errno));
				}
				break;
			case 'h':
				usage(stderr);
				exit(0);
				break;
            case 'm':
                soa_min_ttl = (uint32_t) atol(optarg);
                if (soa_min_ttl == 0) {
                    fprintf(stderr, "Warning: Minimum SOA ttl out of bounds\n");
                    soa_min_ttl = 0;
                }
                break;
			case 'n':
				echo_input = false;
				break;
			case 'v':
				verbosity = atoi(optarg);
				break;
			case 'w':
				out_file = fopen(optarg, "w");
				if (!out_file) {
					fprintf(stderr,
					        "Error opening %s for writing: %s\n",
					        optarg,
					        strerror(errno));
					exit(2);
				}
				break;
			default:
				usage(stderr);
				exit(1);
				break;
		}
	}

	gettimeofday(&t_start, NULL);

	status = create_nsec_records(input_file,
	                             out_file,
	                             soa_min_ttl);

	gettimeofday(&t_end, NULL);

	/* Print statistics */
	if (nsec_counter > 0) {
		elapsed = (double) TIMEVAL_SUB(t_end, t_start);
		if (elapsed > 0)
			fprintf(stderr, "nseccer: %d NSEC records generated (%u rr/sec)\n",
				nsec_counter, (unsigned) (nsec_counter / elapsed));
		else
			fprintf(stderr, "nseccer: %d NSEC records generated within a second\n",
				nsec_counter);
	}

	if (input_file != stdin) {
		fclose(input_file);
	}
	if (out_file != stdout) {
		fclose(out_file);
	}

	return 0;
}
