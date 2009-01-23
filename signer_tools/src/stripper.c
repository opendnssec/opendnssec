/**
 * This tool can be used to strip a zone of glue
 *
 * This will not see A/AAAA records that have the same name as
 * the zone cut they are glue for, for now.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <ldns/ldns.h>

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
	fprintf(out, "Usage: stripper [OPTIONS]\n");
	fprintf(out, "Strips the glue out of the zone read from the given file\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-f <file>\tRead zone from <file> instead of stdin\n");
	fprintf(out, "-h\t\tShow this help\n");
	fprintf(out, "-o <origin>\tUse origin to determine glue (mandatory)\n");
	fprintf(out, "-v <int>\tSet verbosity level\n");
}


int
main(int argc, char **argv)
{
	int verbosity = 5;
	int c;
	FILE *input_file = stdin;

	ldns_rdf *origin = NULL;
	uint32_t ttl = LDNS_DEFAULT_TTL;
	
	ldns_rr *cur_rr;
	ldns_rdf *prev_name = NULL;
	ldns_status status;
	
	ldns_rr *last_delegation_ns = NULL;

	while ((c = getopt(argc, argv, "f:hno:v:")) != -1) {
		switch(c) {
			case 'f':
				input_file = fopen(optarg, "r");
				if (!input_file) {
					fprintf(stderr,
					        "Unable to open %s: %s\n",
					        optarg,
					        strerror(errno));
				}
				break;
			case 'h':
				usage(stdout);
				exit(0);
				break;
			case 'o':
				status = ldns_str2rdf_dname(&origin, optarg);
				if (!origin) {
					fprintf(stderr,
					        "Error parsing origin '%s': %s\n",
					        optarg,
					        ldns_get_errorstr_by_id(status));
					exit(1);
				}
				break;
			case 'v':
				verbosity = atoi(optarg);
				break;
		}
	}
	
	if (!origin) {
		fprintf(stderr, "Error: no origin given to stripper (-o)\n");
		if (input_file != stdin) {
			fclose(input_file);
		}
		exit(2);
	}

	/* Parse mode: read rrs from input */
	/* Directives like $ORIGIN and $TTL are not allowed */
	status = ldns_rr_new_frm_fp(&cur_rr,
	                            input_file,
	                            &ttl,
	                            &origin,
	                            &prev_name);
	
	if (status != LDNS_STATUS_OK) {
		fprintf(stderr,
		        "Error in first RR: %s, aborting\n",
		        ldns_get_errorstr_by_id(status));
		exit(1);
	}
	
	while (status == LDNS_STATUS_OK) {
		if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_NS) {
			ldns_rr_print(stdout, cur_rr);
			if (ldns_dname_compare(ldns_rr_owner(cur_rr),
			                       origin) != 0){
				if (last_delegation_ns) {
					ldns_rr_free(last_delegation_ns);
				}
				last_delegation_ns = cur_rr;
			} else {
				ldns_rr_free(cur_rr);
			}
		} else {
			if (last_delegation_ns) {
				if (ldns_dname_is_subdomain(ldns_rr_owner(cur_rr),
				                  ldns_rr_owner(last_delegation_ns))) {
					/* glue! don't print */
				} else {
					ldns_rr_print(stdout, cur_rr);
				}
			} else {
				ldns_rr_print(stdout, cur_rr);
			}
			ldns_rr_free(cur_rr);
		}

		status = ldns_rr_new_frm_fp(&cur_rr,
		                            input_file,
		                            &ttl,
		                            &origin,
		                            &prev_name);
	}

	if (status != LDNS_STATUS_OK &&
	    status != LDNS_STATUS_SYNTAX_EMPTY) {
		if (verbosity >= 1) {
			fprintf(stderr,
			        "Error parsing RR: %s, aborting\n",
			        ldns_get_errorstr_by_id(status));
		}
	}
	
	if (prev_name) {
		ldns_rdf_deep_free(prev_name);
	}
	if (input_file != stdin) {
		fclose(input_file);
	}
	if (last_delegation_ns) {
		ldns_rr_free(last_delegation_ns);
	}
	if (origin) {
		ldns_rdf_deep_free(origin);
	}

	return 0;
}
