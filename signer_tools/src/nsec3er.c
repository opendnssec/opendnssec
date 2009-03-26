/**
 * This tool creates NSEC3 records
 *
 * This code is provided AS-IS, you know the drill, use at own risk
 * 
 * The input must be sorted in 'NSEC3-space' (with sorter.c)
 * And empty nonterminals must be present at the right locations
 * as comments of the form '; Empty nonterminal: <domain name>'
 * 
 * Written by Jelte Jansen
 * 
 * Copyright 2008 NLnet Labs
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <ldns/ldns.h>
#include "util.h"

struct nsec3_params_struct {
	uint8_t algorithm;
	uint8_t flags;
	uint16_t iterations;
	uint8_t salt_length;
	uint8_t *salt;
};
typedef struct nsec3_params_struct nsec3_params;

nsec3_params *
nsec3_params_new()
{
	nsec3_params *n3p = malloc(sizeof(nsec3_params));
	n3p->algorithm = 1;
	n3p->flags = 0;
	n3p->iterations = 0;
	n3p->salt_length = 0;
	n3p->salt = NULL;
	return n3p;
}

void
nsec3_params_free(nsec3_params *n3p)
{
	if (n3p) {
		if (n3p->salt) {
			LDNS_FREE(n3p->salt);
		}
		LDNS_FREE(n3p);
	}
}

void
usage(FILE *out)
{
	fprintf(out, "Usage: nsec3er [options]\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-a <id>\tSpecifies the NSEC3 hashing algorithm to be used\n");
	fprintf(out, "-e\t\tDon't echo input\n");
	fprintf(out, "-f <file>\tRead RR's from file instead of stdin\n");
	fprintf(out, "-h\t\tShow this text\n");
	fprintf(out, "-n\t\tDon't echo the input records\n");
	fprintf(out, "-o\t\tname of the zone (mandatory)\n");
	fprintf(out, "-p\t\tOpt-out (NS-only sets will not get an NSEC3\n");
	fprintf(out, "-s <hex>\tUse this salt when creating hashes\n");
	fprintf(out, "-t <nr>\tUse <nr> iterations for the hash\n");
	fprintf(out, "-v <level>\tVerbosity level\n");
	fprintf(out, "\n");
	fprintf(out, "When a new owner name is read (or input stops),\n");
	fprintf(out, "an NSEC3 record is created from the previous to\n");
	fprintf(out, "the new owner name. All rr types seen with the\n");
	fprintf(out, "previous owner name are added to this new NSEC\n");
	fprintf(out, "Resource Record\n");
	fprintf(out, "These records are then printed to stdout\n");
}

/* returns 1 if there are only ns rrs in the
 * list, 0 otherwise */
int
only_ns_in_list(const ldns_rr_list *rr_list) {
	size_t i;
	if (ldns_rr_list_rr_count(rr_list) == 0) {
		return 0;
	}
	for (i=0; i<ldns_rr_list_rr_count(rr_list); i++) {
		if (ldns_rr_get_type(ldns_rr_list_rr(rr_list, i)) !=
								LDNS_RR_TYPE_NS) {
			return 0;
		}
	}
	return 1;
}

ldns_rr *
create_nsec3(ldns_rdf *name,
             ldns_rdf *origin,
             ldns_rr_list *rr_list,
             nsec3_params *n3p,
             int empty_nonterminal)
{
	ldns_rr *new_nsec3;
	new_nsec3 = ldns_create_nsec3(name,
		                          origin,
		                          rr_list,
		                          n3p->algorithm,
		                          n3p->flags,
		                          n3p->iterations,
		                          n3p->salt_length,
		                          n3p->salt,
		                          empty_nonterminal);
	return new_nsec3;
}

/* set the next hashed name of nsec3_a to the hash part of the
 * owner name of nsec3_b. If the rdata had been set already, it
 * is deep_free()'d
 */
ldns_status
link_nsec3_rrs(ldns_rr *nsec3_a, ldns_rr *nsec3_b)
{
	ldns_rdf *next_hash_rdf, *next_hash_label;
	char *next_hash_str;
	ldns_status status;

	next_hash_label = ldns_dname_label(ldns_rr_owner(nsec3_b), 0);
	next_hash_str = ldns_rdf2str(next_hash_label);
	if (next_hash_str[strlen(next_hash_str) - 1]
		== '.') {
		next_hash_str[strlen(next_hash_str) - 1]
			= '\0';
	}
	status = ldns_str2rdf_b32_ext(&next_hash_rdf, next_hash_str);
	if (ldns_rr_rdf(nsec3_a, 4)) {
		ldns_rdf_deep_free(ldns_rr_rdf(nsec3_a, 4));
	}
	if (!ldns_rr_set_rdf(nsec3_a, next_hash_rdf, 4)) {
		/* todo: error */
	}
	ldns_rdf_deep_free(next_hash_label);
	LDNS_FREE(next_hash_str);
	return status;
}

/* frees all ldns_rr records in the list, and sets the count to 0 */
void
rr_list_clear(ldns_rr_list *rr_list) {
	size_t i;
	for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
		ldns_rr_free(ldns_rr_list_rr(rr_list, i));
	}
	ldns_rr_list_set_rr_count(rr_list, 0);
}

/* if the line starts with "prefix", parse whatever comes next
 * as a domain name, and return the ldns_rdf that produces */
ldns_rdf *
get_name_from_line(const char *line, const char *prefix)
{
	ldns_rdf *name = NULL;
	size_t len, plen;
	len = strlen(line);
	plen = strlen(prefix);
	
	if (len > plen) {
		if (strncmp(line, prefix, plen) == 0) {
			name = ldns_dname_new_frm_str(line + plen);
		}
	}
	return name;
}

/* check the name, match it to the list. if the list is empty, or the
 * names are the same, add rr to the list (if exists)
 * if rr is NULL, the name is ENT or ENTNS (see ent_ns arg)
 * in which case, depending on whether opt-out is set, we should either
 * skip it or create a nonterminal
 * if names differ, create nonterminal, empty list
 * if prev_nsec is set, link nsec to new, make new the prev
 * 
 */
ldns_status
handle_name(ldns_rr *rr,
            ldns_rdf *origin,
            ldns_rr *prev_rr,
            ldns_rr_list *rr_list,
            ldns_rr **prev_nsec,
            ldns_rr **first_nsec,
            nsec3_params *n3p,
            ldns_rdf *ent_name,
            int ent_ns)
{
	ldns_rr *new_nsec;
	
	if (rr) {
		if (ldns_rr_list_rr_count(rr_list) == 0 ||
		    ldns_dname_compare(ldns_rr_owner(rr),
		                       ldns_rr_list_owner(rr_list)) == 0
		   ) {
			/* same name, or no names yet; simply add to the 'current'
			 * list and move on */
			ldns_rr_list_push_rr(rr_list, rr);
		} else {
			/* new name! do we have optout and only ns records? if
			 * not, create an nsec3. */
			ldns_rr_list_print(stdout, rr_list);
			
			if (n3p->flags & LDNS_NSEC3_VARS_OPTOUT_MASK &&
			    only_ns_in_list(rr_list)) {
				/* delegation. optout. skip. */
			} else {
				new_nsec = create_nsec3(ldns_rr_list_owner(rr_list), origin, rr_list, n3p, 0);
				if (*prev_nsec) {
					link_nsec3_rrs(*prev_nsec, new_nsec);
					ldns_rr_print(stdout, *prev_nsec);
					ldns_rr_free(*prev_nsec);
				} else {
					*first_nsec = ldns_rr_clone(new_nsec);
				}
				*prev_nsec = new_nsec;
			}
			rr_list_clear(rr_list);
			ldns_rr_list_push_rr(rr_list, rr);
		}
	} else if (ent_name) {
		if (n3p->flags & LDNS_NSEC3_VARS_OPTOUT_MASK &&
		    ent_ns) {
			/* Empty non-terminal to an unsigned delegation. skip. */
			printf(";SKIP ENT NS\n");
		} else {
			new_nsec = create_nsec3(ent_name, origin, rr_list, n3p, 1);
			if (*prev_nsec) {
				link_nsec3_rrs(*prev_nsec, new_nsec);
				ldns_rr_print(stdout, *prev_nsec);
				ldns_rr_free(*prev_nsec);
			} else {
				*first_nsec = ldns_rr_clone(new_nsec);
			}
			*prev_nsec = new_nsec;
			rr_list_clear(rr_list);
		}
	} else {
		/* apparently we have reached the end of the input, link last
		 * to first */
		if (ldns_rr_list_rr_count(rr_list) > 0 &&
		    !(n3p->flags & LDNS_NSEC3_VARS_OPTOUT_MASK &&
		      only_ns_in_list(rr_list))
		   ) {
			new_nsec = create_nsec3(ldns_rr_list_owner(rr_list),
			                        origin, rr_list, n3p, 0);
			if (*prev_nsec) {
				link_nsec3_rrs(*prev_nsec, new_nsec);
				ldns_rr_print(stdout, *prev_nsec);
				ldns_rr_free(*prev_nsec);
			} else {
				*first_nsec = ldns_rr_clone(new_nsec);
			}
			*prev_nsec = new_nsec;
			ldns_rr_list_print(stdout, rr_list);
			rr_list_clear(rr_list);
		}
		link_nsec3_rrs(*prev_nsec, *first_nsec);
		ldns_rr_print(stdout, *prev_nsec);
	}
	return LDNS_STATUS_OK;
}

ldns_status
create_nsec3_records(FILE *input_file,
                     ldns_rdf *origin,
                     nsec3_params *n3p)
{
	ldns_status status;

	/* for file reading */
	int line_len;
	char line[MAX_LINE_LEN];

	/* for tracking data on what to create */
	ldns_rr_list *rr_list;
	ldns_rr *rr;
	ldns_rr *prev_nsec = NULL;
	ldns_rr *first_nsec = NULL;
	ldns_rdf *ent_name;

	status = LDNS_STATUS_OK;
	rr_list = ldns_rr_list_new();

	line_len = 0;
	while (line_len >= 0) {
		line_len = read_line(input_file, line);
		if (line_len > 0) {
			if (line[0] != ';') {
				status = ldns_rr_new_frm_str(&rr, line, 0, origin, NULL);
				if (status == LDNS_STATUS_OK) {
					handle_name(rr, origin, NULL, rr_list,
					            &prev_nsec, &first_nsec, n3p, NULL, 0);
				} else {
					fprintf(stderr, "Error parsing RR (%s):\n; %s\n",
					        ldns_get_errorstr_by_id(status), line);
					break;
				}
			} else {
				/* This is a comment line. There are two special comment
				 * lines that may invoke action from the nseccer:
				 * ; Empty nonterminal: <name>
				 * and
				 * ; Empty nonterminal to NS: <name>
				 */
				printf("%s\n", line);
				if ((ent_name = get_name_from_line(line,
				                          "; Empty non-terminal: "))) {
					handle_name(NULL, origin, NULL, rr_list,
					            &prev_nsec, &first_nsec, n3p,
					            ent_name, 0);
					ldns_rdf_deep_free(ent_name);
				} else if ((ent_name = get_name_from_line(line,
				                     "; Empty non-terminal to NS: "))) {
					handle_name(NULL, origin, NULL, rr_list,
					            &prev_nsec, &first_nsec, n3p,
					            ent_name, 1);
					ldns_rdf_deep_free(ent_name);
				}
			}
		}
	}
	handle_name(NULL, origin, NULL, rr_list,
	            &prev_nsec, &first_nsec, n3p, NULL, 0);
	ldns_rr_list_deep_free(rr_list);
	return status;
}

int
main(int argc, char **argv)
{
	int verbosity = 5;
	int c;
	bool echo_input = true;
	FILE *input_file = stdin;

	ldns_status status = LDNS_STATUS_OK;
	ldns_rdf *origin = NULL;

	size_t iterations_cmd;
	nsec3_params *n3p;

	n3p = nsec3_params_new();
	while ((c = getopt(argc, argv, "a:ef:o:ps:t:v:")) != -1) {
		switch(c) {
			case 'a':
				n3p->algorithm = (uint8_t) atoi(optarg);
				if (n3p->algorithm != 1) {
					fprintf(stderr, "Error, only SHA1 is supported");
					fprintf(stderr, " for NSEC3 hashing\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'e':
				echo_input = false;
				break;
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
			case 'p':
				/* TODO: this is superfluous (use flags directly) */
				n3p->flags = n3p->flags | LDNS_NSEC3_VARS_OPTOUT_MASK;
				break;
			case 's':
				if (strlen(optarg) % 2 != 0) {
					fprintf(stderr,
					        "Salt value is not valid hex data, ");
					fprintf(stderr,
					        "not a multiple of 2 characters\n");
					exit(EXIT_FAILURE);
				}
				n3p->salt_length = (uint8_t) strlen(optarg) / 2;
				n3p->salt = LDNS_XMALLOC(uint8_t, n3p->salt_length);
				for (c = 0; c < (int) strlen(optarg); c += 2) {
					if (isxdigit(optarg[c]) && isxdigit(optarg[c+1])) {
						n3p->salt[c/2] = 
							(uint8_t) ldns_hexdigit_to_int(optarg[c]) *
							16 + ldns_hexdigit_to_int(optarg[c+1]);
					} else {
						fprintf(stderr,
							   "Salt value is not valid hex data.\n");
						exit(EXIT_FAILURE);
					}
				}

				break;
			case 't':
				iterations_cmd = (size_t) atol(optarg);
				if (iterations_cmd > LDNS_NSEC3_MAX_ITERATIONS) {
					fprintf(stderr, "Iterations count can not ");
					fprintf(stderr, "exceed %u, quitting\n",
					        LDNS_NSEC3_MAX_ITERATIONS);
					exit(EXIT_FAILURE);
				}
				n3p->iterations = (uint16_t) iterations_cmd;
			case 'v':
				verbosity = atoi(optarg);
				break;
			default:
				usage(stderr);
				exit(1);
				break;
		}
	}
	
	/* origin is mandatory for creating the correct nsec3 owner names
	 */
	if (!origin) {
		fprintf(stderr, "Error: no origin given to nsec3er (-o)\n");
		exit(2);
	}

	if (status != LDNS_STATUS_OK) {
		fprintf(stderr,
		        "Error in first RR: %s, aborting\n",
		        ldns_get_errorstr_by_id(status));
		exit(1);
	}
	
	/*
	 * So here's what we are going to do;
	 * Since the input data is already ordered in 'nsec3-space', we
	 * should need only to read each RR, and if they have the same owner
	 * name, add them to the 'current' list.
	 * If not, we create an NSEC3, but do not set the 'next-name' hash
	 * yet. We remember that NSEC3 and continue reading the new rrs.
	 * When we next see a new name, we create a new NSEC3 record, and
	 * set the next-name of the previously created NSEC3 record to the
	 * name of the current one.
	 *
	 * There are two special cases:
	 * When opt-out is specified, we do not create a new NSEC3 if the
	 * following conditions are true:
	 * - the current list only contains NS resource records
	 * - the current name is an empty non-terminal, AND the next name
	 *   only contains NS resource records
	 *
	 * Optional TODO:
	 * To make the output a bit more readable, if we encounter names
	 * that do not get an NSEC3, we do not print those until we finish
	 * the previous NSEC3, so we need to keep track of those too.
	 *
	 * TODO:
	 * Since NSEC3 records get the TTL from the minimum TTL value in the
	 * SOA record, and since the SOA record might not be the first RR
	 * we see, we may need to keep track of 'partial' NSEC3 rrs before
	 * we can print them.
	 */
	status = create_nsec3_records(input_file,
	                              origin,
	                              n3p);


	if (origin) {
		ldns_rdf_deep_free(origin);
	}
	nsec3_params_free(n3p);
	fclose(input_file);
	return 0;
}
