/**
 * This tool can be used to serially sign resource records sets
 *
 * It will not sign delegation NS rrsets
 * However, it has no way to tell whether something is glue,
 * so filter that out before you pass your records to this program
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <ldns/ldns.h>

void check_tm(struct tm tm)
{
	if (tm.tm_year < 70) {
		fprintf(stderr, "You cannot specify dates before 1970\n");
		exit(EXIT_FAILURE);
	}
	if (tm.tm_mon < 0 || tm.tm_mon > 11) {
		fprintf(stderr, "The month must be in the range 1 to 12\n");
		exit(EXIT_FAILURE);
	}
	if (tm.tm_mday < 1 || tm.tm_mday > 31) {
		fprintf(stderr, "The day must be in the range 1 to 31\n");
		exit(EXIT_FAILURE);
	}
	
	if (tm.tm_hour < 0 || tm.tm_hour > 23) {
		fprintf(stderr, "The hour must be in the range 0-23\n");
		exit(EXIT_FAILURE);
	}

	if (tm.tm_min < 0 || tm.tm_min > 59) {
		fprintf(stderr, "The minute must be in the range 0-59\n");
		exit(EXIT_FAILURE);
	}

	if (tm.tm_sec < 0 || tm.tm_sec > 59) {
		fprintf(stderr, "The second must be in the range 0-59\n");
		exit(EXIT_FAILURE);
	}

}

bool
is_same_rrset(ldns_rr *a, ldns_rr *b)
{
	if (!a || !b) {
		return false;
	} else if (ldns_rr_get_type(a) != ldns_rr_get_type(b)) {
		return false;
	} else if (ldns_dname_compare(ldns_rr_owner(a),
	                              ldns_rr_owner(b)) != 0) {
		return false;
	} else if (ldns_rr_ttl(a) != ldns_rr_ttl(b)) {
		return false;
	} else {
		return true;
	}
}

void
usage(FILE *out)
{
	fprintf(out, "Usage: signer [OPTIONS]\n");
	fprintf(out, "Adds RRSIG records to the read resource records sets\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-e <YYYYMMDD>[HHmmss]\tSet the expiration date on RRSIG records\n");
	fprintf(out, "-i <YYYYMMDD>[HHmmss]\tSet the inception date on RRSIG records\n");
	fprintf(out, "-f <file>\t\tRead from file instead of stdin\n");
	fprintf(out, "-n\t\t\tEcho the input\n");
	fprintf(out, "-o <origin>\t\tSet the zone name (origin). Mandatory.\n");
	fprintf(out, "-v <int>\t\tSet the verbosity level\n");
}

int
main(int argc, char **argv)
{
	/* general options */
	int verbosity = 1;
	int c;
	bool echo_input = true;
	ldns_rdf *origin = NULL;
	uint32_t ttl = LDNS_DEFAULT_TTL;
	FILE *input_file = stdin;
	
	/* key data */
	int argi;
	char *keyfile_name_base;
	char *keyfile_name;
	FILE *keyfile;
	int line_nr = 0;
	uint32_t inception = 0;
	uint32_t expiration = 0;
	ldns_key *key;
	ldns_key_list *keys = NULL;
	struct tm tm;
	
	/* internal variables */
	ldns_rr *cur_rr;
	ldns_rr *prev_rr = NULL;
	ldns_rdf *prev_name = NULL;
	ldns_rr_list *cur_rrset = NULL;
	ldns_status status;
	ldns_rr_list *sigs;

	while ((c = getopt(argc, argv, "e:i:f:hno:v:")) != -1) {
		switch(c) {
			case 'e':
				/* try to parse YYYYMMDD first,
				 * if that doesn't work, it
				 * should be a timestamp (seconds since epoch)
				 */
				memset(&tm, 0, sizeof(tm));

				if (strlen(optarg) == 8 && sscanf(optarg,
				                                  "%4d%2d%2d",
				                                  &tm.tm_year,
				                                  &tm.tm_mon,
				                                  &tm.tm_mday)) {
					tm.tm_year -= 1900;
					tm.tm_mon--;
					check_tm(tm);
					expiration = (uint32_t) mktime_from_utc(&tm);
				} else if (strlen(optarg) == 14 && sscanf(optarg,
				                                  "%4d%2d%2d%2d%2d%2d",
				                                  &tm.tm_year,
				                                  &tm.tm_mon,
				                                  &tm.tm_mday,
				                                  &tm.tm_hour,
				                                  &tm.tm_min, 
				                                  &tm.tm_sec)) {
					tm.tm_year -= 1900;
					tm.tm_mon--;
					check_tm(tm);
					expiration = (uint32_t) mktime_from_utc(&tm);
				} else {
					expiration = (uint32_t) atol(optarg);
				}
				break;
			case 'f':
				input_file = fopen(optarg, "r");
				if (!input_file) {
					fprintf(stderr,
					        "Error: unable to open %s: %s\n",
					        optarg,
					        strerror(errno));
					status = LDNS_STATUS_ERR;
					goto cleanup;
				}
				break;
			case 'h':
				usage(stdout);
				exit(0);
				break;
			case 'i':
				memset(&tm, 0, sizeof(tm));

				if (strlen(optarg) == 8 && sscanf(optarg,
				                                  "%4d%2d%2d",
				                                  &tm.tm_year,
				                                  &tm.tm_mon,
				                                  &tm.tm_mday)) {
					tm.tm_year -= 1900;
					tm.tm_mon--;
					check_tm(tm);
					inception = (uint32_t) mktime_from_utc(&tm);
				} else if (strlen(optarg) == 14 && sscanf(optarg,
				                                  "%4d%2d%2d%2d%2d%2d",
				                                  &tm.tm_year,
				                                  &tm.tm_mon,
				                                  &tm.tm_mday,
				                                  &tm.tm_hour,
				                                  &tm.tm_min,
				                                  &tm.tm_sec)) {
					tm.tm_year -= 1900;
					tm.tm_mon--;
					check_tm(tm);
					inception = (uint32_t) mktime_from_utc(&tm);
				} else {
					inception = (uint32_t) atol(optarg);
				}
				break;
			case 'n':
				echo_input = false;
				break;
			case 'v':
				verbosity = atoi(optarg);
				break;
			case 'o':
				origin = ldns_dname_new_frm_str(optarg);
				break;
		}
	}
	
	argc -= optind;
	argv += optind;

	if (!origin) {
		fprintf(stderr, "Error: bad or no origin specified\n");
		status = LDNS_STATUS_ERR;
		goto cleanup;
	}

	/* read the keys */
	keys = ldns_key_list_new();
	argi = 0;
	while (argi < argc) {
		keyfile_name_base = argv[argi];
		keyfile_name = LDNS_XMALLOC(char, strlen(keyfile_name_base) + 9);
		snprintf(keyfile_name,
			    strlen(keyfile_name_base) + 9,
			    "%s.private",
			    keyfile_name_base);
		keyfile = fopen(keyfile_name, "r");
		line_nr = 0;
		if (!keyfile) {
			fprintf(stderr,
				   "Error: unable to read %s: %s\n",
				   keyfile_name,
				   strerror(errno));
		} else {
			status = ldns_key_new_frm_fp_l(&key, keyfile, &line_nr);
			fclose(keyfile);
			if (status == LDNS_STATUS_OK) {
				/* set times in key? they will end up
				   in the rrsigs
				*/
				if (expiration != 0) {
					ldns_key_set_expiration(key, expiration);
				}
				if (inception != 0) {
					ldns_key_set_inception(key, inception);
				}
				ldns_key_set_pubkey_owner(key, ldns_rdf_clone(origin));

				ldns_key_list_push_key(keys, key);

				LDNS_FREE(keyfile_name);
			}
		}
		argi++;
	}
	if (ldns_key_list_key_count(keys) == 0) {
		fprintf(stderr, "No keys to sign with, aborting\n");
		status = LDNS_STATUS_ERR;
		goto cleanup;
	}
	
	/* Parse mode: read rrs from stdin */
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
		goto cleanup;
	}
	
	cur_rrset = ldns_rr_list_new();
	prev_rr = cur_rr;
	
	while (status == LDNS_STATUS_OK) {
		if (is_same_rrset(prev_rr, cur_rr)) {
			ldns_rr_list_push_rr(cur_rrset, cur_rr);
		} else {
			/* handle rrset */
			if (echo_input) {
				ldns_rr_list_print(stdout, cur_rrset);
			}
			
			/* sign and print sigs */
			if (verbosity >= 5) {
				fprintf(stderr,
				        "INFO: signing %u records\n",
				        ldns_rr_list_rr_count(cur_rrset)
				       );
			}
			if (ldns_rr_get_type(prev_rr) != LDNS_RR_TYPE_NS ||
			    ldns_dname_compare(ldns_rr_owner(prev_rr), origin) == 0) {
				sigs = ldns_sign_public(cur_rrset, keys);
				ldns_rr_list_print(stdout, sigs);
				ldns_rr_list_deep_free(sigs);
			}
			
			/* clean for next set */
			ldns_rr_list_deep_free(cur_rrset);
			cur_rrset = ldns_rr_list_new();
			ldns_rr_list_push_rr(cur_rrset, cur_rr);
		}

		prev_rr = cur_rr;
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
			fprintf(stderr,
			        "Last RR sucessfully read: ");
			ldns_rr_print(stderr, prev_rr);
			goto cleanup;
		}
	}

	if (cur_rrset && ldns_rr_list_rr_count(cur_rrset) > 0) {
		if (echo_input) {
			ldns_rr_list_print(stdout, cur_rrset);
		}
		
		/* sign and print sigs */
		if (verbosity >= 5) {
			fprintf(stderr,
					"INFO: signing %u records\n",
					ldns_rr_list_rr_count(cur_rrset)
				   );
		}
		if (ldns_rr_get_type(prev_rr) != LDNS_RR_TYPE_NS ||
			ldns_dname_compare(ldns_rr_owner(prev_rr), origin) == 0) {
			sigs = ldns_sign_public(cur_rrset, keys);
			ldns_rr_list_print(stdout, sigs);
			ldns_rr_list_deep_free(sigs);
		}
	}
	
	cleanup:
	if (origin) {
		ldns_rdf_deep_free(origin);
	}
	if (keys) {
		ldns_key_list_free(keys);
	}
	if (cur_rrset) {
		ldns_rr_list_deep_free(cur_rrset);
	}
	if (prev_name) {
		ldns_rdf_deep_free(prev_name);
	}
	if (input_file != stdin) {
		fclose(input_file);
	}
	return status;
}
