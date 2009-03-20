/**
 * This tool can be used to serially sign resource records sets
 *
 * It will not sign delegation NS rrsets
 * However, it has no way to tell whether something is glue,
 * so filter that out before you pass your records to this program
 * (TODO: read glue from inline comments and print them out as 'normal'
 * records)
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <strings.h>

#include <ldns/ldns.h>

#include "ldns_pkcs11.h"
#include "util.h"

typedef struct ldns_pkcs11_module_list_struct ldns_pkcs11_module_list;
struct ldns_pkcs11_module_list_struct {
	char *name;
	ldns_pkcs11_ctx *ctx;
	ldns_pkcs11_module_list *next;
};

struct current_config_struct {
	/* general current settings */
	ldns_rdf *origin;

	/* settings for signatures that are generated */
	uint32_t inception;
	uint32_t expiration;
	int echo_input;
	ldns_pkcs11_module_list *pkcs11_module_list;
	ldns_key_list *keys;
	
	/* settings for SOA values that are changed */
	uint32_t soa_ttl;
	uint32_t soa_serial;
	uint32_t soa_minimum;
};
typedef struct current_config_struct current_config;

ldns_pkcs11_module_list *
ldns_pkcs11_module_list_entry_new()
{
	ldns_pkcs11_module_list *mle = malloc(sizeof(ldns_pkcs11_module_list));
	mle->name = NULL;
	mle->ctx = NULL;
	mle->next = NULL;
	return mle;
}

void
ldns_pkcs11_module_list_free(ldns_pkcs11_module_list *mle)
{
	if (mle) {
		if (mle->name) {
			free(mle->name);
		}
		/* ctx is freed by finalize() */
	}
	free(mle);
}

/* if no module with the given name is present in the current list,
 * create a new one, and initialize it
 */
ldns_status
ldns_pkcs11_module_add(ldns_pkcs11_module_list *list,
                       const char *name,
                       const char *module_path,
                       const char *pin)
{
	ldns_pkcs11_module_list *mle, *new_mle;

	if (!name || !module_path || !pin) {
		return LDNS_STATUS_ERR;
	}
	mle = list;
	while (mle->name) {
		if (strcmp(name, mle->name) == 0) {
			/* same name, just return ok (if you want to change the
			 * settings for a module, remove and readd it */
			return LDNS_STATUS_OK;
		}
		/* different name, try next */
		if (mle->next) {
			mle = mle->next;
		} else {
			/* we are at end, create new module list entry */
			new_mle = ldns_pkcs11_module_list_entry_new();
			mle->next = new_mle;
			mle = new_mle;
		}
	}
	/* ok we are at end and haven't found the module yet */
	mle->name = strdup(name);
	mle->ctx = ldns_initialize_pkcs11(module_path, name, pin);
	if (mle->ctx) {
		return LDNS_STATUS_OK;
	} else {
		return LDNS_STATUS_ERR;
	}
}



/* returns the first entry of the modified list 
 * (in case the entry to remove it the first one)
 */
ldns_pkcs11_module_list *
ldns_pkcs11_module_remove(ldns_pkcs11_module_list *list,
                          const char *name)
{
	ldns_pkcs11_module_list *mle, *mle_prev, *first;
	
	if (!name) {
		return list;
	}

	mle_prev = NULL;
	first = list;
	mle = list;
	while (mle) {
		if (strcmp(name, mle->name) == 0) {
			if (mle_prev) {
				mle_prev->next = mle->next;
			} else {
				first = mle->next;
			}
			/* finalize ctx and remove */
			ldns_finalize_pkcs11(mle->ctx);
			ldns_pkcs11_module_list_free(mle);
		} else {
			mle_prev = mle;
			mle = mle->next;
		}
	}
	return first;
}

ldns_pkcs11_ctx *
ldns_find_pkcs11_ctx(const char *name, ldns_pkcs11_module_list *mle)
{
	while (mle) {
		if (name && mle->name && strcmp(name, mle->name) == 0) {
			return mle->ctx;
		} else {
			mle = mle->next;
		}
	}
	return NULL;
}

current_config *
current_config_new()
{
	current_config *cfg = malloc(sizeof(current_config));
	cfg->inception = 0;
	cfg->expiration = 0;
	cfg->echo_input = 0;
	cfg->origin = NULL;
	cfg->pkcs11_module_list = ldns_pkcs11_module_list_entry_new();
	cfg->keys = ldns_key_list_new();
	cfg->soa_ttl = 0;
	cfg->soa_serial = 0;
	cfg->soa_minimum = 0;
	return cfg;
}

void
current_config_free(current_config *cfg)
{
	ldns_pkcs11_module_list *mle, *next;
	if (cfg) {
		if (cfg->origin) {
			ldns_rdf_deep_free(cfg->origin);
		}
		if (cfg->pkcs11_module_list) {
			mle = cfg->pkcs11_module_list;
			while (mle) {
				ldns_finalize_pkcs11(mle->ctx);
				next = mle->next;
				ldns_pkcs11_module_list_free(mle);
				mle = next;
			}
		}
		ldns_key_list_free(cfg->keys);
		free(cfg);
	}
}

void
usage(FILE *out)
{
	fprintf(out, "Usage: signer_pkcs11 [OPTIONS]\n");
	fprintf(out, "Adds RRSIG records to the read resource records sets with PKCS11\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-f <file>\t\tRead from file instead of stdin\n");
	fprintf(out, "-h\t\t\tShow this help\n");
}

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

char *
read_arg(const char *str, char **next)
{
	char *result = NULL;
	char *end;

	if (!str) {
		*next = NULL;
		return result;
	}
	end = index(str, ' ');
	if (!end) {
		end = index(str, '\t');
	}
	if (!end) {
		end = index(str, '\n');
	}
	if (end) {
		result = malloc(end - str + 1);
		memcpy(result, str, end - str);
		result[end - str] = '\0';
		*next = end + 1;
	} else {
		if (strlen > 0) {
			result = strdup(str);
			*next = NULL;
		}
	}
	
	return result;
}

uint32_t
parse_time (const char *time_str)
{
	struct tm tm;
	uint32_t result = 0;
	/* try to parse YYYYMMDD first,
	* if that doesn't work, it
	* should be a timestamp (seconds since epoch)
	*/
	memset(&tm, 0, sizeof(tm));

	if (strlen(time_str) == 8 && sscanf(time_str,
								  "%4d%2d%2d",
								  &tm.tm_year,
								  &tm.tm_mon,
								  &tm.tm_mday)) {
		tm.tm_year -= 1900;
		tm.tm_mon--;
		check_tm(tm);
		result = (uint32_t) mktime_from_utc(&tm);
	} else if (strlen(time_str) == 14 && sscanf(time_str,
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
		result = (uint32_t) mktime_from_utc(&tm);
	}
	return result;
}

void
debug_print_modules(FILE *out, const char *prefix, ldns_pkcs11_module_list *list)
{
	ldns_pkcs11_module_list *elm = list;
	while (elm) {
		fprintf(out, "%s %s\n", prefix, list->name);
		elm = elm->next;
	}
}

ldns_status
add_key(current_config *cfg,
        const char *token_name,
        const char *key_id_str,
        const char *key_algorithm_str,
        const char *key_flags_str)
{
	ldns_pkcs11_ctx *pkcs11_ctx;
	ldns_algorithm key_algorithm;
	unsigned char *key_id;
	int key_id_len;
	ldns_status status;
	ldns_key *key;
	int key_flags;
	
	if (!cfg || !cfg->origin) {
		printf("; Error: no signer context, or origin not set\n");
		return LDNS_STATUS_ERR;
	}
	
	key_algorithm = atoi(key_algorithm_str);
	if (key_algorithm == 0) {
		/* TODO: check for unknown algo's too? */
		fprintf(stdout, "; Error: Bad algorithm: %s\n", key_algorithm_str);
		return LDNS_STATUS_ERR;
	}
	
	key_flags = atoi(key_flags_str);
	if (key_flags <= 0 || key_flags > 65535) {
		fprintf(stdout, "; Error: bad key flags: %s, defaulting to 256\n", key_flags_str);
		return LDNS_STATUS_ERR;
	}
	
	pkcs11_ctx = ldns_find_pkcs11_ctx(token_name, cfg->pkcs11_module_list);
	if (!pkcs11_ctx) {
		printf("; Error: could not find PKCS11 token '%s' for key '%s'\n", token_name, key_id_str);
		printf("; Has it been added to the rrset signer with :add_module?\n");
		debug_print_modules(stdout, "; module", cfg->pkcs11_module_list);
		return LDNS_STATUS_ERR;
	}
	
	key_id = ldns_keystr2id(key_id_str, &key_id_len);

	status = ldns_key_new_frm_pkcs11(pkcs11_ctx,
									 &key,
									 key_algorithm,
									 (uint16_t) key_flags,
									 key_id,
									 key_id_len);
	if (status == LDNS_STATUS_OK) {
		/* set times in key? they will end up
		   in the rrsigs
		*/
		if (cfg->expiration != 0) {
			ldns_key_set_expiration(key, cfg->expiration);
		}
		if (cfg->inception != 0) {
			ldns_key_set_inception(key, cfg->inception);
		}
		ldns_key_set_pubkey_owner(key, ldns_rdf_clone(cfg->origin));

		ldns_key_list_push_key(cfg->keys, key);
	} else {
		printf("; Error reading key %s in token %s\n", key_id_str, token_name);
		status = LDNS_STATUS_ERR;
	}
	
	free(key_id);
	
	return status;
}

ldns_status
handle_command(current_config *cfg, const char *line, int line_len)
{
	char *cmd;
	char *arg1 = NULL, *arg2 = NULL, *arg3 = NULL, *arg4 = NULL;
	char *next;
	ldns_status result = LDNS_STATUS_OK;
	
	cmd = read_arg(line, &next);
	if (strcmp(cmd, "add_module") == 0) {
		arg1 = read_arg(next, &next);
		arg2 = read_arg(next, &next);
		arg3 = read_arg(next, &next);
		if (!arg1 || !arg2 || !arg3) {
			fprintf(stdout, "; Error: missing argument in add_module command\n");
		} else {
			result = ldns_pkcs11_module_add(cfg->pkcs11_module_list,
			                                arg1, arg2, arg3);
			if (result != LDNS_STATUS_OK) {
				fprintf(stdout, "; Error adding token '%s'\n", arg1);
			}
		}
	} else if (strcmp(cmd, "del_module") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(stdout, "; Error: missing argument in add_module command\n");
		} else {
			cfg->pkcs11_module_list = ldns_pkcs11_module_remove(
			                               cfg->pkcs11_module_list,
			                               arg1);
		}
	} else if (strcmp(cmd, "add_key") == 0) {
		arg1 = read_arg(next, &next);
		arg2 = read_arg(next, &next);
		arg3 = read_arg(next, &next);
		arg4 = read_arg(next, &next);
		if (!arg1 || !arg2 || !arg3 || !arg4) {
			fprintf(stdout, "; Error: missing argument in add_key command\n");
		} else {
			result = add_key(cfg, arg1, arg2, arg3, arg4);
		}
	} else if (strcmp(cmd, "flush_keys") == 0) {
		ldns_key_list_free(cfg->keys);
		cfg->keys = ldns_key_list_new();
	} else if (strcmp(cmd, "inception") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(stdout, "; Error: missing argument in inception command\n");
		} else {
			cfg->inception = parse_time(arg1);
		}
	} else if (strcmp(cmd, "expiration") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(stdout, "; Error: missing argument in expiration command\n");
		} else {
			cfg->expiration = parse_time(arg1);
		}
	} else if (strcmp(cmd, "origin") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(stdout, "; Error: missing argument in inception command\n");
		} else {
			if (cfg->origin) {
				ldns_rdf_deep_free(cfg->origin);
			}
			result = ldns_str2rdf_dname(&cfg->origin, arg1);
		}
	} else if (strcmp(cmd, "soa_ttl") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(stdout, "; Error: missing argument in soa_ttl command\n");
		} else {
			cfg->soa_ttl = atol(arg1);
		}
	} else if (strcmp(cmd, "soa_serial") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(stdout, "; Error: missing argument in soa_serial command\n");
		} else {
			cfg->soa_serial = atol(arg1);
		}
	} else if (strcmp(cmd, "soa_minimum") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(stdout, "; Error: missing argument in soa_minimum command\n");
		} else {
			cfg->soa_minimum = atol(arg1);
		}
	} else if (strcmp(cmd, "stop") == 0) {
		result = LDNS_STATUS_NULL;
	} else {
		printf("; Error: unknown command: %s\n", cmd);
	}
	if (arg1) free(arg1);
	if (arg2) free(arg2);
	if (arg3) free(arg3);
	free(cmd);
	return result;
}

int main(int argc, char **argv)
{
	current_config *cfg;
	char line[MAX_LINE_LEN];
	int line_len;
	int c;
	FILE *input;
	bool echo_input = true;
	uint32_t ttl = LDNS_DEFAULT_TTL;
	
	ldns_rr *cur_rr;
	ldns_rr *prev_rr = NULL;
	ldns_rdf *prev_name = NULL;
	ldns_rr_list *cur_rrset;
	ldns_status status;
	ldns_rr_list *sigs;
	ldns_status cmd_res;
	
	int verbosity = 1;

	memset(line, 0, MAX_LINE_LEN);
	cfg = current_config_new();
	input = stdin;

	while ((c = getopt(argc, argv, "f:h")) != -1) {
		switch(c) {
		case 'f':
			input = fopen(optarg, "r");
			if (!input) {
				fprintf(stderr,
						"Error: unable to open %s: %s\n",
						optarg,
						strerror(errno));
				exit(1);
			}
			break;
		case 'h':
			usage(stdout);
			exit(0);
			break;
		}
	}

	cur_rrset = ldns_rr_list_new();
	prev_rr = cur_rr;

	line_len = 0;
	while (line_len >= 0) {
		line_len = read_line(input, line);
		/* four cases:
		 * - line is a comment (starts with ;)
		 * - line is a command (starts with :)
		 * - line is an RR or empty (otherwise)
		 */
		if (line_len > 0) {
			if (line[0] == ';') {
				/* pass comments */
				fprintf(stdout, "%s\n", line);
			} else if (line[0] == ':') {
				cmd_res = handle_command(cfg, line + 1, line_len - 1);
				if (cmd_res == LDNS_STATUS_NULL) {
					goto done;
				}
			} else {
				/* read RR, gather rrset, etc, see old main */
				status = ldns_rr_new_frm_str(&cur_rr,
											line,
											ttl,
											cfg->origin,
											&prev_name);
				if (cur_rr && ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_SOA) {
					if (cfg->soa_ttl != 0) {
						ldns_rr_set_ttl(cur_rr, cfg->soa_ttl);
					}
					if (cfg->soa_serial != 0) {
						ldns_rdf_deep_free(ldns_rr_rdf(cur_rr, 2));
						ldns_rr_set_rdf(cur_rr,
										ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32,
															  cfg->soa_serial),
										2);
					}
					if (cfg->soa_minimum != 0) {
						ldns_rdf_deep_free(ldns_rr_rdf(cur_rr, 6));
						ldns_rr_set_rdf(cur_rr,
										ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32,
															  cfg->soa_minimum),
										6);
					}
				}
				if (prev_rr) {
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
									(unsigned int) ldns_rr_list_rr_count(cur_rrset)
								   );
						}
						if (ldns_rr_get_type(prev_rr) != LDNS_RR_TYPE_NS ||
							ldns_dname_compare(ldns_rr_owner(prev_rr), cfg->origin) == 0) {
							sigs = ldns_pkcs11_sign_rrset(cur_rrset, cfg->keys);
							ldns_rr_list_print(stdout, sigs);
							ldns_rr_list_deep_free(sigs);
							(void)sigs;
						}
						
						/* clean for next set */
						ldns_rr_list_deep_free(cur_rrset);
						cur_rrset = ldns_rr_list_new();
						ldns_rr_list_push_rr(cur_rrset, cur_rr);
					}
				}
				prev_rr = cur_rr;
			}
		}
	}
	done:
	if (cur_rrset && ldns_rr_list_rr_count(cur_rrset) > 0) {
		if (echo_input) {
			ldns_rr_list_print(stdout, cur_rrset);
		}
		
		/* sign and print sigs */
		if (verbosity >= 5) {
			fprintf(stderr,
					"INFO: signing %u records\n",
					(unsigned int) ldns_rr_list_rr_count(cur_rrset)
				   );
		}
		if (ldns_rr_get_type(prev_rr) != LDNS_RR_TYPE_NS ||
			ldns_dname_compare(ldns_rr_owner(prev_rr), cfg->origin) == 0) {
			sigs = ldns_pkcs11_sign_rrset(cur_rrset, cfg->keys);
			ldns_rr_list_print(stdout, sigs);
			ldns_rr_list_deep_free(sigs);
		}
	}

	current_config_free(cfg);
	if (input != stdin) {
		fclose(input);
	}
	return 0;
}
