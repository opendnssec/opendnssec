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
	uint32_t refresh;
	uint32_t jitter;
	int echo_input;
	ldns_pkcs11_module_list *pkcs11_module_list;
	ldns_key_list *keys;
	
	/* settings for SOA values that are changed */
	uint32_t soa_ttl;
	uint32_t soa_serial;
	uint32_t soa_minimum;
	
	/* and let's keep some statistics */
	unsigned long existing_sigs;
	unsigned long removed_sigs;
	unsigned long created_sigs;
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
		/* ctx is freed by ldns_finalize_pkcs11() (which is
		 * automatically called by current_config_free() */
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
	cfg->refresh = 0;
	cfg->jitter = 0;
	cfg->echo_input = 0;
	cfg->origin = NULL;
	cfg->pkcs11_module_list = ldns_pkcs11_module_list_entry_new();
	cfg->keys = ldns_key_list_new();
	cfg->soa_ttl = 0;
	cfg->soa_serial = 0;
	cfg->soa_minimum = 0;
	cfg->existing_sigs = 0;
	cfg->removed_sigs = 0;
	cfg->created_sigs = 0;
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
	end = strchr(str, ' ');
	if (!end) {
		end = strchr(str, '\t');
	}
	if (!end) {
		end = strchr(str, '\n');
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
add_key(FILE *output,
        current_config *cfg,
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
		fprintf(output, "; Error: no signer context, or origin not set\n");
		return LDNS_STATUS_ERR;
	}
	
	key_algorithm = atoi(key_algorithm_str);
	if (key_algorithm == 0) {
		/* TODO: check for unknown algo's too? */
		fprintf(output, "; Error: Bad algorithm: %s\n", key_algorithm_str);
		return LDNS_STATUS_ERR;
	}
	
	key_flags = atoi(key_flags_str);
	if (key_flags <= 0 || key_flags > 65535) {
		fprintf(output, "; Error: bad key flags: %s\n", key_flags_str);
		return LDNS_STATUS_ERR;
	}
	
	pkcs11_ctx = ldns_find_pkcs11_ctx(token_name, cfg->pkcs11_module_list);
	if (!pkcs11_ctx) {
		fprintf(output, "; Error: could not find PKCS11 token '%s' for key '%s'\n", token_name, key_id_str);
		fprintf(output, "; Has it been added to the rrset signer with :add_module?\n");
		debug_print_modules(output, "; module", cfg->pkcs11_module_list);
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
		fprintf(output, "; Error reading key %s in token %s\n", key_id_str, token_name);
		status = LDNS_STATUS_ERR;
	}
	
	free(key_id);
	
	return status;
}

ldns_status
handle_command(FILE *output, current_config *cfg,
               const char *line, int line_len)
{
	char *cmd;
	char *arg1 = NULL, *arg2 = NULL, *arg3 = NULL, *arg4 = NULL;
	char *next;
	ldns_status result = LDNS_STATUS_OK;
	
	cmd = read_arg(line, &next);
	if (!cmd) {
		return LDNS_STATUS_ERR;
	}
	if (strcmp(cmd, "add_module") == 0) {
		arg1 = read_arg(next, &next);
		arg2 = read_arg(next, &next);
		arg3 = read_arg(next, &next);
		if (!arg1 || !arg2 || !arg3) {
			fprintf(output, "; Error: missing argument in add_module command\n");
		} else {
			result = ldns_pkcs11_module_add(cfg->pkcs11_module_list,
			                                arg1, arg2, arg3);
			if (result != LDNS_STATUS_OK) {
				fprintf(output, "; Error adding token '%s'\n", arg1);
			}
		}
	} else if (strcmp(cmd, "del_module") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in add_module command\n");
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
			fprintf(output, "; Error: missing argument in add_key command\n");
		} else {
			result = add_key(output, cfg, arg1, arg2, arg3, arg4);
		}
	} else if (strcmp(cmd, "flush_keys") == 0) {
		ldns_key_list_free(cfg->keys);
		cfg->keys = ldns_key_list_new();
	} else if (strcmp(cmd, "inception") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in inception command\n");
		} else {
			cfg->inception = parse_time(arg1);
		}
	} else if (strcmp(cmd, "expiration") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in expiration command\n");
		} else {
			cfg->expiration = parse_time(arg1);
		}
	} else if (strcmp(cmd, "jitter") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in jitter command\n");
		} else {
			cfg->jitter = atol(arg1);
		}
	} else if (strcmp(cmd, "refresh") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in refresh command\n");
		} else {
			cfg->refresh = parse_time(arg1);
		}
	} else if (strcmp(cmd, "origin") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in inception command\n");
		} else {
			if (cfg->origin) {
				ldns_rdf_deep_free(cfg->origin);
			}
			result = ldns_str2rdf_dname(&cfg->origin, arg1);
		}
	} else if (strcmp(cmd, "soa_ttl") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in soa_ttl command\n");
		} else {
			cfg->soa_ttl = atol(arg1);
		}
	} else if (strcmp(cmd, "soa_serial") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in soa_serial command\n");
		} else {
			cfg->soa_serial = atol(arg1);
		}
	} else if (strcmp(cmd, "soa_minimum") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in soa_minimum command\n");
		} else {
			cfg->soa_minimum = atol(arg1);
		}
	} else if (strcmp(cmd, "stop") == 0) {
		result = LDNS_STATUS_NULL;
	} else {
		fprintf(output, "; Error: unknown command: %s\n", cmd);
	}
	if (arg1) free(arg1);
	if (arg2) free(arg2);
	if (arg3) free(arg3);
	if (arg4) free(arg4);
	free(cmd);
	return result;
}

void
enable_keys(current_config *cfg)
{
	size_t i;
	for (i = 0; i < ldns_key_list_key_count(cfg->keys); i++) {
		ldns_key_set_use(ldns_key_list_key(cfg->keys, i), 1);
	}
}

void
set_use_key_for(current_config *cfg, ldns_rr *rrsig, int use)
{
	size_t i;
	ldns_key *key;
	/* let's assume for now that name etc are right, and only check
	 * keytag (TODO)*/
	for (i = 0; i < ldns_key_list_key_count(cfg->keys); i++) {
		key = ldns_key_list_key(cfg->keys, i);
		if (ldns_key_keytag(key) == ldns_rdf2native_int16(ldns_rr_rrsig_keytag(rrsig))) {
			ldns_key_set_use(key, use);
			return;
		}
	}
}

void
disable_key_for(current_config *cfg, ldns_rr *rrsig)
{
		set_use_key_for(cfg, rrsig, 0);
}

void
enable_key_for(current_config *cfg, ldns_rr *rrsig)
{
		set_use_key_for(cfg, rrsig, 1);
}

void
update_jitter(current_config *cfg) {
	size_t i;
	for (i = 0; i < ldns_key_list_key_count(cfg->keys); i++) {
		ldns_key_set_expiration(ldns_key_list_key(cfg->keys, i),
		                        cfg->expiration + rand() % cfg->jitter);
	}
}

int main(int argc, char **argv)
{
	current_config *cfg;
	char line[MAX_LINE_LEN];
	int line_len;
	int c;
	FILE *input;
	FILE *output;
	bool echo_input = true;
	uint32_t ttl = LDNS_DEFAULT_TTL;
	
	ldns_rr *cur_rr = NULL;
	ldns_rr *prev_rr = NULL;
	ldns_rdf *prev_name = NULL;
	ldns_rr_list *cur_rrset;
	ldns_rr_list *old_sigs;
	ldns_status status;
	ldns_rr_list *sigs;
	ldns_status cmd_res;
	
	int verbosity = 1;

	memset(line, 0, MAX_LINE_LEN);
	cfg = current_config_new();
	input = stdin;
	output = stdout;

	while ((c = getopt(argc, argv, "f:hnw:")) != -1) {
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
		case 'n':
			echo_input = false;
			break;
		case 'w':
			output = fopen(optarg, "w");
			if (!output) {
				fprintf(stderr,
						"Error: unable to open %s for writing: %s\n",
						optarg,
						strerror(errno));
				exit(1);
			}
			break;
		}
	}

	cur_rrset = ldns_rr_list_new();
	old_sigs = ldns_rr_list_new();
	prev_rr = cur_rr;

	enable_keys(cfg);
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
				if (line_len > 15 && strncmp(line, "; Last refresh stats: ", 15) == 0) {
					/* except stats */
				} else if (line_len > 8 && strncmp(line, "; Error ", 8) == 0) {
					/* and previous errors */
				} else {
					fprintf(output, "%s\n", line);
				}
			} else if (line[0] == ':') {
				cmd_res = handle_command(output, cfg, line + 1,
				                         line_len - 1);
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
				if (status == LDNS_STATUS_OK && cur_rr &&
				    ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_SOA) {
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
						/* sign and print sigs */
						if (verbosity >= 5) {
							fprintf(stderr,
									"INFO: signing %u records\n",
									(unsigned int) ldns_rr_list_rr_count(cur_rrset)
								   );
						}
						if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_RRSIG) {
							/* if refresh is zero, we just drop existing
							 * signatures. Otherwise, we'll have to check
							 * them and mark which keys should still be used
							 * to create new ones
							 * 
							 * *always* update SOA RRSIG
							 */
							cfg->existing_sigs++;
							if (cfg->refresh != 0 || ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(cur_rr)) == LDNS_RR_TYPE_SOA) {
								if (ldns_rdf2native_int32(ldns_rr_rrsig_expiration(cur_rr)) < cfg->refresh ||
								    ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(cur_rr)) == LDNS_RR_TYPE_SOA) {
									/* ok, drop sig, resign */
									enable_key_for(cfg, cur_rr);
									cfg->removed_sigs++;
								} else {
									/* leave sig, disable key */
									ldns_rr_list_push_rr(old_sigs, cur_rr);
									disable_key_for(cfg, cur_rr);
								}
							}
						} else {
							/* handle rrset */
							if (echo_input) {
								ldns_rr_list_print(output, cur_rrset);
								ldns_rr_list_print(output, old_sigs);
							}
							
							if (ldns_rr_get_type(prev_rr) != LDNS_RR_TYPE_NS ||
								ldns_dname_compare(ldns_rr_owner(prev_rr), cfg->origin) == 0) {
								if (cfg->jitter) {
									update_jitter(cfg);
								}
								sigs = ldns_pkcs11_sign_rrset(cur_rrset, cfg->keys);
								cfg->created_sigs += ldns_rr_list_rr_count(sigs);
								ldns_rr_list_print(output, sigs);
								ldns_rr_list_deep_free(sigs);
								(void)sigs;
								enable_keys(cfg);
							}
							/* clean for next set */
							ldns_rr_list_deep_free(cur_rrset);
							cur_rrset = ldns_rr_list_new();
							ldns_rr_list_push_rr(cur_rrset, cur_rr);
							ldns_rr_list_deep_free(old_sigs);
							old_sigs = ldns_rr_list_new();
							prev_rr = cur_rr;
						}
					}
				} else {
					prev_rr = cur_rr;
					ldns_rr_list_push_rr(cur_rrset, cur_rr);
				}
			}
		}
	}
	done:
	if (cur_rrset && ldns_rr_list_rr_count(cur_rrset) > 0) {
		if (echo_input) {
			ldns_rr_list_print(output, cur_rrset);
			ldns_rr_list_print(output, old_sigs);
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
			cfg->created_sigs += ldns_rr_list_rr_count(sigs);
			ldns_rr_list_print(output, sigs);
			ldns_rr_list_deep_free(sigs);
		}
	}
	
	fprintf(output, "; Last refresh stats: existing: %lu, removed %lu, created %lu\n",
	        cfg->existing_sigs,
	        cfg->removed_sigs,
	        cfg->created_sigs);

	current_config_free(cfg);
	if (input != stdin) {
		fclose(input);
	}
	if (output != stdout) {
		fclose(output);
	}
	return 0;
}
