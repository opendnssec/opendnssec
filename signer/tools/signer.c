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
#include <syslog.h>

#include <ldns/ldns.h>

#include "logging.h"
#include "util.h"
#include <libhsm.h>
#include <libhsmdns.h>

typedef struct {
	ldns_rr *skipped_rr;
	FILE *file;
} rrset_reader_t;

typedef struct {
	hsm_key_t **keys;
	uint16_t *keytags;
	uint16_t *flags;
	uint8_t *algorithms;
	int *use_key;
	size_t key_count;
	size_t capacity;
} key_list;

typedef struct {
	/* general current settings */
	ldns_rdf *origin;

	/* settings for signatures that are generated */
	uint32_t inception;
	uint32_t expiration;
	uint32_t expiration_denial;
	uint32_t refresh;
	uint32_t refresh_denial;
	uint32_t jitter;
	int echo_input;
	/*ldns_pkcs11_module_list *pkcs11_module_list;*/
	key_list *zsks;
	key_list *ksks;

	/* settings for SOA values that are changed */
	int cfg_soa_ttl;
	int cfg_soa_minimum;

	uint32_t soa_ttl;
	uint32_t soa_serial;
	uint32_t soa_serial_keep;
	uint32_t soa_minimum;

	/* settings for NSEC3 if used */
	uint32_t nsec3_algorithm;
	uint32_t nsec3_iterations;
	char* nsec3_salt;

	/* and let's keep some statistics */
	unsigned long existing_sigs;
	unsigned long removed_sigs;
	unsigned long created_sigs;

	int verbosity;
} current_config;

current_config* global_cfg = NULL;

key_list *
key_list_new()
{
	key_list *list;
	list = malloc(sizeof(key_list));
	if (!list) {
		fprintf(stderr,
		        "Out of memory while creating key list, aborting\n");
		exit(1);
	}
	list->capacity = 10;
	list->key_count = 0;
	list->keys = malloc(sizeof(hsm_key_t *) * list->capacity);
	if (!list->keys) {
		fprintf(stderr,
		        "Out of memory while creating key list, aborting\n");
		exit(1);
	}
	list->keytags = malloc(sizeof(uint16_t) * list->capacity);
	if (!list->keytags) {
		fprintf(stderr,
		        "Out of memory while creating key list, aborting\n");
		exit(1);
	}
	list->flags = malloc(sizeof(uint16_t) * list->capacity);
	if (!list->flags) {
		fprintf(stderr,
		        "Out of memory while creating key list, aborting\n");
		exit(1);
	}
	list->algorithms = malloc(sizeof(uint8_t) * list->capacity);
	if (!list->algorithms) {
		fprintf(stderr,
		        "Out of memory while creating key list, aborting\n");
		exit(1);
	}
	list->use_key = malloc(sizeof(int) * list->capacity);
	if (!list->use_key) {
		fprintf(stderr,
		        "Out of memory while creating key list, aborting\n");
		exit(1);
	}
	return list;
}

void
key_list_free(key_list *list)
{
	if (list->keys) free(list->keys);
	if (list->keytags) free(list->keytags);
	if (list->flags) free(list->flags);
	if (list->algorithms) free(list->algorithms);
	if (list->use_key) free(list->use_key);
	free(list);
}

void
key_list_add_key(key_list *list,
                 const char *key_id,
                 const char *key_algorithm_str,
                 const char *key_flags_str,
                 const current_config *cfg)
{
	hsm_sign_params_t *params;
	hsm_key_t *key;
	ldns_rr *dnskey;

	key = hsm_find_key_by_id(NULL, key_id);
	if (!key) {
		fprintf(stderr, "; Could not find key %s\n", key_id);
		return;
	}
	/* check whether we have room left for this new key */
	if (list->key_count >= list->capacity) {
		list->capacity = list->capacity * 2;
		list->keys = realloc(list->keys,
		                     sizeof(hsm_key_t *) * list->capacity);
		if (!list->keys) {
			fprintf(stderr,
			        "Out of memory while adding key, skipping key\n");
			hsm_key_free(key);
			return;
		}
		list->keytags = realloc(list->keytags,
		                        sizeof(uint16_t) * list->capacity);
		if (!list->keytags) {
			fprintf(stderr,
			        "Out of memory while adding key, skipping key\n");
			hsm_key_free(key);
			return;
		}
		list->algorithms = realloc(list->algorithms,
		                        sizeof(uint8_t) * list->capacity);
		if (!list->algorithms) {
			fprintf(stderr,
			        "Out of memory while adding key, skipping key\n");
			hsm_key_free(key);
			return;
		}
		list->use_key = realloc(list->use_key,
		                        sizeof(int) * list->capacity);
		if (!list->use_key) {
			fprintf(stderr,
			        "Out of memory while adding key, skipping key\n");
			hsm_key_free(key);
			return;
		}
	}

	params = hsm_sign_params_new();
	params->algorithm = atoi(key_algorithm_str);
	if (params->algorithm == 0 ||
		hsm_supported_algorithm(params->algorithm) != 0) {
		fprintf(stderr, "; Error: Bad algorithm: %s, skipping key\n",
		        key_algorithm_str);
		hsm_key_free(key);
		hsm_sign_params_free(params);
		return;
	}

	params->flags = atoi(key_flags_str);
	params->owner = ldns_rdf_clone(cfg->origin);
	dnskey = hsm_get_dnskey(NULL, key, params);

	list->keys[list->key_count] = key;
	list->keytags[list->key_count] = ldns_calc_keytag(dnskey);
	list->algorithms[list->key_count] = params->algorithm;
	list->flags[list->key_count] = params->flags;
	list->use_key[list->key_count] = 1;
	list->key_count++;

	ldns_rr_free(dnskey);
	hsm_sign_params_free(params);
}

current_config *
current_config_new()
{
	current_config *cfg = malloc(sizeof(current_config));
	if (!cfg) {
		return NULL;
	}

	cfg->inception = 0;
	cfg->expiration = 0;
	cfg->expiration_denial = 0;
	cfg->refresh = 0;
	cfg->refresh_denial = 0;
	cfg->jitter = 0;
	cfg->echo_input = 0;
	cfg->origin = NULL;
	cfg->zsks = key_list_new();
	cfg->ksks = key_list_new();
	cfg->nsec3_algorithm = 0;
	cfg->nsec3_iterations = 0;
	cfg->nsec3_salt = NULL;
	cfg->cfg_soa_ttl = 0;
	cfg->soa_ttl = 0;
	cfg->soa_serial = 0;
	cfg->soa_serial_keep = 0;
	cfg->cfg_soa_minimum = 0;
	cfg->soa_minimum = 0;
	cfg->existing_sigs = 0;
	cfg->removed_sigs = 0;
	cfg->created_sigs = 0;
	cfg->verbosity = 1;
	return cfg;
}

void
current_config_free(current_config *cfg)
{
	if (cfg) {
		if (cfg->origin) {
			ldns_rdf_deep_free(cfg->origin);
		}
		if (cfg->zsks) free(cfg->zsks);
		if (cfg->ksks) free(cfg->ksks);
		if (cfg->nsec3_salt) free(cfg->nsec3_salt);
		free(cfg);
	}
}

static uint32_t
jitter_expiration(uint expiration, uint32_t jitter)
{
	uint32_t e = expiration;

	if (jitter) {
		e -= jitter;
#ifdef HAVE_ARC4RANDOM_UNIFORM
		e += arc4random_uniform(2 * jitter);
#elif HAVE_ARC4RANDOM
		e += arc4random() % (2 * jitter);
#else
		e += rand() % (2 * jitter);
#endif
	}

	return e;
}

void
usage(FILE *out)
{
	fprintf(out, "Usage: signer [OPTIONS]\n");
	fprintf(out, "Adds RRSIG records to the read resource records sets with PKCS11\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-c <file>\t\tUse the specified OpenDNSSEC configuration file\n");
	fprintf(out, "-f <file>\t\tRead from file instead of stdin\n");
	fprintf(out, "-h\t\t\tShow this help\n");
	fprintf(out, "-l <facility>\t\tSyslog facility\n");
	fprintf(out, "-p <file>\t\tRead a previous output of this tool for existing signatures\n");
	fprintf(out, "-w <file>\t\tWrite the output to this file (default stdout)\n");
	fprintf(out, "-r\t\t\tPrints the number of signatures generated to stderr. On success, this will\n");
	fprintf(out, "\t\t\talways be 1 or more.\n");
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
	} else {
		return true;
	}
}

char *
read_arg(const char *istr, char **next)
{
	char *result = NULL;
	char *end;
	char *str = (char *)istr;

	if (!str) {
		*next = NULL;
		return result;
	}
	if (*str == '"') {
		if (strlen(str) > 0) {
			str++;
		}
		end = strchr(str, '"');
	} else {
		end = strchr(str, ' ');
	}
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
		*next = end;
		if (**next == '"') {
			*next = *next + 1;
		}
		while (**next == ' ' || **next == '\t') {
			*next = *next + 1;
		}
	} else {
		if (strlen(str) > 0) {
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

/* Coverity comment:
   use of sscanf() is seen as a security risk
*/
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

ldns_status
handle_command(FILE *output, current_config *cfg,
               const char *line, int line_len)
{
	char *cmd;
	char *arg1 = NULL, *arg2 = NULL, *arg3 = NULL;
	char *next;
	ldns_status result = LDNS_STATUS_OK;
	(void)line_len;

	cmd = read_arg(line, &next);
	if (!cmd) {
		return LDNS_STATUS_ERR;
	}
	if (strncmp(cmd, "add_zsk", 7) == 0 && strlen(cmd) == 7) {
		arg1 = read_arg(next, &next);
		arg2 = read_arg(next, &next);
		arg3 = read_arg(next, &next);
		if (!arg1 || !arg2 || !arg3) {
			fprintf(output, "; Error: missing argument in add_key command\n");
		} else {
			key_list_add_key(cfg->zsks, arg1, arg2, arg3, cfg);
		}
	} else if (strncmp(cmd, "add_ksk", 7) == 0 && strlen(cmd) == 7) {
		arg1 = read_arg(next, &next);
		arg2 = read_arg(next, &next);
		arg3 = read_arg(next, &next);
		if (!arg1 || !arg2 || !arg3) {
			fprintf(output, "; Error: missing argument in add_key command\n");
		} else {
			key_list_add_key(cfg->ksks, arg1, arg2, arg3, cfg);
		}
	} else if (strncmp(cmd, "inception", 9) == 0 && strlen(cmd) == 9) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in inception command\n");
		} else {
			cfg->inception = parse_time(arg1);
		}
	} else if (strncmp(cmd, "expiration", 10) == 0 && strlen(cmd) == 10) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in expiration command\n");
		} else {
			cfg->expiration = parse_time(arg1);
		}
	} else if (strncmp(cmd, "expiration_denial", 17) == 0 && strlen(cmd) == 17) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in expiration_denial command\n");
		} else {
			cfg->expiration_denial = parse_time(arg1);
		}
	} else if (strncmp(cmd, "jitter", 6) == 0 && strlen(cmd) == 6) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in jitter command\n");
		} else {
			cfg->jitter = atol(arg1);
		}
	} else if (strncmp(cmd, "refresh", 7) == 0 && strlen(cmd) == 7) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in refresh command\n");
		} else {
			cfg->refresh = parse_time(arg1);
		}
	} else if (strncmp(cmd, "refresh_denial", 14) == 0 && strlen(cmd) == 14) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in refresh_denial command\n");
		} else {
			cfg->refresh_denial = parse_time(arg1);
		}
	} else if (strncmp(cmd, "nsec3_algorithm", 15) == 0 && strlen(cmd) == 15) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in nsec3_algorithm command\n");
		} else {
			cfg->nsec3_algorithm = atol(arg1);
		}
	} else if (strncmp(cmd, "nsec3_iterations", 16) == 0 && strlen(cmd) == 16) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in nsec3_iterations command\n");
		} else {
			cfg->nsec3_iterations = atol(arg1);
		}
	} else if (strncmp(cmd, "nsec3_salt", 10) == 0 && strlen(cmd) == 10) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in nsec3_salt command\n");
		} else {
			cfg->nsec3_salt = strdup(arg1);
		}
	} else if (strncmp(cmd, "origin", 6) == 0 && strlen(cmd) == 6) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in origin command\n");
		} else {
			if (cfg->origin) {
				ldns_rdf_deep_free(cfg->origin);
			}
			result = ldns_str2rdf_dname(&cfg->origin, arg1);
		}
	} else if (strncmp(cmd, "soa_ttl", 7) == 0 && strlen(cmd) == 7) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in soa_ttl command\n");
		} else {
			cfg->soa_ttl = atol(arg1);
			cfg->cfg_soa_ttl = 1;
		}
	} else if (strncmp(cmd, "soa_serial", 10) == 0 && strlen(cmd) == 10) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in soa_serial command\n");
		} else {
			cfg->soa_serial = atol(arg1);
		}
	} else if (strncmp(cmd, "soa_serial_keep", 15) == 0 && strlen(cmd) == 15) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in soa_serial_keep command\n");
		} else {
			cfg->soa_serial_keep = atol(arg1);
		}
	} else if (strncmp(cmd, "soa_minimum", 11) == 0 && strlen(cmd) == 11) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in soa_minimum command\n");
		} else {
			cfg->soa_minimum = atol(arg1);
			cfg->cfg_soa_minimum = 1;
		}
	} else if (strncmp(cmd, "stop", 4) == 0 && strlen(cmd) == 4) {
		result = LDNS_STATUS_NULL;
	} else {
		fprintf(stderr, "; Error: unknown command: %s\n", cmd);
		fprintf(output, "; Error: unknown command: %s\n", cmd);
	}
	if (arg1) free(arg1);
	if (arg2) free(arg2);
	if (arg3) free(arg3);
	free(cmd);
	return result;
}

void
enable_keys(current_config *cfg)
{
	size_t i;
	for (i = 0; i < cfg->zsks->key_count; i++) {
		cfg->zsks->use_key[i] = 1;
	}
	for (i = 0; i < cfg->ksks->key_count; i++) {
		cfg->ksks->use_key[i] = 1;
	}
}

void
set_use_key_for(key_list *list, ldns_rr *rrsig, int use)
{
	size_t i;

	for (i = 0; i < list->key_count; i++) {
		/* What if there are multiple keys with the same keytag? */
		if (list->keytags[i] ==
		    ldns_rdf2native_int16(ldns_rr_rrsig_keytag(rrsig))) {
			list->use_key[i] = use;
			return;
		}
	}
}

int
key_enabled_for(key_list *list, ldns_rr *rrsig)
{
	size_t i;

	for (i = 0; i < list->key_count; i++) {
		/* What if there are multiple keys with the same keytag? */
		if (list->keytags[i] ==
		    ldns_rdf2native_int16(ldns_rr_rrsig_keytag(rrsig))) {
			return list->use_key[i];
		}
	}
	return 0;
}

void
disable_key_for(key_list *list, ldns_rr *rrsig)
{
		set_use_key_for(list, rrsig, 0);
}

void
enable_key_for(key_list *list, ldns_rr *rrsig)
{
		set_use_key_for(list, rrsig, 1);
}

void
update_soa_record(ldns_rr *soa, current_config *cfg)
{
	if (cfg->cfg_soa_ttl != 0) {
		ldns_rr_set_ttl(soa, cfg->soa_ttl);
	}
	if (cfg->soa_serial != 0) {
		ldns_rdf_deep_free(ldns_rr_rdf(soa, 2));
		ldns_rr_set_rdf(soa,
						ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32,
											  cfg->soa_serial),
						2);
	}
	if (cfg->cfg_soa_minimum != 0) {
		ldns_rdf_deep_free(ldns_rr_rdf(soa, 6));
		ldns_rr_set_rdf(soa,
						ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32,
											  cfg->soa_minimum),
						6);
	}
}

rrset_reader_t *
rrset_reader_new(FILE *file)
{
	rrset_reader_t *reader;

	reader = malloc(sizeof(rrset_reader_t));
	if (!reader) {
		return NULL;
	}
	reader->skipped_rr = NULL;
	reader->file = file;

	return reader;
}

/* comments and commands are handled by their functions,
 * the first rr read is returned
 * garbage is skipped
 *
 * if pass_comments is not true, comments are dropped
 * (this is needed to avoid replication of comments in generated output
 * ie. set it to true on your 'new' zone, and to false one your
 * 'previously signed' zone)
 */
ldns_rr *
read_rr_from_file(FILE *file, FILE *out,
                  current_config *cfg, int pass_comments)
{
	char line[MAX_LINE_LEN];
	int line_len;
	ldns_rr *rr = NULL;
	ldns_status status, cmd_res;

	while (!rr) {
		line_len = read_line(file, line, 0, 0);
		if (line_len < 0) {
			return NULL;
		}
		if (line_len == 0 || line[0] == '\n') {
			continue;
		}
		if (line[0] == ';') {
			if (pass_comments) {
				fprintf(out, "%s\n", line);
			}
		} else if (line[0] == ':') {
			cmd_res = handle_command(out, cfg, line + 1,
									 line_len - 1);
			if (cmd_res == LDNS_STATUS_NULL) {
				return NULL;
			}
		} else {
			status = ldns_rr_new_frm_str(&rr, line, 0, NULL, NULL);
			if (status == LDNS_STATUS_OK) {
				if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_SOA) {
					update_soa_record(rr, cfg);
				}
				return rr;
			} else {
				fprintf(stderr,
				        ";Warning: skipping garbage: %s\n",
				        line);
			}
		}
	}
	return NULL;
}

/* read an rrset from the file in the reader.
 * if an rr is found that does not belong to the set, it
 * is added to skipped_rrs
 * next time, skipped_rrs is read before the file
 * comments and commends are handled by their respective functions
 * return an rr_list with one or more rrs, or NULL (never an empty one)
 */
ldns_rr_list *
read_rrset(rrset_reader_t *reader, FILE *out,
           current_config *cfg, int pass_comments)
{
	ldns_rr *rr;
	ldns_rr_list *rrset;

	if (!reader) return NULL;
	rrset = ldns_rr_list_new();
	if (reader->skipped_rr) {
		ldns_rr_list_push_rr(rrset, reader->skipped_rr);
		reader->skipped_rr = NULL;
	}
	while(1) {
		rr = read_rr_from_file(reader->file, out, cfg, pass_comments);
		if (!rr) {
			if (ldns_rr_list_rr_count(rrset) == 0) {
				ldns_rr_list_free(rrset);
				return NULL;
			} else {
				return rrset;
			}
		}
		if (ldns_rr_list_rr_count(rrset) > 0) {
			if (is_same_rrset(ldns_rr_list_rr(rrset, 0), rr)) {
				ldns_rr_set_ttl(rr, ldns_rr_ttl(ldns_rr_list_rr(rrset, 0)) );
				ldns_rr_list_push_rr(rrset, rr);
			} else {
				reader->skipped_rr = rr;
				return rrset;
			}
		} else {
			ldns_rr_list_push_rr(rrset, rr);
		}
	}
	return NULL;
}

/* same as read_rrset, but only return RRSIGS. NULL if next rr is not
 * a signature */
ldns_rr_list *
read_signatures(rrset_reader_t *reader, FILE *out,
                current_config *cfg, int pass_comments)
{
	ldns_rr *rr;
	ldns_rr_list *rrset;

	if (!reader) return NULL;
	rrset = ldns_rr_list_new();
	if (reader->skipped_rr) {
		if (ldns_rr_get_type(reader->skipped_rr) !=
		    LDNS_RR_TYPE_RRSIG) {
			ldns_rr_list_free(rrset);
			return NULL;
		}
		ldns_rr_list_push_rr(rrset, reader->skipped_rr);
		reader->skipped_rr = NULL;
	}
	while(1) {
		rr = read_rr_from_file(reader->file, out, cfg, pass_comments);
		if (!rr) {
			if (ldns_rr_list_rr_count(rrset) == 0) {
				ldns_rr_list_free(rrset);
				return NULL;
			} else {
				return rrset;
			}
		}
		if (ldns_rr_list_rr_count(rrset) > 0 &&
			is_same_rrset(ldns_rr_list_rr(rrset, 0), rr) &&
			ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG) {
			ldns_rr_list_push_rr(rrset, rr);
		} else {
			reader->skipped_rr = rr;
			return rrset;
		}
	}
	return NULL;
}

/* check for existing sigs that do not have to be renewed yet
 * print those, and mark the corresponding keys so they aren't
 * used by sign_rrset */
void
check_existing_sigs(ldns_rr_list *sigs,
                    FILE *output,
                    current_config *cfg)
{
	size_t i;
	ldns_rr *cur_sig;
	uint32_t expiration;
	uint32_t refresh;
	ldns_rr_type type_covered;
	int printed;

	for (i = 0; i < ldns_rr_list_rr_count(sigs); i++) {
		/* check the refresh date for this signature. If the signature
		 * covers a denial RRset (NSEC or NSEC3), and :expiration_denial
		 * was set to anything other than 0, we need to use
		 * expiration_denial instead of :expiration */
		cur_sig = ldns_rr_list_rr(sigs, i);
		if (!cur_sig) {
			/* hm ok, this was not expected: just create a new signature. */
			continue;
		}
		cfg->existing_sigs++;
		type_covered = ldns_rdf2native_int16(
		                  ldns_rr_rrsig_typecovered(cur_sig));
		expiration = ldns_rdf2native_int32(
		                  ldns_rr_rrsig_expiration(cur_sig));
		if (cfg->expiration_denial &&
		    (type_covered == LDNS_RR_TYPE_NSEC ||
			 type_covered == LDNS_RR_TYPE_NSEC3)) {
			refresh = cfg->refresh_denial;
		} else {
			refresh = cfg->refresh;
		}
		/* if refresh is zero, we just drop existing
		 * signatures. Otherwise, we'll have to check
		 * them and mark which keys should still be used
		 * to create new ones
		 *
		 * *always* update SOA RRSIG
		 */
		if (refresh || type_covered == LDNS_RR_TYPE_SOA) {
			if ( expiration < refresh ||
				type_covered == LDNS_RR_TYPE_SOA) {
				/* ok, drop sig, resign */
				cfg->removed_sigs++;
			} else {
				printed = 0;
				/* leave sig, disable key */
				/* but only if it wasn't disabled yet */
				if (key_enabled_for(cfg->zsks, cur_sig)) {
					ldns_rr_print(output, cur_sig);
					printed = 1;
					disable_key_for(cfg->zsks, cur_sig);
				}
				if (key_enabled_for(cfg->ksks, cur_sig)) {
					if (!printed) {
						ldns_rr_print(output, cur_sig);
					}
					disable_key_for(cfg->ksks, cur_sig);
				}
			}
		}
	}
}

static int
rr_list_delegation_only(ldns_rdf *origin, ldns_rr_list *rr_list)
{
	size_t i;
	ldns_rr *cur_rr;
	if (!origin || !rr_list) return 0;
	for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
		cur_rr = ldns_rr_list_rr(rr_list, i);
		if (ldns_dname_compare(ldns_rr_owner(cur_rr), origin) == 0) {
			return 0;
		}
		if (ldns_rr_get_type(cur_rr) != LDNS_RR_TYPE_NS) {
			return 0;
		}
	}
	return 1;
}

static ldns_status
signature_verifies(ldns_rr_list* rrset, ldns_rr* sig, const hsm_key_t *key, const hsm_sign_params_t *params)
{
	ldns_status ret = LDNS_STATUS_OK;
	ldns_rr* dnskey = hsm_get_dnskey(NULL, key, params);
	ldns_rr_list* keylist = ldns_rr_list_new();
	ldns_rr_list* good_keylist = ldns_rr_list_new();
	ldns_rr_list_push_rr(keylist, dnskey);
	ret = ldns_verify_rrsig_keylist(rrset, sig, keylist, good_keylist);
	ldns_rr_list_deep_free(keylist);
	ldns_rr_list_free(good_keylist);
	return ret;
}

void
sign_rrset(ldns_rr_list *rrset,
           FILE *output,
           current_config *cfg)
{
	size_t i;
	ldns_status status = LDNS_STATUS_OK;
	ldns_rr *sig;
	key_list *keys;
	hsm_sign_params_t *params;
	params = hsm_sign_params_new();
	if (!cfg->origin) {
		fprintf(stderr, "Origin not set! Unable to continue.\n");
		if (params) {
			hsm_sign_params_free(params);
		}
		exit(1);
	}

	/* skip delegation rrsets */
	if (rr_list_delegation_only(cfg->origin, rrset)) return;

	params->owner = ldns_rdf_clone(cfg->origin);
	params->inception = cfg->inception;
	if (ldns_rr_get_type(ldns_rr_list_rr(rrset, 0)) ==
	                           LDNS_RR_TYPE_DNSKEY) {
		keys = cfg->ksks;
	} else {
		keys = cfg->zsks;
	}
	for (i = 0; i < keys->key_count; i++) {
		if (keys->use_key[i]) {
			if (cfg->verbosity >= 4) {
				fprintf(output, "; new signature\n");
			}
			params->keytag = keys->keytags[i];
			params->algorithm = keys->algorithms[i];
			params->flags = keys->flags[i];
			if (cfg->expiration_denial &&
			    (ldns_rr_list_type(rrset) == LDNS_RR_TYPE_NSEC ||
			     ldns_rr_list_type(rrset) == LDNS_RR_TYPE_NSEC3)) {
				params->expiration = jitter_expiration(cfg->expiration_denial, cfg->jitter);
			} else {
				params->expiration = jitter_expiration(cfg->expiration, cfg->jitter);
			}
			sig = hsm_sign_rrset(NULL, rrset,  keys->keys[i], params);
			if (sig)
				status = signature_verifies(rrset, sig, keys->keys[i], params);

			if (sig && status == LDNS_STATUS_OK) {
				if (cfg->verbosity >= 4) {
					fprintf(output, "; signature verifies\n");
				}
				cfg->created_sigs++;
				ldns_rr_print(output, sig);
				ldns_rr_free(sig);
			} else if (sig) {
				fprintf(output, "; signing failed: %s\n", ldns_get_errorstr_by_id(status));
				ldns_rr_print(output, sig);
				ldns_rr_free(sig);
				if (status == LDNS_STATUS_CRYPTO_BOGUS) {
					log_msg(LOG_ALERT, "WARNING: HSM returned BOGUS signature! Abort signing, "
						"retry on next resign\n");
				}
				exit(EXIT_FAILURE);
			} else {
				fprintf(output, "; signing failed: hsm returned null signature\n");
				log_msg(LOG_ALERT, "WARNING: HSM returned NULL signature! Abort signing, "
					"retry on next resign\n");
				exit(EXIT_FAILURE);
			}
		}
	}
	hsm_sign_params_free(params);
}

int
compare_list_rrset(ldns_rr_list *a, ldns_rr_list *b)
{
	ldns_rr* rr1, *rr2;
	ldns_rdf* rdf1, *rdf2;
	size_t rr1_len, rr2_len;
	uint8_t nsec3_salt_length = 0;
	uint8_t* nsec3_salt = NULL;
	int c, ret = 0;

	if (ldns_rr_list_rr_count(a) == 0) {
		if (ldns_rr_list_rr_count(b) == 0) {
			if (global_cfg->verbosity >= 4) {
				fprintf(stderr, "Compared RRsets: both empty\n");
			}
			return 0;
		} else {
			if (global_cfg->verbosity >= 4) {
				fprintf(stderr, "Compared RRsets: first RRset empty\n");
			}
			return -1;
		}
	}
	/* ldns_rr_list_rr_count(a) != 0 */
	if (ldns_rr_list_rr_count(b) == 0) {
		if (global_cfg->verbosity >= 4) {
			fprintf(stderr, "Compared RRsets: second RRset empty\n");
		}
		return 1;
	}

	rr1 = ldns_rr_list_rr(a, 0);
	rr2 = ldns_rr_list_rr(b, 0);
	rr1_len = ldns_rr_uncompressed_size(rr1);
	rr2_len = ldns_rr_uncompressed_size(rr2);

	/* If we encounter non-NSEC3 data, we should compare the hash(owner)'s instead of owner's */
	if (ldns_rr_get_type(rr1) != LDNS_RR_TYPE_NSEC3 &&
		ldns_rr_get_type(rr2) != LDNS_RR_TYPE_NSEC3 &&
		global_cfg && global_cfg->nsec3_algorithm) {

		if (global_cfg->nsec3_salt) {
			nsec3_salt_length = (uint8_t) (strlen(global_cfg->nsec3_salt) / 2);
			nsec3_salt = LDNS_XMALLOC(uint8_t, nsec3_salt_length);
			for (c = 0; c < (int) strlen(global_cfg->nsec3_salt); c += 2) {
				if (isxdigit((int) global_cfg->nsec3_salt[c]) && isxdigit((int) global_cfg->nsec3_salt[c+1])) {
					nsec3_salt[c/2] = (uint8_t) ldns_hexdigit_to_int(global_cfg->nsec3_salt[c]) * 16 +
						ldns_hexdigit_to_int(global_cfg->nsec3_salt[c+1]);
				} else {
					fprintf(stderr, "Salt value is not valid hex data.\n");
					exit(EXIT_FAILURE);
				}
			}
		}

		rdf1 = ldns_nsec3_hash_name(ldns_rr_owner(rr1),
					global_cfg->nsec3_algorithm,
					global_cfg->nsec3_iterations,
	                nsec3_salt_length,
					nsec3_salt);
		rdf2 = ldns_nsec3_hash_name(ldns_rr_owner(rr2),
					global_cfg->nsec3_algorithm,
					global_cfg->nsec3_iterations,
	                nsec3_salt_length,
					nsec3_salt);

		if (global_cfg->verbosity >= 4) {
			fprintf(stderr, "Compare hash(%s)=%s vs. hash(%s)=%s\n",
				ldns_rdf2str(ldns_rr_owner(rr1)),
				ldns_rdf2str(rdf1),
				ldns_rdf2str(ldns_rr_owner(rr2)),
				ldns_rdf2str(rdf2)
			);
		}

		ret = 0;
		if (ldns_dname_compare(rdf1, rdf2) < 0) {
			ret = -1;
		} else if (ldns_dname_compare(rdf1, rdf2) > 0) {
			ret = 1;
		}

		ldns_rdf_deep_free(rdf1);
		ldns_rdf_deep_free(rdf2);
		if (nsec3_salt) free(nsec3_salt);
		if (ret != 0) {
			if (global_cfg->verbosity >= 4) {
				fprintf(stderr, "Compared RRsets: hash(owner) differs [cmp=%i]\n", ret);
			}
			return ret;
		}
	} else if (ldns_rr_get_type(rr1) != LDNS_RR_TYPE_NSEC3 &&
		global_cfg && global_cfg->nsec3_algorithm) {
		/* NSEC3 removed */
		return 1;
	} else if (ldns_rr_get_type(rr2) != LDNS_RR_TYPE_NSEC3 &&
		global_cfg && global_cfg->nsec3_algorithm) {
		/* NSEC3 added */
		return -1;
	}

	/* continue normal rr_compare_no_rdata: both NSEC3 or no NSEC3 involved */
	return ldns_rr_compare_no_rdata(rr1, rr2);
}

int
rr_list_compare_soa(ldns_rr_list* a, ldns_rr_list* b, current_config* cfg)
{
	size_t i = 0;
	int rr_cmp;
    ldns_rr* soa1, *soa2;

	assert(a != NULL);
	assert(b != NULL);

	for (i = 0; i < ldns_rr_list_rr_count(a) && i < ldns_rr_list_rr_count(b); i++) {
		rr_cmp = ldns_rr_compare(ldns_rr_list_rr(a, i), ldns_rr_list_rr(b, i));
		if (rr_cmp != 0) {
			if (ldns_rr_list_type(a) == LDNS_RR_TYPE_SOA) {
				soa1 = ldns_rr_list_rr(a, i);
				soa2 = ldns_rr_list_rr(b, i);
				/* NAME, CLASS, TYPE, RDLENGTH */
				if (ldns_rr_compare_no_rdata(soa1, soa2) != 0)
					return rr_cmp;
				/* MNAME, RNAME, ..., REFRESH, RETRY, EXPIRE, ... */
				if ((ldns_rdf_compare(ldns_rr_rdf(soa1, 0), ldns_rr_rdf(soa2, 0))) != 0 ||
				    (ldns_rdf_compare(ldns_rr_rdf(soa1, 1), ldns_rr_rdf(soa2, 1))) != 0 ||
				    (ldns_rdf_compare(ldns_rr_rdf(soa1, 3), ldns_rr_rdf(soa2, 3))) != 0 ||
				    (ldns_rdf_compare(ldns_rr_rdf(soa1, 4), ldns_rr_rdf(soa2, 4))) != 0 ||
				    (ldns_rdf_compare(ldns_rr_rdf(soa1, 5), ldns_rr_rdf(soa2, 5))) != 0)
				{
					return rr_cmp;
				}

				/* SERIAL */
				if (cfg->soa_serial == 0 && /* we did not change it */
					ldns_rdf_compare(ldns_rr_rdf(soa1, 2), ldns_rr_rdf(soa2, 2)) != 0) {
					return rr_cmp;
				}
				if (cfg->soa_serial_keep != 0 && /* soa serial is keep, force change */
					ldns_rdf_compare(ldns_rr_rdf(soa1, 2), ldns_rr_rdf(soa2, 2)) != 0) {
					return rr_cmp;
				}

				/* MINIMUM */
				if (cfg->cfg_soa_minimum == 0 && /* we did not change it */
					ldns_rdf_compare(ldns_rr_rdf(soa1, 6), ldns_rr_rdf(soa2, 6)) != 0) {
					return rr_cmp;
				}

				/* TTL */
				if (cfg->cfg_soa_ttl == 0 && /* we did not change it */
					ldns_rr_ttl(soa1) != ldns_rr_ttl(soa2)) {
					if (ldns_rr_ttl(soa1) < ldns_rr_ttl(soa2))
						return 1;
					else
						return -1;
				}

				/* consider the same */
				return 0;
			} else
				return rr_cmp;
		}
	}

	if (i == ldns_rr_list_rr_count(a) &&
		i != ldns_rr_list_rr_count(b)) {
		return 1;
	} else if (i == ldns_rr_list_rr_count(b) &&
			   i != ldns_rr_list_rr_count(a)) {
		return -1;
	}

	return 0;
}

/* returns 0 when an rrset has successfully been read and handled
 * returns 1 when EOF is read and the last rrset has successfully been
 * handled
 * returns -1 on error
 */
int
read_input(FILE *input, FILE *signed_zone, FILE *output, current_config *cfg)
{
	rrset_reader_t *new_zone_reader, *signed_zone_reader;
	ldns_rr_list *new_zone_rrset = NULL;
	ldns_rr_list *new_zone_signatures= NULL;
	ldns_rr_list *signed_zone_rrset = NULL;
	ldns_rr_list *signed_zone_signatures = NULL;
	int cmp;

	if (signed_zone) {
		signed_zone_reader = rrset_reader_new(signed_zone);
		if (!signed_zone_reader) {
			fprintf(stderr, "Error creating rrset reader\n");
			return -1;
		}
	} else {
		signed_zone_reader = NULL;
	}

	new_zone_reader = rrset_reader_new(input);
	if (!new_zone_reader) {
		fprintf(stderr, "Error creating rrset reader\n");
		return -1;
	}

	while ((new_zone_rrset = read_rrset(new_zone_reader, output, cfg, 1))) {
		if (ldns_rr_list_rr_count(new_zone_rrset) == 0) {
			ldns_rr_list_free(new_zone_rrset);
			continue;
		}
		if (cfg->verbosity >= 4) {
			fprintf(stderr, "Read rrset from input:\n");
			ldns_rr_list_print(stderr, new_zone_rrset);
		}
		new_zone_signatures = read_signatures(new_zone_reader,
		                                      output, cfg, 1);
		if (cfg->verbosity >= 4) {
			fprintf(stderr, "Read signatures from input:\n");
			ldns_rr_list_print(stderr, new_zone_signatures);
		}
		enable_keys(cfg);
		/* if we have no previously signed zone, check for sigs
		 * in input, and sign the rest */
		if (!signed_zone_reader) {
			ldns_rr_list_print(output, new_zone_rrset);
			check_existing_sigs(new_zone_signatures, output, cfg);
			sign_rrset(new_zone_rrset, output, cfg);
		} else {
			/* now we have a few scenarios, either this rrset is new
			 * or not. If not, it has either changed or not. If not,
			 * there may be signatures in the old zone file as well
			 */
			signed_zone_rrset = read_rrset(signed_zone_reader, output, cfg, 0);
			if (cfg->verbosity >= 4) {
				fprintf(stderr, "Read rrset from signed zone:\n");
				ldns_rr_list_print(stderr, signed_zone_rrset);
			}
			signed_zone_signatures = read_signatures(signed_zone_reader, output, cfg, 0);
			if (cfg->verbosity >= 4) {
				fprintf(stderr, "Read signatures from signed zone:\n");
				ldns_rr_list_print(stderr, signed_zone_signatures);
			}
			cmp = compare_list_rrset(new_zone_rrset, signed_zone_rrset);

			/* if cmp != 0 and the type of the input RRSET is NSEC3,
			 * we cannot compare the name to the name of the signed
			 * rrset. Since the zone reader removes NSEC3 records
			 * anyway, we can assume that the signed data has been
			 * resorted, and that there are no nsec3 records anymore
			 * In that case, we treat the data as new */
nsec3_encountered:
			while (cmp != 0 &&
			       ldns_rr_list_type(new_zone_rrset) == LDNS_RR_TYPE_NSEC3 &&
				   ldns_rr_list_type(signed_zone_rrset) != LDNS_RR_TYPE_NSEC3)
			{
				if (new_zone_signatures) {
					check_existing_sigs(new_zone_signatures, output, cfg);
					ldns_rr_list_deep_free(new_zone_signatures);
				}
				if (cfg->verbosity >= 4) {
					fprintf(output, "; NSEC3, signing\n");
					fprintf(stderr, "NSEC3, signing:\n");
					ldns_rr_list_print(stderr, new_zone_rrset);
				}
				ldns_rr_list_print(output, new_zone_rrset);
				sign_rrset(new_zone_rrset, output, cfg);
				ldns_rr_list_deep_free(new_zone_rrset);

				new_zone_rrset = read_rrset(new_zone_reader, output, cfg, 1);
				if (cfg->verbosity >= 4) {
					fprintf(stderr, "NSEC3 signed, read rrset from input:\n");
					ldns_rr_list_print(stderr, new_zone_rrset);
				}
				new_zone_signatures = read_signatures(new_zone_reader, output, cfg, 1);
				if (cfg->verbosity >= 4) {
					fprintf(stderr, "NSEC3 signed, read signatures from input:\n");
					ldns_rr_list_print(stderr, new_zone_signatures);
				}
				cmp = compare_list_rrset(new_zone_rrset, signed_zone_rrset);
			}
			/* if the cur rrset name > signed rrset name then data has
			 * been removed, reread signed rrset */
nsec3_removed:
			while (cmp > 0 && signed_zone_rrset) {
				ldns_rr_list_deep_free(signed_zone_rrset);
				if (signed_zone_signatures) ldns_rr_list_deep_free(signed_zone_signatures);
				signed_zone_rrset = read_rrset(signed_zone_reader, output, cfg, 0);
				if (cfg->verbosity >= 4) {
					fprintf(stderr, "Data was removed, read next rrset from signed zone:\n");
					ldns_rr_list_print(stderr, signed_zone_rrset);
				}
				signed_zone_signatures = read_signatures(signed_zone_reader, output, cfg, 0);
				if (cfg->verbosity >= 4) {
					fprintf(stderr, "Data was removed, read next signatures from signed zone:\n");
					ldns_rr_list_print(stderr, signed_zone_signatures);
				}
				cmp = compare_list_rrset(new_zone_rrset, signed_zone_rrset);
				if (cmp != 0 &&
					ldns_rr_list_type(new_zone_rrset) == LDNS_RR_TYPE_NSEC3 &&
					ldns_rr_list_type(signed_zone_rrset) != LDNS_RR_TYPE_NSEC3) {
					goto nsec3_encountered;
				}
				if (cmp != 0 &&
					ldns_rr_list_type(new_zone_rrset) != LDNS_RR_TYPE_NSEC3 &&
					ldns_rr_list_type(signed_zone_rrset) == LDNS_RR_TYPE_NSEC3) {
					goto nsec3_removed;
				}
			}
			/* if the cur rrset name < signer rrset name then data is new
			 */
			while (cmp < 0 && new_zone_rrset) {
				check_existing_sigs(new_zone_signatures, output, cfg);
				if (cfg->verbosity >= 4) {
					fprintf(stderr, "New data, signing:\n");
					ldns_rr_list_print(stderr, new_zone_rrset);
					fprintf(output, "; new data, signing\n");
				}
				ldns_rr_list_print(output, new_zone_rrset);
				sign_rrset(new_zone_rrset, output, cfg);
				ldns_rr_list_deep_free(new_zone_rrset);
				ldns_rr_list_deep_free(new_zone_signatures);

				new_zone_rrset = read_rrset(new_zone_reader, output, cfg, 1);
				if (cfg->verbosity >= 4) {
					fprintf(stderr, "Continue, read rrset from input:\n");
					ldns_rr_list_print(stderr, new_zone_rrset);
				}
				new_zone_signatures = read_signatures(new_zone_reader, output, cfg, 1);
				if (cfg->verbosity >= 4) {
					fprintf(stderr, "Continue, read signatures from input:\n");
					ldns_rr_list_print(stderr, new_zone_signatures);
				}
				cmp = compare_list_rrset(new_zone_rrset, signed_zone_rrset);
				if (cmp != 0 &&
					ldns_rr_list_type(new_zone_rrset) == LDNS_RR_TYPE_NSEC3 &&
					ldns_rr_list_type(signed_zone_rrset) != LDNS_RR_TYPE_NSEC3) {
					goto nsec3_encountered;
				}
				if (cmp != 0 &&
					ldns_rr_list_type(new_zone_rrset) != LDNS_RR_TYPE_NSEC3 &&
					ldns_rr_list_type(signed_zone_rrset) == LDNS_RR_TYPE_NSEC3) {
					goto nsec3_removed;
				}
				if (cmp > 0 &&
					ldns_rr_list_type(new_zone_rrset) != LDNS_RR_TYPE_NSEC3) {
					goto nsec3_removed;
				}

			}
			/* if same, and rrset not same, treat as new */
			/* if same, and rrset same, check old sigs as well */
			/* sigs with same keytag in input get priority */
			if (cmp == 0 && new_zone_rrset && signed_zone_rrset) {
				if (ldns_rr_list_compare(new_zone_rrset, signed_zone_rrset) != 0) {
					if (cfg->verbosity >= 4) {
						fprintf(output, "; rrset changed\n");
						fprintf(stderr, "RRset changed:\n");
						ldns_rr_list_print(stderr, new_zone_rrset);
					}
					ldns_rr_list_print(output, new_zone_rrset);
					check_existing_sigs(new_zone_signatures, output, cfg);
					sign_rrset(new_zone_rrset, output, cfg);
					/* special case: SOA */
					if (ldns_rr_list_type(new_zone_rrset) == LDNS_RR_TYPE_SOA) {
						if (rr_list_compare_soa(new_zone_rrset, signed_zone_rrset, cfg) == 0)
						{
							cfg->created_sigs -= cfg->zsks->key_count;
						}
					}

				} else {
					if (cfg->verbosity >= 4) {
						fprintf(output, "; rrset%s still the same\n",
							ldns_rr_list_type(new_zone_rrset) == 6 ? " SOA":"");
						fprintf(stderr, "RRset the same:\n");
						ldns_rr_list_print(stderr, new_zone_rrset);
					}
					ldns_rr_list_print(output, new_zone_rrset);
					check_existing_sigs(signed_zone_signatures, output, cfg);
					check_existing_sigs(new_zone_signatures, output, cfg);
					sign_rrset(new_zone_rrset, output, cfg);
					/* special case: SOA */
					if (ldns_rr_list_type(new_zone_rrset) == LDNS_RR_TYPE_SOA) {
						if (rr_list_compare_soa(new_zone_rrset, signed_zone_rrset, cfg) == 0)
						{
							cfg->created_sigs -= cfg->zsks->key_count;
						}
					}
				}
			}
			/* in our search for the next signed rrset, we may have
			 * reached the end, in which case we have new rrsets at
			 * the input */
			else if (cmp > 0 && !signed_zone_rrset) {
				if (cfg->verbosity >= 4) {
					fprintf(output, "; new data at end, signing\n");
					fprintf(stderr, "New data at end, signing:\n");
					ldns_rr_list_print(stderr, new_zone_rrset);
				}
				ldns_rr_list_print(output, new_zone_rrset);
				check_existing_sigs(new_zone_signatures, output, cfg);
				sign_rrset(new_zone_rrset, output, cfg);
			}
		}

		ldns_rr_list_deep_free(new_zone_rrset);
		ldns_rr_list_deep_free(new_zone_signatures);
		ldns_rr_list_deep_free(signed_zone_rrset);
		ldns_rr_list_deep_free(signed_zone_signatures);
		new_zone_rrset = NULL;
		new_zone_signatures = NULL;
		signed_zone_rrset = NULL;
		signed_zone_signatures = NULL;
	}

	if (cfg->verbosity >= 4) {
		fprintf(output, "; done\n");
	}

	if (new_zone_reader) {
		free(new_zone_reader);
	}
	if (signed_zone_reader) {
		free(signed_zone_reader);
	}

	return 0;
}

int main(int argc, char **argv)
{
	current_config *cfg;
	int c;
	FILE *input;
	FILE *output;
	FILE *prev_zone = NULL;
	char *config_file = NULL;
	int result;
	int print_creation_count = 0;
	struct timeval t_start,t_end;
	double elapsed;
	int facility = DEFAULT_LOG_FACILITY;

	cfg = current_config_new();
	if (!cfg) {
		fprintf(stderr,	"Error: malloc failed\n");
		exit(1);
	}

	global_cfg = cfg;
	input = stdin;
	output = stdout;

	while ((c = getopt(argc, argv, "c:f:hl:p:w:r")) != -1) {
		switch(c) {
		case 'c':
			config_file = optarg;
			break;
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
		case 'l':
			if (facility2int(optarg, &facility) != 0) {
				fprintf(stderr,
						"Error: unable to set log facility: %s\n",
						optarg);
				exit(1);
			}
			break;
		case 'p':
			prev_zone = fopen(optarg, "r");
			if (!prev_zone) {
				fprintf(stderr,
						"Warning: unable to open %s: %s, performing "
						"full zone sign\n",
						optarg,
						strerror(errno));
			}
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
		case 'r':
			print_creation_count = 1;
			break;
		}
	}

	if (!config_file) {
		fprintf(stderr, "Error: no configuration file given\n");
		exit(1);
	}

	log_open(facility, "signer");

	result = hsm_open(config_file, hsm_prompt_pin, NULL);
	if (result != HSM_OK) {
		fprintf(stderr, "Error initializing libhsm\n");
		exit(2);
	}

	gettimeofday(&t_start, NULL);

	result = read_input(input, prev_zone, output, cfg);

	gettimeofday(&t_end, NULL);

	hsm_close();
	fprintf(output, "; Last refresh stats: existing: %lu, removed %lu, created %lu\n",
	        cfg->existing_sigs,
	        cfg->removed_sigs,
	        cfg->created_sigs);

	if (print_creation_count) {
		elapsed = (double) TIMEVAL_SUB(t_end, t_start);
		fprintf(stderr, "Number of signatures created: %lu\n", cfg->created_sigs);
		if (elapsed > 0)
			fprintf(stderr, "signer: number of signatures created: %lu (%u rr/sec)\n",
				cfg->created_sigs, (unsigned) (cfg->created_sigs / elapsed));
		else
			fprintf(stderr, "signer: number of signatures created: %lu (within a second)\n",
				cfg->created_sigs);
	}

	log_close();

	if (result == 1) {
		return 0;
	} else {
		return 1;
	}
}
