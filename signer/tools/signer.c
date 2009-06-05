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

#include <ldns/ldns.h>
#include <uuid/uuid.h>

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
	uint32_t refresh;
	uint32_t jitter;
	int echo_input;
	/*ldns_pkcs11_module_list *pkcs11_module_list;*/
	key_list *zsks;
	key_list *ksks;
	
	/* settings for SOA values that are changed */
	uint32_t soa_ttl;
	uint32_t soa_serial;
	uint32_t soa_minimum;
	
	/* and let's keep some statistics */
	unsigned long existing_sigs;
	unsigned long removed_sigs;
	unsigned long created_sigs;
} current_config;

static int
keystr2uuid(uuid_t *uuid, const char *key_id_str)
{
	unsigned char *key_id;
	int key_id_len;
	/* length of the hex input */
	size_t hex_len;
	int i;
	
	hex_len = strlen(key_id_str);
	if (hex_len % 2 != 0) {
		fprintf(stderr,
		        "Error: bad hex data for key id: %s\n",
		        key_id_str);
		return -1;
	}
	key_id_len = hex_len / 2;
	if (key_id_len != 16) {
		return -2;
	}
	key_id = malloc(16);
	for (i = 0; i < key_id_len; i++) {
		key_id[i] = ldns_hexdigit_to_int(key_id_str[2*i]) * 16 +
		            ldns_hexdigit_to_int(key_id_str[2*i+1]);
	}
	memcpy(uuid, key_id, 16);
	free(key_id);
	return 0;
}

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
	uuid_t key_uuid;
	hsm_key_t *key;
	ldns_rr *dnskey;

	(void) keystr2uuid(&key_uuid, key_id);
	key = hsm_find_key_by_uuid(NULL, (const uuid_t *)&key_uuid);
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
			        "Out of memory while adding key, aborting\n");
		}
		list->keytags = realloc(list->keytags,
		                        sizeof(uint16_t) * list->capacity);
		if (!list->keytags) {
			fprintf(stderr,
			        "Out of memory while adding key, aborting\n");
		}
		list->algorithms = realloc(list->algorithms,
		                        sizeof(uint8_t) * list->capacity);
		if (!list->algorithms) {
			fprintf(stderr,
			        "Out of memory while adding key, aborting\n");
		}
		list->use_key = realloc(list->use_key,
		                        sizeof(int) * list->capacity);
		if (!list->use_key) {
			fprintf(stderr,
			        "Out of memory while adding key, aborting\n");
		}
	}

	params = hsm_sign_params_new();
	params->algorithm = atoi(key_algorithm_str);
	if (params->algorithm == 0) {
		/* TODO: check for unknown algo's too? */
		fprintf(stderr, "; Error: Bad algorithm: %s, skipping key\n",
		        key_algorithm_str);
		hsm_sign_params_free(params);
		return;
	}
	
	params->flags = atoi(key_flags_str);
	params->owner = ldns_rdf_clone(cfg->origin);
	dnskey = hsm_get_dnskey(NULL, key, params);
	
	list->keys[list->key_count] = key;
	list->keytags[list->key_count] = ldns_calc_keytag(dnskey);
	list->algorithms[list->key_count] = params->algorithm;
	list->use_key[list->key_count] = 1;
	list->key_count++;
	
	ldns_rr_free(dnskey);
	hsm_sign_params_free(params);
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
	cfg->zsks = key_list_new();
	cfg->ksks = key_list_new();
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
	if (cfg) {
		if (cfg->origin) {
			ldns_rdf_deep_free(cfg->origin);
		}
		if (cfg->zsks) free(cfg->zsks);
		if (cfg->ksks) free(cfg->ksks);
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
	char *arg1 = NULL, *arg2 = NULL, *arg3 = NULL, *arg4 = NULL;
	char *next;
	ldns_status result = LDNS_STATUS_OK;
	int iresult;
	(void)line_len;
	
	cmd = read_arg(line, &next);
	if (!cmd) {
		return LDNS_STATUS_ERR;
	}
	if (strcmp(cmd, "add_module") == 0) {
		arg1 = read_arg(next, &next);
		arg2 = read_arg(next, &next);
		arg3 = read_arg(next, &next);
		arg4 = read_arg(next, &next);
		if (!arg1 || !arg2 || !arg3) {
			fprintf(output, "; Error: missing argument in add_module command\n");
		} else {
			if (!hsm_token_attached(NULL, arg1)) {
				iresult = hsm_attach(arg1, arg2, arg3, arg4);
				if (iresult != 0) {
					fprintf(output, "; Error adding token '%s'\n", arg1);
				}
			}
		}
	} else if (strcmp(cmd, "del_module") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in add_module command\n");
		} else {
			iresult = hsm_detach(arg1);
		}
	} else if (strcmp(cmd, "add_zsk") == 0) {
		arg1 = read_arg(next, &next);
		arg2 = read_arg(next, &next);
		arg3 = read_arg(next, &next);
		if (!arg1 || !arg2 || !arg3) {
			fprintf(output, "; Error: missing argument in add_key command\n");
		} else {
			/*result = add_key(output, cfg, arg1, arg2, arg3, arg4);*/
			/* todo find hsm_key */
			key_list_add_key(cfg->zsks, arg1, arg2, arg3, cfg);
		}
	} else if (strcmp(cmd, "add_ksk") == 0) {
		arg1 = read_arg(next, &next);
		arg2 = read_arg(next, &next);
		arg3 = read_arg(next, &next);
		if (!arg1 || !arg2 || !arg3) {
			fprintf(output, "; Error: missing argument in add_key command\n");
		} else {
			/*result = add_key(output, cfg, arg1, arg2, arg3, arg4);*/
			/* todo find hsm_key */
			key_list_add_key(cfg->ksks, arg1, arg2, arg3, cfg);
		}
	} else if (strcmp(cmd, "flush_keys") == 0) {
		/* TODO */
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
			fprintf(output, "; Error: missing argument in origin command\n");
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
handle_comment(char *line, int line_len, FILE *output)
{
	/* pass comments */
	if (line_len > 15 && strncmp(line, "; Last refresh stats: ", 15) == 0) {
		/* except stats */
	} else if (line_len > 8 && strncmp(line, "; Error ", 8) == 0) {
		/* and previous errors */
	} else {
		fprintf(output, "%s\n", line);
	}
}

void
update_soa_record(ldns_rr *soa, current_config *cfg)
{
	if (cfg->soa_ttl != 0) {
		ldns_rr_set_ttl(soa, cfg->soa_ttl);
	}
	if (cfg->soa_serial != 0) {
		ldns_rdf_deep_free(ldns_rr_rdf(soa, 2));
		ldns_rr_set_rdf(soa,
						ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32,
											  cfg->soa_serial),
						2);
	}
	if (cfg->soa_minimum != 0) {
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
	reader->skipped_rr = NULL;
	reader->file = file;

	return reader;
}

/* comments and commands are handled by their functions,
 * the first rr read is returned
 * garbage is skipped
 */
ldns_rr *
read_rr_from_file(FILE *file, FILE *out, current_config *cfg)
{
	char line[MAX_LINE_LEN];
	int line_len;
	ldns_rr *rr = NULL;
	ldns_status status, cmd_res;
	
	while (!rr) {
		line_len = read_line(file, line);
		if (line_len < 0) {
			return NULL;
		}
		if (line_len == 0 || line[0] == '\n') {
			continue;
		}
		if (line[0] == ';') {
			handle_comment(line, line_len, out);
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
read_rrset(rrset_reader_t *reader, FILE *out, current_config *cfg)
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
		rr = read_rr_from_file(reader->file, out, cfg);
		if (!rr) {
			if (ldns_rr_list_rr_count(rrset) == 0) {
				ldns_rr_list_free(rrset);
				return NULL;
			} else {
				return rrset;
			}
		}
		if (ldns_rr_list_rr_count(rrset) > 0 &&
			is_same_rrset(ldns_rr_list_rr(rrset, 0), rr)) {
			ldns_rr_list_push_rr(rrset, rr);
		} else {
			reader->skipped_rr = rr;
			return rrset;
		}
	}
	return NULL;
}

/* same as read_rrset, but only return RRSIGS. NULL if next rr is not
 * a signature */
ldns_rr_list *
read_signatures(rrset_reader_t *reader, FILE *out, current_config *cfg)
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
		rr = read_rr_from_file(reader->file, out, cfg);
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
	for (i = 0; i < ldns_rr_list_rr_count(sigs); i++) {
		/* if refresh is zero, we just drop existing
		 * signatures. Otherwise, we'll have to check
		 * them and mark which keys should still be used
		 * to create new ones
		 * 
		 * *always* update SOA RRSIG
		 */
		cur_sig = ldns_rr_list_rr(sigs, i);
		cfg->existing_sigs++;
		if (cfg->refresh != 0 || ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(cur_sig)) == LDNS_RR_TYPE_SOA) {
			if (ldns_rdf2native_int32(ldns_rr_rrsig_expiration(cur_sig)) < cfg->refresh ||
				ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(cur_sig)) == LDNS_RR_TYPE_SOA) {
				/* ok, drop sig, resign */
				cfg->removed_sigs++;
			} else {
				/* leave sig, disable key */
				/* but only if it wasn't disabled yet */
				if (key_enabled_for(cfg->zsks, cur_sig)) {
					ldns_rr_print(output, cur_sig);
					disable_key_for(cfg->zsks, cur_sig);
				}
				if (key_enabled_for(cfg->ksks, cur_sig)) {
					ldns_rr_print(output, cur_sig);
					disable_key_for(cfg->ksks, cur_sig);
				}
			}
		}
	}
}

void
sign_rrset(ldns_rr_list *rrset,
           FILE *output,
           current_config *cfg)
{
	size_t i;
	ldns_rr *sig;
	key_list *keys;
	hsm_sign_params_t *params;
	params = hsm_sign_params_new();
	if (!cfg->origin) {
		fprintf(stderr, "Origin not set! Unable to continue.\n");
		exit(1);
	}
	params->owner = ldns_rdf_clone(cfg->origin);
	params->inception = cfg->inception;
	if (ldns_rr_get_type(ldns_rr_list_rr(rrset, 0)) ==
	                           LDNS_RR_TYPE_DNSKEY) {
		keys = cfg->ksks;
	} else {
		keys = cfg->zsks;
	}
	ldns_rr_list_print(output, rrset);
	for (i = 0; i < keys->key_count; i++) {
		if (keys->use_key[i]) {
			params->keytag = keys->keytags[i];
			params->algorithm = keys->algorithms[i];
			params->expiration = cfg->expiration + rand() % cfg->jitter;
			sig = hsm_sign_rrset(NULL, rrset,
								 keys->keys[i], params);
			cfg->created_sigs++;
			ldns_rr_print(output, sig);
			ldns_rr_free(sig);
		}
	}
	hsm_sign_params_free(params);
}

int
compare_list_rrset(ldns_rr_list *a, ldns_rr_list *b)
{
	if (ldns_rr_list_rr_count(a) == 0) {
		if (ldns_rr_list_rr_count(b) == 0) {
			return 0;
		} else {
			return -1;
		}
	}
	if (ldns_rr_list_rr_count(b) == 0) {
		if (ldns_rr_list_rr_count(a) == 0) {
			return 0;
		} else {
			return 1;
		}
	}
	return ldns_rr_compare_no_rdata(ldns_rr_list_rr(a, 0),
	                                ldns_rr_list_rr(b, 0));
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
	ldns_rr_list *new_zone_rrset;
	ldns_rr_list *new_zone_signatures;
	ldns_rr_list *signed_zone_rrset;
	ldns_rr_list *signed_zone_signatures;
	int cmp;
	
	new_zone_reader = rrset_reader_new(input);
	if (signed_zone) {
		signed_zone_reader = rrset_reader_new(signed_zone);
	} else {
		signed_zone_reader = NULL;
	}

	while((new_zone_rrset = read_rrset(new_zone_reader, output, cfg))) {
		if (ldns_rr_list_rr_count(new_zone_rrset) == 0) {
			ldns_rr_list_free(new_zone_rrset);
			continue;
		}
		/* ldns_rr_list_print(output, new_zone_rrset); */
		new_zone_signatures = read_signatures(new_zone_reader,
		                                      output, cfg);
		enable_keys(cfg);
		/* if we have no previously signed zone, check for sigs
		 * in input, and sign the rest */
		if (!signed_zone_reader) {
			check_existing_sigs(new_zone_signatures, output, cfg);
			sign_rrset(new_zone_rrset, output, cfg);
		} else {
			/* now we have a few scenarios, either this rrset is new
			 * or not. If not, it has either changed or not. If not,
			 * there may be signatures in the old zone file as well
			 */
			signed_zone_rrset = read_rrset(signed_zone_reader, output, cfg);
			signed_zone_signatures = read_signatures(signed_zone_reader, output, cfg);
			cmp = compare_list_rrset(new_zone_rrset, signed_zone_rrset);
			/* if the cur rrset name > signed rrset name then data has
			 * been removed, reread signed rrset */
			while (cmp > 0 && signed_zone_rrset) {
				ldns_rr_list_deep_free(signed_zone_rrset);
				if (signed_zone_signatures) ldns_rr_list_deep_free(signed_zone_signatures);
				signed_zone_rrset = read_rrset(signed_zone_reader, output, cfg);
				signed_zone_signatures = read_signatures(signed_zone_reader, output, cfg);
				cmp = compare_list_rrset(new_zone_rrset, signed_zone_rrset);
			}
			/* if the cur rrset name < signer rrset name then data is new
			 */
			while (cmp < 0 && new_zone_rrset) {
				check_existing_sigs(new_zone_signatures, output, cfg);
				/* ldns_rr_list_print(output, new_zone_rrset); */
				sign_rrset(new_zone_rrset, output, cfg);
				ldns_rr_list_deep_free(new_zone_rrset);
				ldns_rr_list_deep_free(new_zone_signatures);
				new_zone_rrset = read_rrset(new_zone_reader, output, cfg);
				new_zone_signatures = read_signatures(new_zone_reader, output, cfg);
				cmp = compare_list_rrset(new_zone_rrset, signed_zone_rrset);
			}
			/* if same, and rrset not same, treat as new */
			/* if same, and rrset same, check old sigs as well */
			/* sigs with same keytag in input get priority */
			if (cmp == 0) {
				if (ldns_rr_list_compare(new_zone_rrset, signed_zone_rrset) != 0) {
					check_existing_sigs(new_zone_signatures, output, cfg);
					sign_rrset(new_zone_rrset, output, cfg);
				} else {
					check_existing_sigs(new_zone_signatures, output, cfg);
					check_existing_sigs(signed_zone_signatures, output, cfg);
					sign_rrset(new_zone_rrset, output, cfg);
				}
			}
			/* in our search for the next signed rrset, we may have
			 * reached the end, in which case we have new rrsets at
			 * the input */
			if (cmp > 0 && !signed_zone_rrset) {
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
	return 0;
}

int main(int argc, char **argv)
{
	current_config *cfg;
	int c;
	FILE *input;
	FILE *output;
	FILE *prev_zone = NULL;
	bool echo_input = true;
	int result;

	cfg = current_config_new();
	input = stdin;
	output = stdout;

	hsm_open(NULL, NULL, NULL);

	while ((c = getopt(argc, argv, "f:hnp:w:")) != -1) {
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
		case 'p':
			prev_zone = fopen(optarg, "r");
			if (!prev_zone) {
				fprintf(stderr,
						"Error: unable to open %s: %s\n",
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
		}
	}

	result = 0;
	result = read_input(input, prev_zone, output, cfg);
	
	hsm_close();
	fprintf(output, "; Last refresh stats: existing: %lu, removed %lu, created %lu\n",
	        cfg->existing_sigs,
	        cfg->removed_sigs,
	        cfg->created_sigs);

	if (result == 1) {
		return 0;
	} else {
		return 1;
	}
}
