/*
 * $Id: signer.c 1222 2009-07-01 17:16:57Z jelte $
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

#include <pthread.h>
#define PTHREAD_THREADS_MAX 2048

#include <ldns/ldns.h>

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
	uint32_t expiration_denial;
	uint32_t refresh;
	uint32_t refresh_denial;
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

	int verbosity;

	struct timeval start;
} current_config;

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
	size_t i;
	if (list->keys) {
		for (i = 0; i < list->key_count; i++) {
			if (list->keys[i]) {
				hsm_key_free(list->keys[i]);
			}
		}
		free(list->keys);
	}
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
	cfg->expiration_denial = 0;
	cfg->refresh = 0;
	cfg->refresh_denial = 0;
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
	cfg->verbosity = 1;
	gettimeofday(&(cfg->start), NULL);
	return cfg;
}

void
current_config_free(current_config *cfg)
{
	if (cfg) {
		if (cfg->origin) {
			ldns_rdf_deep_free(cfg->origin);
		}
		if (cfg->zsks) key_list_free(cfg->zsks);
		if (cfg->ksks) key_list_free(cfg->ksks);
		free(cfg);
	}
}

void
print_stats(FILE *out, current_config *cfg)
{
	struct timeval end;
	double elapsed;
	double speed;

	gettimeofday(&end, NULL);
	end.tv_sec -= cfg->start.tv_sec;
	end.tv_usec-= cfg->start.tv_usec;
	elapsed =(double)(end.tv_sec)+(double)(end.tv_usec)*.000001;
	speed = cfg->created_sigs / elapsed;

	fprintf(out, "; running time: %.2f secs, sigs created %lu, %.2f sigs/s\n",
	        elapsed, cfg->created_sigs, speed);
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

void
init_print_buf(char **print_buf, size_t size)
{
	memset(print_buf, 0, sizeof(char *) * size);
}

typedef struct pb_entry {
	size_t pos;
	char *data;
	struct pb_entry *next;
} pb_entry;

pb_entry *
pb_entry_new(size_t pos, char *data)
{
	pb_entry *pbe = malloc(sizeof(pb_entry));
	pbe->pos = pos;
	pbe->data = data;
	pbe->next = NULL;
	return pbe;
}

void
pb_entry_free(pb_entry *pbe)
{
	if (pbe) {
		if (pbe->data) free(pbe->data);
		free(pbe);
	}
}

/* prints and frees the entry, if the entry has a *next, it is returned
 * otherwise it returns NULL;
 */
pb_entry *
pb_entry_print(FILE *out, pb_entry *pbe)
{
	pb_entry *next = NULL;
	if (pbe) {
		/*fprintf(out, "%03u %s", pbe->pos, pbe->data);*/
		fprintf(out, "%s", pbe->data);
		next = pbe->next;
	}
	return next;
}

typedef struct {
	FILE *out;
	pb_entry *first;
	int done;
	pthread_mutex_t *lock;
} print_buffer;

print_buffer *
print_buffer_new(FILE *out)
{
	print_buffer *pb = malloc(sizeof(print_buffer));
	pb->out = out;
	pb->first = NULL;
	pb->done = 0;
	pb->lock = malloc(sizeof(pthread_mutex_t));
	pthread_mutex_init(pb->lock, NULL);
	return pb;
}

void
print_buffer_free(print_buffer *pb)
{
	if (pb) {
		pthread_mutex_destroy(pb->lock);
		free(pb->lock);
		free(pb);
	}
}

void
pb_lock(print_buffer *pb)
{
	pthread_mutex_lock(pb->lock);
}

void
pb_release(print_buffer *pb)
{
	pthread_mutex_unlock(pb->lock);
}

int
print_buffer_add_entry(print_buffer *pb, pb_entry *pbe)
{
	pb_entry *cur;
	if (!pb || !pbe) return 0;
	/*fprintf(stderr, "[XX] lock pb for add\n");*/
	pb_lock(pb);
	if (!pb->first) {
		/*fprintf(stderr, "[XX] new first (%u)\n", pbe->pos);*/
		pb->first = pbe;
	} else {
		if (pbe->pos < pb->first->pos) {
			pbe->next = pb->first;
			/*fprintf(stderr, "[XX] %u before first (%u)\n", pbe->pos, pb->first->pos);*/
			pb->first = pbe;
		} else {
			cur = pb->first;
			while (cur) {
				if (cur->next) {
					if (pbe->pos < cur->next->pos) {
						/*fprintf(stderr, "[XX] %u between %u and %u\n", pbe->pos, cur->pos, cur->next->pos);*/
						pbe->next = cur->next;
						cur->next = pbe;
						cur = NULL;
					} else {
						cur = cur->next;
					}
				} else {
					/*fprintf(stderr, "[XX] %u last; after %u\n", pbe->pos, cur->pos);*/
					cur->next = pbe;
					cur = NULL;
				}
			}
		}
	}
	/*fprintf(stderr, "[XX] release pb for add\n");*/
	pb_release(pb);
	return 1;
}

void *
print_buf(void *pbv)
{
	print_buffer *pb = (print_buffer *)pbv;
	pb_entry *pbe = NULL, *prev_pbe;
	size_t pos = 0;
	while (!pb->done) {
		/*fprintf(stderr, "[XX] lock pb for printf\n");*/
		pb_lock(pb);
		if (pb->first && pb->first->pos == pos) {
			pbe = pb->first;
			pb->first = pbe->next;
		}
		/*fprintf(stderr, "[XX] release pb for print\n");*/
		pb_release(pb);
		if (pbe) {
			pb_entry_print(pb->out, pbe);
			pb_entry_free(pbe);
			pbe = NULL;
			pos++;
		}
	}
	/* when we stop, handle rest of queue */
	pbe = pb->first;
	while (pbe) {
		pb_entry_print(pb->out, pbe);
		prev_pbe = pbe;
		pbe = pbe->next;
		pb_entry_free(prev_pbe);
	}
	return NULL;
}

void
print_rr(print_buffer *pb, ldns_rr *rr, const size_t pos)
{
	pb_entry *pbe;
	pbe = pb_entry_new(pos, ldns_rr2str(rr));
	(void) print_buffer_add_entry(pb, pbe);
}

void
print_rr_list(print_buffer *pb, ldns_rr_list *rr_list, size_t *pos)
{
	size_t i;
	for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
		print_rr(pb, ldns_rr_list_rr(rr_list, i), *pos);
		(*pos)++;
	}
}

typedef struct sign_buffer_entry {
	ldns_rr_list *rrset;
	hsm_key_t *key;
	hsm_sign_params_t *params;
	struct sign_buffer_entry *next;
	size_t pos;
} sign_buffer_entry;

typedef struct {
	size_t number;
	pthread_mutex_t *lock;
	int done;
	sign_buffer_entry *first;
	hsm_ctx_t *ctx;
	print_buffer *pb;
} sign_buffer;

sign_buffer *
sign_buffer_new(print_buffer *pb, size_t number)
{
	sign_buffer *sb = malloc(sizeof(sign_buffer));
	sb->number = number;
	sb->lock = malloc(sizeof(pthread_mutex_t));
	pthread_mutex_init(sb->lock, NULL);
	sb->done = 0;
	sb->first = NULL;
	sb->ctx = hsm_create_context();
	sb->pb = pb;
	return sb;
}

void
sign_buffer_free(sign_buffer *sb)
{
	if (sb) {
		pthread_mutex_destroy(sb->lock);
		free(sb->lock);
		if (sb->ctx) hsm_destroy_context(sb->ctx);
		free(sb);
	}
}

void
sign_buffer_lock(sign_buffer *sb)
{
	pthread_mutex_lock(sb->lock);
}

void
sign_buffer_release(sign_buffer *sb)
{
	pthread_mutex_unlock(sb->lock);
}

void
sign_buffer_add_entry(sign_buffer *sb, sign_buffer_entry *sbe)
{
	sign_buffer_entry *cur;
	if (!sb || !sbe) return;
	sign_buffer_lock(sb);
	if (!sb->first) {
		sb->first = sbe;
	} else {
		cur = sb->first;
		while(cur->next) {
			cur = cur->next;
		}
		cur->next = sbe;
	}
	sign_buffer_release(sb);
}

hsm_sign_params_t *
hsm_sign_params_clone(hsm_sign_params_t *params) {
    hsm_sign_params_t *newp;
    if (!params) {
        return NULL;
    }
    newp = hsm_sign_params_new();
    newp->algorithm = params->algorithm;
    newp->flags = params->flags;
    newp->inception = params->inception;
    newp->expiration = params->expiration;
    newp->keytag = params->keytag;
    newp->owner = ldns_rdf_clone(params->owner);
    return newp;
}

sign_buffer_entry *
sign_buffer_entry_new(ldns_rr_list *rrset, hsm_key_t *key, hsm_sign_params_t *params, size_t pos)
{
	/* rrset and params can be cleared before we get to them, so for
	 * now we must clone them */
	sign_buffer_entry *sbe = malloc(sizeof(sign_buffer_entry));
	sbe->rrset = ldns_rr_list_clone(rrset);
	sbe->key = key;
	sbe->params = hsm_sign_params_clone(params);
	sbe->pos = pos;
	sbe->next = NULL;
	return sbe;
}

void
sign_buffer_entry_free(sign_buffer_entry *sbe)
{
	if (sbe) {
		ldns_rr_list_deep_free(sbe->rrset);
		hsm_sign_params_free(sbe->params);
		free(sbe);
	}
}

void *
sign_sign_buffer(void *sbv)
{
	sign_buffer *sb = (sign_buffer *) sbv;
	sign_buffer_entry *sbe = NULL, *prev_sbe;
	ldns_rr *sig;

	/*fprintf(stderr, "[XX] sign_sign start %u\n", sb->number);*/
	while (!sb->done) {
		/*fprintf(stderr, "[XX] sign_sign %u count %u\n", sb->number, sb->count);*/
		sign_buffer_lock(sb);
		sbe = sb->first;
		if (sbe) {
			sb->first = sbe->next;
		}
		sign_buffer_release(sb);

		if (sbe) {
			sig = hsm_sign_rrset(sb->ctx, sbe->rrset,  sbe->key, sbe->params);
			print_rr(sb->pb, sig, sbe->pos);
			sign_buffer_entry_free(sbe);
			sbe = NULL;
			ldns_rr_free(sig);
		} else {
			/* nothing to do, wait for a little bit */
			usleep(10);
		}
	}
	/* handle the rest */
	sbe = sb->first;
	while (sbe) {
		sig = hsm_sign_rrset(sb->ctx, sbe->rrset,  sbe->key, sbe->params);
		print_rr(sb->pb, sig, sbe->pos);
		ldns_rr_free(sig);
		prev_sbe = sbe;
		sbe = sbe->next;
		sign_buffer_entry_free(prev_sbe);
	}
	/*fprintf(stderr, "[XX] sign_sign done\n");*/
	return NULL;
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
	if (strcmp(cmd, "add_zsk") == 0) {
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
	} else if (strcmp(cmd, "expiration_denial") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in expiration_denial command\n");
		} else {
			cfg->expiration_denial = parse_time(arg1);
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
	} else if (strcmp(cmd, "refresh_denial") == 0) {
		arg1 = read_arg(next, &next);
		if (!arg1) {
			fprintf(output, "; Error: missing argument in refresh_denial command\n");
		} else {
			cfg->refresh_denial = parse_time(arg1);
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
		line_len = read_line(file, line);
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
                    print_buffer *pb,
                    current_config *cfg,
                    size_t *pos)
{
	size_t i;
	ldns_rr *cur_sig;
	uint32_t expiration;
	uint32_t refresh;
	ldns_rr_type type_covered;

	for (i = 0; i < ldns_rr_list_rr_count(sigs); i++) {
		/* check the refresh date for this signature. If the signature
		 * covers a denial RRset (NSEC or NSEC3), and :expiration_denial
		 * was set to anything other than 0, we need to use
		 * expiration_denial instead of :expiration */
		cur_sig = ldns_rr_list_rr(sigs, i);
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
				/* leave sig, disable key */
				/* but only if it wasn't disabled yet */
				if (key_enabled_for(cfg->zsks, cur_sig)) {
					print_rr(pb, cur_sig, *pos);
					(*pos)++;
					disable_key_for(cfg->zsks, cur_sig);
				}
				if (key_enabled_for(cfg->ksks, cur_sig)) {
					print_rr(pb, cur_sig, *pos);
					(*pos)++;
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

void
sign_rrset(ldns_rr_list *rrset,
           sign_buffer *sb,
           current_config *cfg,
           size_t *pos)
{
	size_t i;
	key_list *keys;
	hsm_sign_params_t *params;

	if (!cfg->origin) {
		fprintf(stderr, "Origin not set! Unable to continue.\n");
		exit(1);
	}

	/* skip delegation rrsets */
	if (rr_list_delegation_only(cfg->origin, rrset)) return;
	
	params = hsm_sign_params_new();
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
				fprintf(stderr, "new signature\n");
			}
			params->keytag = keys->keytags[i];
			params->algorithm = keys->algorithms[i];
			if (cfg->expiration_denial &&
			    (ldns_rr_list_type(rrset) == LDNS_RR_TYPE_NSEC ||
			     ldns_rr_list_type(rrset) == LDNS_RR_TYPE_NSEC3)) {
				params->expiration = cfg->expiration_denial +
			                   (cfg->jitter ? rand() % cfg->jitter : 0);
			} else {
				params->expiration = cfg->expiration +
			                   (cfg->jitter ? rand() % cfg->jitter : 0);
			}
			sign_buffer_add_entry(sb, sign_buffer_entry_new(rrset, keys->keys[i], params, *pos));

			cfg->created_sigs++;
			(*pos)++;
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
read_input(FILE *input, FILE *signed_zone, FILE *output, current_config *cfg, size_t si_count)
{
	rrset_reader_t *new_zone_reader, *signed_zone_reader;
	ldns_rr_list *new_zone_rrset = NULL;
	ldns_rr_list *new_zone_signatures= NULL;
	ldns_rr_list *signed_zone_rrset = NULL;
	ldns_rr_list *signed_zone_signatures = NULL;
	int cmp;

	pthread_attr_t thread_attr;
	pthread_t print_thread;
	void *thread_status;
	int result;

	size_t pos = 0;
	print_buffer *pb = print_buffer_new(output);
	size_t si;
	sign_buffer **sbs = malloc(sizeof(sign_buffer *) * si_count);
	pthread_t *sign_threads = malloc(sizeof(pthread_t) * si_count);

	new_zone_reader = rrset_reader_new(input);
	if (signed_zone) {
		signed_zone_reader = rrset_reader_new(signed_zone);
	} else {
		signed_zone_reader = NULL;
	}

	/* fire up the buffered printer */
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);
	result = pthread_create(&print_thread, &thread_attr, &print_buf, (void *) pb);
	if (result) {
		fprintf(stderr, "pthread_create() returned %d\n", result);
		exit(EXIT_FAILURE);
	}
	for (si = 0; si < si_count; si++) {
		sbs[si] = sign_buffer_new(pb, si);
		result = pthread_create(&sign_threads[si], &thread_attr, &sign_sign_buffer, (void *) sbs[si]);
		
		if (result) {
			fprintf(stderr, "pthread_create() returned %d\n", result);
			exit(EXIT_FAILURE);
		}
	}
	si = 0;
	fprintf(stderr, "[XX] starting run\n");

	while((new_zone_rrset = read_rrset(new_zone_reader, output, cfg, 1))) {
		if (ldns_rr_list_rr_count(new_zone_rrset) == 0) {
			ldns_rr_list_free(new_zone_rrset);
			continue;
		}
		if (cfg->verbosity >= 4) {
			fprintf(stderr, "Read rrset from input:\n");
			ldns_rr_list_print(stderr, new_zone_rrset);
		}
		/* ldns_rr_list_print(output, new_zone_rrset); */
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
			print_rr_list(pb, new_zone_rrset, &pos);
			check_existing_sigs(new_zone_signatures, pb, cfg, &pos);
			sign_rrset(new_zone_rrset, sbs[si++], cfg, &pos);
			if (si >= si_count) si = 0;
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
			while (cmp != 0 && 
			       ldns_rr_list_type(new_zone_rrset) == LDNS_RR_TYPE_NSEC3 &&
				   ldns_rr_list_type(signed_zone_rrset) != LDNS_RR_TYPE_NSEC3
			     ) {
				print_rr_list(pb, new_zone_rrset, &pos);
				if (new_zone_signatures) {
					check_existing_sigs(new_zone_signatures, pb, cfg, &pos);
					ldns_rr_list_deep_free(new_zone_signatures);
				}
				if (cfg->verbosity >= 4) {
					fprintf(stderr, "NSEC3, signing\n");
					ldns_rr_list_print(stderr, signed_zone_rrset);
				}
				sign_rrset(new_zone_rrset, sbs[si++], cfg, &pos);
				if (si >= si_count) si = 0;
				ldns_rr_list_deep_free(new_zone_rrset);
				new_zone_rrset = read_rrset(new_zone_reader, output, cfg, 1);
				if (cfg->verbosity >= 4) {
					fprintf(stderr, "Read rrset from input:\n");
					ldns_rr_list_print(stderr, new_zone_rrset);
				}
				new_zone_signatures = read_signatures(new_zone_reader, output, cfg, 1);
				if (cfg->verbosity >= 4) {
					fprintf(stderr, "Read signatures from input:\n");
					ldns_rr_list_print(stderr, new_zone_signatures);
				}
				cmp = compare_list_rrset(new_zone_rrset, signed_zone_rrset);
			}
			
			/* if the cur rrset name > signed rrset name then data has
			 * been removed, reread signed rrset */
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
			}
			/* if the cur rrset name < signer rrset name then data is new
			 */
			while (cmp < 0 && new_zone_rrset) {
				print_rr_list(pb, new_zone_rrset, &pos);
				check_existing_sigs(new_zone_signatures, pb, cfg, &pos);
				if (cfg->verbosity >= 4) {
					fprintf(stderr, "new data, signing\n");
				}
				sign_rrset(new_zone_rrset, sbs[si++], cfg, &pos);
				if (si >= si_count) si = 0;
				ldns_rr_list_deep_free(new_zone_rrset);
				ldns_rr_list_deep_free(new_zone_signatures);
				new_zone_rrset = read_rrset(new_zone_reader, output, cfg, 1);
				if (cfg->verbosity >= 4) {
					fprintf(stderr, "Read rrset from input:\n");
					ldns_rr_list_print(stderr, new_zone_rrset);
				}
				new_zone_signatures = read_signatures(new_zone_reader, output, cfg, 1);
				if (cfg->verbosity >= 4) {
					fprintf(stderr, "Read signatures from input:\n");
					ldns_rr_list_print(stderr, new_zone_signatures);
				}
				cmp = compare_list_rrset(new_zone_rrset, signed_zone_rrset);
			}
			/* if same, and rrset not same, treat as new */
			/* if same, and rrset same, check old sigs as well */
			/* sigs with same keytag in input get priority */
			if (cmp == 0 && new_zone_rrset && signed_zone_rrset) {
				if (ldns_rr_list_compare(new_zone_rrset, signed_zone_rrset) != 0) {
					print_rr_list(pb, new_zone_rrset, &pos);
					check_existing_sigs(new_zone_signatures, pb, cfg, &pos);
					if (cfg->verbosity >= 4) {
						fprintf(stderr, "rrset changed\n");
					}
					sign_rrset(new_zone_rrset, sbs[si++], cfg, &pos);
					if (si >= si_count) si = 0;
				} else {
					print_rr_list(pb, new_zone_rrset, &pos);
					check_existing_sigs(new_zone_signatures, pb, cfg, &pos);
					check_existing_sigs(signed_zone_signatures, pb, cfg, &pos);
					if (cfg->verbosity >= 4) {
						fprintf(stderr, "rrset still the same\n");
					}
					sign_rrset(new_zone_rrset, sbs[si++], cfg, &pos);
					if (si >= si_count) si = 0;
				}
			}
			/* in our search for the next signed rrset, we may have
			 * reached the end, in which case we have new rrsets at
			 * the input */
			if (cmp > 0 && !signed_zone_rrset) {
				print_rr_list(pb, new_zone_rrset, &pos);
				check_existing_sigs(new_zone_signatures, pb, cfg, &pos);
				if (cfg->verbosity >= 4) {
					fprintf(stderr, "new data at end, signing\n");
				}
				sign_rrset(new_zone_rrset, sbs[si++], cfg, &pos);
				if (si >= si_count) si = 0;
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

	if (new_zone_reader) free(new_zone_reader);
	if (signed_zone_reader) free(signed_zone_reader);
	
	for (si = 0; si < si_count; si++) {
		sbs[si]->done = 1;
		pthread_join(sign_threads[si], &thread_status);
		sign_buffer_free(sbs[si]);
	}
	pb->done = 1;
	pthread_join(print_thread, &thread_status);
	free(sbs);
	free(sign_threads);
	print_buffer_free(pb);
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
	size_t si_count = 1;

	cfg = current_config_new();
	input = stdin;
	output = stdout;

	while ((c = getopt(argc, argv, "c:f:hnp:t:w:r")) != -1) {
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
		case 't':
			si_count = (size_t) atoi(optarg);
			if (si_count > 1000 || si_count == 0) {
				fprintf(stderr, "Error: number of signer threads must be 1 - 1000\n");
				exit(1);
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

	result = hsm_open(config_file, hsm_prompt_pin, NULL);
	if (result != HSM_OK) {
		fprintf(stderr, "Error initializing libhsm\n");
		exit(2);
	}
	result = read_input(input, prev_zone, output, cfg, si_count);

	hsm_close();
	fprintf(output, "; Last refresh stats: existing: %lu, removed %lu, created %lu\n",
	        cfg->existing_sigs,
	        cfg->removed_sigs,
	        cfg->created_sigs);

	print_stats(stderr, cfg);
	if (print_creation_count) {
		fprintf(stderr, "Number of signatures created: %lu\n", cfg->created_sigs);
	}

	current_config_free(cfg);
	if (result == 1) {
		return 0;
	} else {
		return 1;
	}
}
