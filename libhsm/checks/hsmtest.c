/*
 * $Id$
 *
 * Copyright (c) 2009 Nominet UK.
 * All rights reserved.
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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libhsm.h>

int
main (int argc, char *argv[])
{
	int result;
	//hsm_ctx_t *ctx;
	hsm_key_t **keys;
	hsm_key_t *key = NULL;
	uuid_t *uuid;
	size_t key_count = 0;
	size_t i;
	ldns_rr_list *rrset;
	ldns_rr *rr, *sig;
	ldns_status status;
	hsm_sign_params_t *sign_params;

	int do_generate = 0;
	int do_sign = 0;
	int do_show = 1;
	int do_delete = 0;
	int do_random = 0;

	int res;
	uint32_t r32;
	uint64_t r64;

	const char *repository = "regress";

	int ch;

	while ((ch = getopt(argc, argv, "gsdr")) != -1) {
		switch (ch) {
		case 'g':
			do_generate = 1;
			do_show = 0;
			break;
		case 's':
			do_sign = 1;
			do_show = 0;
			break;
		case 'd':
			do_delete = 1;
			do_show = 0;
			break;
		case 'r':
			do_show = 0;
			do_random = 1;
			break;
		default:
			fprintf(stderr, "usage: %s [-gsd]\n", argv[0]);
			exit(1);
		}
	}

	fprintf(stdout, "Starting HSM lib test\n");
	result = hsm_open(getenv("HSMTEST_CONF"), hsm_prompt_pin, NULL);
	fprintf(stdout, "hsm_open result: %d\n", result);

	//ctx = hsm_create_context();
	/*printf("global: ");
	hsm_print_ctx(NULL);
	printf("my: ");
	hsm_print_ctx(ctx);
	*/

	if (do_generate) {
		/* generate new key */
		key = hsm_generate_rsa_key(NULL, repository, 1024);
		if (key) {
			printf("Created key:\n");
			hsm_print_key(key);
		} else {
			printf("Error creating key, bad token name?\n");
		}
	} else {
		/* use any key found */
		keys = hsm_list_keys(NULL, &key_count);
		printf("I have found %u keys\n", (unsigned int) key_count);

		/* let's just use the very first key we find and throw away the rest */
		for (i = 0; i < key_count; i++) {
			if (do_show) {
				hsm_print_key(keys[i]);
			}
			if ((do_sign || do_delete) && !key) {
				/* only use keys with uuid */
				uuid = hsm_get_uuid(NULL, keys[i]);
				if (uuid) {
					key = hsm_find_key_by_uuid(NULL, uuid);
				}
			}
			hsm_key_free(keys[i]);
		}
		free(keys);
	}

	/* print "active" key */
	if (key) {
		hsm_print_key(key);
		hsm_key_free(key);
	}

	/* do some signing with it */
	if (do_sign) {
		rrset = ldns_rr_list_new();
		status = ldns_rr_new_frm_str(&rr, "regress.opendnssec.se.	IN	A	123.123.123.123", 0, NULL, NULL);
		if (status == LDNS_STATUS_OK) ldns_rr_list_push_rr(rrset, rr);
		status = ldns_rr_new_frm_str(&rr, "regress.opendnssec.se.	IN	A	124.124.124.124", 0, NULL, NULL);
		if (status == LDNS_STATUS_OK) ldns_rr_list_push_rr(rrset, rr);

		sign_params = hsm_sign_params_new();
		sign_params->algorithm = LDNS_RSASHA1;
		sign_params->owner = ldns_rdf_clone(ldns_rr_owner(rr));
		ldns_rr_list_print(stdout, rrset);
		sig = hsm_sign_rrset(NULL, rrset, key, sign_params);
		ldns_rr_print(stdout, sig);
		/* cleanup */
		ldns_rr_list_deep_free(rrset);
		ldns_rr_free(sig);
		hsm_sign_params_free(sign_params);
	}

	if (do_delete) {
		printf("Delete key:\n");
		hsm_print_key(key);
		//res = hsm_remove_key(ctx, key);
		res = hsm_remove_key(NULL, key);
		printf("Deleted key. Result: %d\n", res);
	}

	/* test random{32,64} functions */
	if (do_random) {
		r32 = hsm_random32(NULL);
		printf("random 32: %u\n", r32);
		r64 = hsm_random64(NULL);
		printf("random 64: %llu\n", r64);
	}

	//hsm_destroy_context(ctx);

	result = hsm_close();
	fprintf(stdout, "all done! hsm_close result: %d\n", result);
	return 0;
}
