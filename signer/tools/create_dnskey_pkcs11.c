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

/*
 * create_dnskey_pkcs11.c
 *
 * Generates a DNSKEY resource record from the data in an HSM token
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>

#include <ldns/ldns.h>
#include <uuid/uuid.h>

#include <libhsm.h>
#include <libhsmdns.h>

#define DEFAULT_TTL 3600
#define DEFAULT_FLAGS 256
/*#define DEFAULT_PROTOCOL 3*/
/* TODO: try to derive default from key? */
#define DEFAULT_ALGORITHM 5

/*
 * Parses the null-terminated string key_id_str as hex values,
 * and sets the given uuid to that value
 */
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

/* TODO: we can actually check whether the algorithm matches here if
 * we want*/
static void
usage(FILE *out)
{
	fprintf(out, "Usage: create_dnskey_pkcs11 [options] <CKA_ID(s)>\n\n");
	fprintf(out, "CKA_ID is the hexadecimal representation of the CKA_ID field of the\n");
	fprintf(out, "intended key. Multiple values can be given.\n");
	fprintf(out, "If the token is found, but none of the keys are present on the token,\n");
	fprintf(out, "nothing is printed and an error value is returned\n\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-a <algorithm>\tSet DNSKEY algorithm (default %u)\n", DEFAULT_ALGORITHM);
	fprintf(out, "-f <flags>\tflags for the DNSKEY RR (defult %u)\n", DEFAULT_FLAGS);
	fprintf(out, "-h\t\tShow this help screen\n");
	fprintf(out, "-t <ttl>\tTTL for the DNSKEY RR (default %u)\n", DEFAULT_TTL);
	fprintf(out, "-m <module>\tUse <module> as PKCS11 module\n");
	fprintf(out, "-n <token name>\tUse the token <token name> from the pkcs #11 module (mandatory)\n");
	fprintf(out, "-o <origin>\tUse origina as zone name (mandatory)\n");
/*	fprintf(out, "-r <protocol>\tSet protocol for DNSKEY RR (default %u)\n", DEFAULT_PROTOCOL);*/
	fprintf(out, "-p <PIN>\tUse PIN for PKCS11 token\n");
	fprintf(out, "-v <level>\tSets verbosity level\n");
}

int
main(int argc, char **argv)
{
	/* general options */
	int verbosity = 1;
	int c;
	
	/* key data */
	int flags_i;
	ldns_rr *key_rr;
	uint32_t ttl = DEFAULT_TTL;
	char *token_name = NULL;

	uuid_t key_uuid;
	hsm_sign_params_t *params;
	hsm_key_t *key;
	
	int result;
	char *pkcs11_lib_file = NULL;
	char *pin = NULL;
	int tries;
	
	/* internal variables */
	int found = 0;
	int argi;

	params = hsm_sign_params_new();
	params->algorithm = DEFAULT_ALGORITHM;
	params->flags = DEFAULT_FLAGS;
	
	hsm_open(NULL, NULL, NULL);
	while ((c = getopt(argc, argv, "a:f:hm:n:o:p:r:t:v:")) != -1) {
		switch(c) {
			case 'a':
				params->algorithm = atoi(optarg);
				break;
			case 'f':
				flags_i = atoi(optarg);
				if (flags_i >= 0 && flags_i < 65536) {
					params->flags = (uint16_t) flags_i;
				} else {
					fprintf(stderr,
					        "Error: bad flags value: %s\n", optarg);
					exit(1);
				}
				break;
			case 'h':
				usage(stdout);
				exit(0);
				break;
			case 'm':
				pkcs11_lib_file = optarg;
				break;
			case 'n':
				token_name = optarg;
				break;
			case 'o':
				params->owner = ldns_dname_new_frm_str(optarg);
				break;
			case 'p':
				pin = optarg;
				break;
			/*case 'r':
				// todo: check bounds
				protocol = (uint8_t) atoi(optarg);
				break;*/
			case 't':
				/* todo: check bounds */
				ttl = (uint32_t) atoi(optarg);
				break;
			case 'v':
				verbosity = atoi(optarg);
				break;
		}
	}
	
	argc -= optind;
	argv += optind;

	if (!params->owner) {
		fprintf(stderr, "Error: bad or no origin specified\n");
		exit(1);
	}
	if (!token_name) {
		fprintf(stderr, "Error: no token name provided\n");
		exit(2);
	}
	if (!pkcs11_lib_file) {
		fprintf(stderr, "Error: no PKCS#11 library provided\n");
		exit(3);
	}
	/* init the pkcs environment */
	if (!pin) {
		result = HSM_PIN_INCORRECT;
		tries = 0;
		while (result == HSM_PIN_INCORRECT && tries < 3) {
			pin = hsm_prompt_pin(token_name, NULL);
			/* we'll use the token name as the repository name here
			 * (no need to specify a second name for this one-off use)
			 */
			result = hsm_attach(token_name,
			                    token_name,
			                    pkcs11_lib_file,
			                    pin);
			memset(pin, 0, strlen(pin));
			tries++;
		}
	} else {
			result = hsm_attach(token_name,
			                    token_name,
			                    pkcs11_lib_file,
			                    pin);
	}
	if (result != 0) {
		fprintf(stderr, "Failed to initialize token %s\n", token_name);
		if (result == HSM_PIN_INCORRECT) {
			fprintf(stderr, "Incorrect PIN\n");
		}
		exit(1);
	}

	/* read the keys */
	argi = 0;
	while (argi < argc) {
		/* hex representation of the uuid */
		result = keystr2uuid(&key_uuid, argv[argi]);
		
		key = hsm_find_key_by_uuid(NULL, (const uuid_t *)&key_uuid);
		
		/* todo: key_rr */
		key_rr = hsm_get_dnskey(NULL, key, params);
		ldns_rr_set_ttl(key_rr, ttl);
		
		ldns_rr_print(stdout, key_rr);
		found = 1;

		ldns_rr_free(key_rr);
		hsm_key_free(key);

		argi++;
	}
	
	hsm_sign_params_free(params);

	hsm_close();
	
	if (found) {
		return LDNS_STATUS_OK;
	} else {
		return LDNS_STATUS_ERR;
	}
}

