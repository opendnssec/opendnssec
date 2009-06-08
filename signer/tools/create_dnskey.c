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

#include <libhsm.h>
#include <libhsmdns.h>

#define DEFAULT_TTL 3600
#define DEFAULT_FLAGS 256
/*#define DEFAULT_PROTOCOL 3*/
/* TODO: try to derive default from key? */
#define DEFAULT_ALGORITHM 5

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
	fprintf(out, "-c <file>\tSpecifies the OpenDNSSEC config file\n");
	fprintf(out, "-f <flags>\tFlags for the DNSKEY RRs (default %u)\n", DEFAULT_FLAGS);
	fprintf(out, "-h\t\tShow this help screen\n");
	fprintf(out, "-t <ttl>\tTTL for the DNSKEY RR (default %u)\n", DEFAULT_TTL);
/*
	fprintf(out, "-m <module>\tUse <module> as PKCS11 module\n");
	fprintf(out, "-n <token name>\tUse the token <token name> from the pkcs #11 module (mandatory)\n");
	fprintf(out, "-p <PIN>\tUse PIN for PKCS11 token\n");
*/
	fprintf(out, "-o <origin>\tUse origin as zone name (mandatory)\n");
/*	fprintf(out, "-r <protocol>\tSet protocol for DNSKEY RR (default %u)\n", DEFAULT_PROTOCOL);*/
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

	hsm_sign_params_t *params;
	hsm_key_t *key;

	char *config_file = NULL;
	int result;
	
	/* internal variables */
	int found = 0;
	int argi;

	params = hsm_sign_params_new();
	params->algorithm = DEFAULT_ALGORITHM;
	params->flags = DEFAULT_FLAGS;
	
	while ((c = getopt(argc, argv, "a:c:f:ho:r:t:v:")) != -1) {
		switch(c) {
			case 'a':
				params->algorithm = atoi(optarg);
				break;
			case 'c':
				config_file = optarg;
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
			case 'o':
				params->owner = ldns_dname_new_frm_str(optarg);
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

	if (!config_file) {
		fprintf(stderr, "Error: no configuration file specified\n");
		exit(1);
	}
	if (!params->owner) {
		fprintf(stderr, "Error: bad or no origin specified\n");
		exit(2);
	}

	result = hsm_open(config_file, hsm_prompt_pin, NULL);
	if (result != HSM_OK) {
		fprintf(stderr, "Error initializing libhsm\n");
		exit(3);
	}
	
	/* read the keys */
	argi = 0;
	while (argi < argc) {
		key = hsm_find_key_by_id(NULL, argv[argi]);

		if (key) {
			/* todo: key_rr */
			key_rr = hsm_get_dnskey(NULL, key, params);
			if (key_rr) {
				ldns_rr_set_ttl(key_rr, ttl);
				
				ldns_rr_print(stdout, key_rr);
				found = 1;

				ldns_rr_free(key_rr);
			} else {
				fprintf(stderr, "Error creating DNSKEY RR for %s\n",
				        argv[argi]);
			}
			hsm_key_free(key);
		} else {
			fprintf(stderr, "Unable to find key with id %s\n",
			        argv[argi]);
		}
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

