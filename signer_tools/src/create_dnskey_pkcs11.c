/**
 * This tool can be used to create DNSKEY records from pkcs11 keys
 * TODO: add options for KSK and other flags
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>

#include <ldns/ldns.h>

#include "ldns_pkcs11.h"

#define DEFAULT_TTL 3600
#define DEFAULT_FLAGS 256
/*#define DEFAULT_PROTOCOL 3*/
/* TODO: try to derive default from key? */
#define DEFAULT_ALGORITHM 5

/* TODO: we can actually check whether the algorithm matches here if
 * we want*/
void
usage(FILE *out)
{
	fprintf(out, "Usage: create_dnskey_pkcs11 [options]\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-a <algorithm>\tSet DNSKEY algorithm (default %u\n", DEFAULT_ALGORITHM);
	fprintf(out, "-f <flags>\tflags for the DNSKEY RR (defult %u)\n", DEFAULT_FLAGS);
	fprintf(out, "-h\t\tShow this help screen\n");
	fprintf(out, "-t <ttl>\tTTL for the DNSKEY RR (default %u)\n", DEFAULT_TTL);
	fprintf(out, "-m <module>\tUse <module> as PKCS11 module\n");
	fprintf(out, "-o <origin>\tUse origina as zone name (mandatory\n");
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
	ldns_rdf *origin = NULL;
	
	/* key data */
	int argi;
	char *key_id;
	int key_id_len;
	ldns_key *key;
	ldns_rr *key_rr;
/*	uint8_t protocol = DEFAULT_PROTOCOL;*/
	ldns_algorithm key_algorithm = DEFAULT_ALGORITHM;
	uint32_t ttl = DEFAULT_TTL;
	uint16_t flags = DEFAULT_FLAGS;
	
	/* pkcs11 vars */
	char *pkcs11_lib_file = NULL;
	//   "/usr/local/lib/libsofthsm.so";
	ldns_pkcs11_ctx *pkcs11_ctx;
	char *pin = NULL;
	
	/* internal variables */
	ldns_status status;

	while ((c = getopt(argc, argv, "a:f:hm:o:p:r:t:v:")) != -1) {
		switch(c) {
			case 'a':
				key_algorithm = atoi(optarg);
				break;
			case 'f':
				// todo: check bounds
				flags = (uint16_t) atoi(optarg);
				break;
			case 'h':
				usage(stdout);
				exit(0);
				break;
			case 'm':
				pkcs11_lib_file = optarg;
				break;
			case 'o':
				origin = ldns_dname_new_frm_str(optarg);
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

	if (!origin) {
		fprintf(stderr, "Error: bad or no origin specified\n");
		exit(1);
	}

	/* init the pkcs environment */
	pkcs11_ctx = ldns_initialize_pkcs11(pkcs11_lib_file,
	                                    pin);
	if (!pkcs11_ctx) {
		fprintf(stderr, "Failed to initialize PKCS11 context\n");
		exit(1);
	}

	/* read the keys */
	argi = 0;
	while (argi < argc) {
		/* of the form <key_id>_<algorithm number> */
		key_id = ldns_keystr2id(argv[argi], &key_id_len);

		/* todo: protocol? is it ever different than 3? */
		status = ldns_key_new_frm_pkcs11(pkcs11_ctx,
		                                 &key,
		                                 key_algorithm,
		                                 key_id,
		                                 key_id_len);
		if (status == LDNS_STATUS_OK) {
			ldns_key_set_flags(key, flags);
			ldns_key_set_pubkey_owner(key, ldns_rdf_clone(origin));
		} else {
			argi++;
			continue;
		}
		
		key_rr = ldns_key2rr_pkcs(pkcs11_ctx,
		                          key);
		ldns_rr_set_ttl(key_rr, ttl);
		
		ldns_rr_print(stdout, key_rr);

		free(key_id);
		ldns_rr_free(key_rr);
		pkcs_keypair_handle_free(ldns_key_external_key(key));
		ldns_key_deep_free(key);

		argi++;
	}
	
	ldns_finalize_pkcs11(pkcs11_ctx);
	if (origin) {
		ldns_rdf_deep_free(origin);
	}
	return LDNS_STATUS_OK;
}

