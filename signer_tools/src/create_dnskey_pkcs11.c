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

void
usage(FILE *out)
{
	fprintf(out, "Usage: create_dnskey_pkcs11 [options]\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-h\t\tShow this help screen\n");
	fprintf(out, "-m <module>\tUse <module> as PKCS11 module\n");
	fprintf(out, "-o <origin>\tUse origina as zone name (mandatory\n");
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
	ldns_algorithm key_algorithm;
	
	/* pkcs11 vars */
	char *pkcs11_lib_file = NULL;
	//   "/usr/local/lib/libsofthsm.so";
	ldns_pkcs11_ctx *pkcs11_ctx;
	char *pin = NULL;
	
	/* internal variables */
	ldns_status status;

	while ((c = getopt(argc, argv, "hm:o:p:v:")) != -1) {
		switch(c) {
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
		key_algorithm = ldns_keystr2algorithm(argv[argi]);
		if (key_algorithm == 0) {
			fprintf(stderr, "Bad algorithm in %s\n", argv[argi]);
			exit(1);
		}

		status = ldns_key_new_frm_pkcs11(pkcs11_ctx,
		                                 &key,
		                                 key_algorithm,
		                                 key_id,
		                                 key_id_len);
		if (status == LDNS_STATUS_OK) {
			ldns_key_set_pubkey_owner(key, ldns_rdf_clone(origin));
		}
		
		key_rr = ldns_key2rr_pkcs(pkcs11_ctx,
		                          key);

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

