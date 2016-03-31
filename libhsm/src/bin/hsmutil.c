/*
 * Copyright (c) 2009 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2009 NLNet Labs.
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

#include "config.h"
#include "hsmtest.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "libhsm.h"
#include <libhsmdns.h>


extern char *optarg;
char *progname = NULL;
unsigned int verbose = 0;


static void
version ()
{
    fprintf(stderr, "%s (%s) version %s\n",
        progname, PACKAGE_NAME, PACKAGE_VERSION);
}

static void
usage ()
{
    fprintf(stderr,
       "usage: %s [-c config] [-vV] command [options]\n",
        progname);

    fprintf(stderr,"  login\n");
    fprintf(stderr,"  logout\n");
    fprintf(stderr,"  list [repository]\n");
    fprintf(stderr,"  generate <repository> rsa|dsa|gost|ecdsa [keysize]\n");
    fprintf(stderr,"  remove <id>\n");
    fprintf(stderr,"  purge <repository>\n");
    fprintf(stderr,"  dnskey <id> <name> <type> <algo>\n");
    fprintf(stderr,"  test <repository>\n");
    fprintf(stderr,"  info\n");
#if 0
    fprintf(stderr,"  debug\n");
#endif
}

static int
cmd_login ()
{
    printf("The tokens are now logged in.\n");

    return 0;
}

static int
cmd_logout ()
{
    if (hsm_logout_pin() != HSM_OK) {
        printf("Failed to erase the credentials.\n");
        hsm_print_error(NULL);
        return 1;
    }

    printf("The credentials has been erased.\n");

    return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
static int
cmd_list (int argc, char *argv[])
{
    size_t i;
    char *repository = NULL;

    size_t key_count = 0;
    size_t key_count_valid = 0;
    libhsm_key_t **keys;
    hsm_ctx_t *ctx = NULL;

    const char *key_info_format = "%-20s  %-32s  %-10s\n";


    if (argc) {
        repository = argv[0];
        argc--;
        argv++;

        /* Check for repository before starting using it */
        if (hsm_token_attached(ctx, repository) == 0) {
           hsm_print_error(ctx);
           return 1;
        }

        fprintf(stdout, "\nListing keys in repository: %s\n", repository);
        keys = hsm_list_keys_repository(NULL, &key_count, repository);
    } else {
        fprintf(stdout, "\nListing keys in all repositories.\n");
        keys = hsm_list_keys(NULL, &key_count);
    }

    fprintf(stdout, "%u %s found.\n\n", (unsigned int) key_count,
        (key_count > 1 || key_count == 0 ? "keys" : "key"));

    if (!keys) {
        return -1;
    }

    /* print fancy header */
    fprintf(stdout, key_info_format, "Repository", "ID", "Type");
    fprintf(stdout, key_info_format, "----------", "--", "----");

    for (i = 0; i < key_count; i++) {
        libhsm_key_info_t *key_info;
        libhsm_key_t *key = NULL;
        char key_type[HSM_MAX_ALGONAME + 8];
        char const * key_id = NULL;

        key = keys[i];
        if (key == NULL) {
            /* Skip NULL key for now */
            continue;
        }

        key_count_valid++;

        key_info = hsm_get_key_info(NULL, key);

        if (key_info) {
            snprintf(key_type, sizeof(key_type), "%s/%lu",
                key_info->algorithm_name, key_info->keysize);
            key_id = key_info->id;
        } else {
            snprintf(key_type, sizeof(key_type), "UNKNOWN");
            key_id = "UNKNOWN";
        }

        printf(key_info_format, key->module->name, key_id, key_type);

        libhsm_key_info_free(key_info);
    }
    libhsm_key_list_free(keys, key_count);

    if (key_count != key_count_valid) {
        size_t invalid_keys;
        invalid_keys = key_count - key_count_valid;
        printf("\n");
        fprintf(stderr, "Warning: %u %s not usable by OpenDNSSEC was found.\n",
            (unsigned int) invalid_keys, invalid_keys > 1 ? "keys" : "key");
    }

    return 0;
}
#pragma GCC diagnostic pop

static int
cmd_generate (int argc, char *argv[])
{
    const char *repository = NULL;
    const char *algorithm = NULL;
    unsigned int keysize = 1024;

    libhsm_key_t *key = NULL;
    hsm_ctx_t *ctx = NULL;

    if (argc < 2 || argc > 3) {
        usage();
        return -1;
    }

    repository = argv[0];

    /* Check for repository before starting using it */
    if (hsm_token_attached(ctx, repository) == 0) {
       hsm_print_error(ctx);
       return 1;
    }

    algorithm = argv[1];
    if (argc == 3) {
        keysize = atoi(argv[2]);
    }

    if (!strcasecmp(algorithm, "rsa")) {
        printf("Generating %d bit RSA key in repository: %s\n",
            keysize, repository);

        key = hsm_generate_rsa_key(NULL, repository, keysize);
    } else if (!strcasecmp(algorithm, "dsa")) {
        printf("Generating %d bit DSA key in repository: %s\n",
            keysize, repository);

        key = hsm_generate_dsa_key(NULL, repository, keysize);
    } else if (!strcasecmp(algorithm, "gost")) {
        printf("Generating 512 bit GOST key in repository: %s\n",
            repository);

        key = hsm_generate_gost_key(NULL, repository);
    } else if (!strcasecmp(algorithm, "ecdsa")) {
        if (keysize == 256) {
            printf("Generating a P-256 ECDSA key in repository: %s\n",
                repository);

            key = hsm_generate_ecdsa_key(NULL, repository, "P-256");
        } else if (keysize == 384) {
            printf("Generating a P-384 ECDSA key in repository: %s\n",
                repository);

            key = hsm_generate_ecdsa_key(NULL, repository, "P-384");
        } else {
            printf("Invalid ECDSA key size: %d\n", keysize);
            printf("Expecting 256 or 384.\n");
            return -1;
        }
    } else {
        printf("Unknown algorithm: %s\n", algorithm);
        return -1;
    }

    if (key) {
        libhsm_key_info_t *key_info;

        key_info = hsm_get_key_info(NULL, key);
        printf("Key generation successful: %s\n",
            key_info ? key_info->id : "NULL");
        libhsm_key_info_free(key_info);
        if (verbose) hsm_print_key(key);
        free(key);
    } else {
        printf("Key generation failed.\n");
        return -1;
    }

    return 0;
}

static int
cmd_remove (int argc, char *argv[])
{
    char *id;
    int result;

    libhsm_key_t *key = NULL;

    if (argc != 1) {
        usage();
        return -1;
    }

    id = argv[0];

    key = hsm_find_key_by_id(NULL, id);

    if (!key) {
        printf("Key not found: %s\n", id);
        return -1;
    }

    result = hsm_remove_key(NULL, key);

    if (!result) {
        printf("Key remove successful.\n");
    } else {
        printf("Key remove failed.\n");
    }

    free(key);

    return result;
}

static int
cmd_purge (int argc, char *argv[])
{
    int result;
    int final_result = 0;
    char *fresult;

    size_t i;
    char *repository = NULL;
    char confirm[16];

    size_t key_count = 0;
    libhsm_key_t **keys;
    hsm_ctx_t *ctx = NULL;

    if (argc != 1) {
        usage();
        return -1;
    }

    repository = argv[0];
    argc--;
    argv++;

    /* Check for repository before starting using it */
    if (hsm_token_attached(ctx, repository) == 0) {
        hsm_print_error(ctx);
        return 1;
    }

    printf("Purging all keys from repository: %s\n", repository);
    keys = hsm_list_keys_repository(NULL, &key_count, repository);

    printf("%u %s found.\n\n", (unsigned int) key_count,
        (key_count > 1 || key_count == 0 ? "keys" : "key"));

    if (!keys) {
        return -1;
    }

    if (key_count == 0) {
        libhsm_key_list_free(keys, key_count);
        return -1;
    }

    printf("Are you sure you want to remove ALL keys from repository %s ? (YES/NO) ", repository);
    fresult = fgets(confirm, sizeof(confirm) - 1, stdin);
    if (fresult == NULL || strncasecmp(confirm, "yes", 3) != 0) {
        printf("\nPurge cancelled.\n");
        libhsm_key_list_free(keys, key_count);
        return -1;
    } else {
        printf("\nStarting purge...\n");
    }

    for (i = 0; i < key_count; i++) {
        libhsm_key_info_t *key_info;
        libhsm_key_t *key = keys[i];

        key_info = hsm_get_key_info(NULL, key);
        result = hsm_remove_key(NULL, key);

        if (!result) {
            printf("Key remove successful: %s\n",
                key_info ? key_info->id : "NULL");
        } else {
            printf("Key remove failed: %s\n",
                key_info ? key_info->id : "NULL");
            final_result++;
        }

        libhsm_key_info_free(key_info);
    }
    libhsm_key_list_free(keys, key_count);

    printf("Purge done.\n");

    return final_result;
}

static int
cmd_dnskey (int argc, char *argv[])
{
    char *id;
    char *name;
    int type;
    int algo;

    libhsm_key_t *key = NULL;
    ldns_rr *dnskey_rr;
    hsm_sign_params_t *sign_params;

    if (argc != 4) {
        usage();
        return -1;
    }

    id = strdup(argv[0]);
    name = strdup(argv[1]);
    type = atoi(argv[2]);
    algo = atoi(argv[3]);

    key = hsm_find_key_by_id(NULL, id);

    if (!key) {
        printf("Key not found: %s\n", id);
        free(name);
        free(id);
        return -1;
    }

    if (type != LDNS_KEY_ZONE_KEY && type != LDNS_KEY_ZONE_KEY + LDNS_KEY_SEP_KEY) {
        printf("Invalid key type: %i\n", type);
        printf("Please use: %i or %i\n", LDNS_KEY_ZONE_KEY, LDNS_KEY_ZONE_KEY + LDNS_KEY_SEP_KEY);
        free(name);
        free(id);
        free(key);
        return -1;
    }

    libhsm_key_info_t *key_info = hsm_get_key_info(NULL, key);
    switch (algo) {
        case LDNS_SIGN_RSAMD5:
        case LDNS_SIGN_RSASHA1:
        case LDNS_SIGN_RSASHA1_NSEC3:
        case LDNS_SIGN_RSASHA256:
        case LDNS_SIGN_RSASHA512:
            if (strcmp(key_info->algorithm_name, "RSA") != 0) {
                printf("Not an RSA key, the key is of algorithm %s.\n", key_info->algorithm_name);
                libhsm_key_info_free(key_info);
                free(name);
                free(id);
                return -1;
            }
            break;
        case LDNS_SIGN_DSA:
        case LDNS_SIGN_DSA_NSEC3:
            if (strcmp(key_info->algorithm_name, "DSA") != 0) {
                printf("Not a DSA key, the key is of algorithm %s.\n", key_info->algorithm_name);
                libhsm_key_info_free(key_info);
                free(name);
                free(id);
                return -1;
            }
            break;
        case LDNS_SIGN_ECC_GOST:
            if (strcmp(key_info->algorithm_name, "GOST") != 0) {
                printf("Not a GOST key, the key is of algorithm %s.\n", key_info->algorithm_name);
                libhsm_key_info_free(key_info);
                free(name);
                free(id);
                return -1;
            }
            break;
/* TODO: We can remove the directive if we require LDNS >= 1.6.13 */
#if !defined LDNS_BUILD_CONFIG_USE_ECDSA || LDNS_BUILD_CONFIG_USE_ECDSA
        case LDNS_SIGN_ECDSAP256SHA256:
            if (strcmp(key_info->algorithm_name, "ECDSA") != 0) {
                printf("Not an ECDSA key, the key is of algorithm %s.\n", key_info->algorithm_name);
                libhsm_key_info_free(key_info);
                free(name);
                free(id);
                return -1;
            }
            if (key_info->keysize != 256) {
                printf("The key is a ECDSA/%lu, expecting ECDSA/256 for this algorithm.\n", key_info->keysize);
                libhsm_key_info_free(key_info);
                free(name);
                free(id);
                return -1;
            }
            break;
        case LDNS_SIGN_ECDSAP384SHA384:
            if (strcmp(key_info->algorithm_name, "ECDSA") != 0) {
                printf("Not an ECDSA key, the key is of algorithm %s.\n", key_info->algorithm_name);
                libhsm_key_info_free(key_info);
                free(name);
                free(id);
                return -1;
            }
            if (key_info->keysize != 384) {
                printf("The key is a ECDSA/%lu, expecting ECDSA/384 for this algorithm.\n", key_info->keysize);
                libhsm_key_info_free(key_info);
                free(name);
                free(id);
                return -1;
            }
            break;
#endif
        default:
            printf("Invalid algorithm: %i\n", algo);
            libhsm_key_info_free(key_info);
            free(name);
            free(id);
            return -1;
    }
    libhsm_key_info_free(key_info);

    sign_params = hsm_sign_params_new();
    sign_params->algorithm = algo;
    sign_params->flags = type;
    sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, name);
    dnskey_rr = hsm_get_dnskey(NULL, key, sign_params);
    sign_params->keytag = ldns_calc_keytag(dnskey_rr);

    ldns_rr_print(stdout, dnskey_rr);

    hsm_sign_params_free(sign_params);
    ldns_rr_free(dnskey_rr);
    free(key);
    free(name);
    free(id);

    return 0;
}

static int
cmd_test (int argc, char *argv[])
{
    char *repository = NULL;

    if (argc) {
        repository = strdup(argv[0]);
        argc--;
        argv++;

        printf("Testing repository: %s\n\n", repository);
        int rv = hsm_test(repository);
        if (repository) free(repository);
        return rv;
    } else {
        usage();
    }

    return 0;
}

static int
cmd_info ()
{
    hsm_print_tokeninfo(NULL);

    return 0;
}

static int
cmd_debug ()
{
    hsm_print_ctx(NULL);

    return 0;
}

int
main (int argc, char *argv[])
{
    int result;

    char *config = NULL;

    int ch;
    progname = argv[0];

    while ((ch = getopt(argc, argv, "c:vVh")) != -1) {
        switch (ch) {
        case 'c':
            config = strdup(optarg);
            break;
        case 'v':
            verbose++;
            break;
        case 'V':
            version();
            exit(0);
            break;
        case 'h':
            usage();
            exit(0);
            break;
        default:
            usage();
            exit(1);
        }
    }
    argc -= optind;
    argv += optind;

    if (!argc) {
        usage();
        exit(1);
    }


    if (!strcasecmp(argv[0], "logout")) {
        if (config) free(config);
        exit(cmd_logout());
    }

    result = hsm_open(config, hsm_prompt_pin);
    if (result) {
        hsm_print_error(NULL);
        exit(-1);
    }

    openlog("hsmutil", LOG_PID, LOG_USER);

    if (!strcasecmp(argv[0], "login")) {
        argc --;
        argv ++;
        result = cmd_login();
    } else if (!strcasecmp(argv[0], "list")) {
        argc --;
        argv ++;
        result = cmd_list(argc, argv);
    } else if (!strcasecmp(argv[0], "generate")) {
        argc --;
        argv ++;
        result = cmd_generate(argc, argv);
    } else if (!strcasecmp(argv[0], "remove")) {
        argc --;
        argv ++;
        result = cmd_remove(argc, argv);
    } else if (!strcasecmp(argv[0], "purge")) {
        argc --;
        argv ++;
        result = cmd_purge(argc, argv);
    } else if (!strcasecmp(argv[0], "dnskey")) {
        argc --;
        argv ++;
        result = cmd_dnskey(argc, argv);
    } else if (!strcasecmp(argv[0], "test")) {
        argc --;
        argv ++;
        result = cmd_test(argc, argv);
    } else if (!strcasecmp(argv[0], "info")) {
        argc --;
        argv ++;
        result = cmd_info();
    } else if (!strcasecmp(argv[0], "debug")) {
        argc --;
        argv ++;
        result = cmd_debug();
    } else {
        usage();
        result = -1;
    }

    hsm_close();
    if (config) free(config);

    closelog();

    exit(result);
}
