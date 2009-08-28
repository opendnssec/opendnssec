/*
 * $Id$
 *
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
#include <unistd.h>

#include <libhsm.h>
#include <libhsmdns.h>


extern char *optarg;
char *progname = "hsmutil";


void
usage_list ()
{
    fprintf(stderr,
        "usage: %s [-f config] list [repository]\n",
        progname);
}

void
usage_generate ()
{
    fprintf(stderr,
        "usage: %s [-f config] generate [repository] rsa [keysize]\n",
        progname);
}

void
usage_remove ()
{
    fprintf(stderr,
        "usage: %s [-f config] remove [id]\n",
        progname);
}

void
usage_dnskey ()
{
    fprintf(stderr,
        "usage: %s [-f config] dnskey [id] [name]\n",
        progname);
}

void
usage_test ()
{
    fprintf(stderr,
        "usage: %s [-f config] test [repository]\n",
        progname);
}

void
usage_debug ()
{
    fprintf(stderr,
        "usage: %s [-f config] debug\n",
        progname);
}

void
usage ()
{
    usage_list();
    usage_generate();
    usage_remove();
    usage_dnskey();
    usage_test();
#if 0
    usage_debug();
#endif
}

int
cmd_list (int argc, char *argv[])
{
    size_t i;
    char *repository = NULL;

    size_t key_count = 0;
    hsm_key_t **keys;
    
    const char *key_info_format = "%-20s  %-32s  %-10s\n";
    

    if (argc) {
        repository = strdup(argv[0]);
        argc--;
        argv++;

        printf("Listing keys in repository: %s\n", repository);
        keys = hsm_list_keys_repository(NULL, &key_count, repository);
    } else {
        printf("Listing keys in all repositories.\n");
        keys = hsm_list_keys(NULL, &key_count);
    }

    printf("%u %s found.\n\n", (unsigned int) key_count,
        (key_count > 1 ? "keys" : "key"));

    if (!keys) {
        return -1;
    }

    /* print fancy header */
    printf(key_info_format, "Repository", "ID", "Type");
    printf(key_info_format, "----------", "--", "----");

    for (i = 0; i < key_count; i++) {
        hsm_key_info_t *key_info;
        hsm_key_t *key = keys[i];
        char key_type[HSM_MAX_ALGONAME + 8];

        key_info = hsm_get_key_info(NULL, key);
        snprintf(key_type, sizeof(key_type),
            "%s/%lu",
            key_info->algorithm_name, key_info->keysize);

        printf(key_info_format, key->module->name, key_info->id, key_type);

        hsm_key_info_free(key_info);
    }
    hsm_key_list_free(keys, key_count);

    return 0;
}

int
cmd_generate (int argc, char *argv[])
{
    char *repository = NULL;
    char *algorithm = NULL;
    unsigned int keysize = 1024;

    hsm_key_t *key = NULL;

    if (argc != 3) {
        usage_generate();
        return -1;
    }

    repository = strdup(argv[0]);
    algorithm = strdup(argv[1]);
    keysize = atoi(argv[2]);

    if (!strcasecmp(algorithm, "rsa")) {
        printf("Generating %d bit RSA key in repository: %s\n",
            keysize, repository);

        key = hsm_generate_rsa_key(NULL, repository, keysize);

        if (key) {
            printf("Key generation successful.\n");
            hsm_print_key(key);
            hsm_key_free(key);
        } else {
            printf("Key generation failed.\n");
            return -1;
        }

    } else {
        printf("Unknown algorithm: %s\n", algorithm);
        return -1;
    }

    return 0;
}

int
cmd_remove (int argc, char *argv[])
{
    char *id;
    int result;

    hsm_key_t *key = NULL;

    if (argc != 1) {
        usage_remove();
        return -1;
    }

    id = strdup(argv[0]);

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
        return -1;
    }

    hsm_key_free(key);

    return 0;
}

int
cmd_dnskey (int argc, char *argv[])
{
    char *id;
    char *name;

    hsm_key_t *key = NULL;
    ldns_rr *dnskey_rr;
    hsm_sign_params_t *sign_params;

    if (argc != 2) {
        usage_dnskey();
        return -1;
    }

    id = strdup(argv[0]);
    name = strdup(argv[1]);

    key = hsm_find_key_by_id(NULL, id);

    if (!key) {
        printf("Key not found: %s\n", id);
        return -1;
    }

    sign_params = hsm_sign_params_new();
    sign_params->algorithm = LDNS_RSASHA1;
    sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, name);
    dnskey_rr = hsm_get_dnskey(NULL, key, sign_params);
    sign_params->keytag = ldns_calc_keytag(dnskey_rr);

    ldns_rr_print(stdout, dnskey_rr);

    hsm_sign_params_free(sign_params);
    ldns_rr_free(dnskey_rr);
    hsm_key_free(key);

    return 0;
}

int
cmd_test (int argc, char *argv[])
{
    char *repository = NULL;

    if (argc) {
        repository = strdup(argv[0]);
        argc--;
        argv++;

        printf("Testing repository: %s\n\n", repository);
        hsm_test(repository);
    } else {
        usage_test();
    }
}

int
cmd_debug (int argc, char *argv[])
{
    hsm_print_ctx(NULL);
}

int
main (int argc, char *argv[])
{
    int result;

    char *config = NULL;

    int ch;
    /* progname = argv[0]; */

    while ((ch = getopt(argc, argv, "f:h")) != -1) {
        switch (ch) {
        case 'f':
            config = strdup(optarg);
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

    result = hsm_open(config, hsm_prompt_pin, NULL);
    if (result) {
        hsm_print_error(NULL);
        exit(-1);
    }

    if (!strcasecmp(argv[0], "list")) {
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
    } else if (!strcasecmp(argv[0], "dnskey")) {
        argc --;
        argv ++;
        result = cmd_dnskey(argc, argv);
    } else if (!strcasecmp(argv[0], "test")) {
        argc --;
        argv ++;
        result = cmd_test(argc, argv);
    } else if (!strcasecmp(argv[0], "debug")) {
        argc --;
        argv ++;
        result = cmd_debug(argc, argv);
    } else {
        usage();
        result = -1;
    }

    (void) hsm_close();
    if (config) free(config);

    exit(result);
}
