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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <libhsm.h>
#include <libhsmdns.h>


extern char *optarg;
char *progname = NULL;


void
usage ()
{
	fprintf(stderr,
		"usage: %s [-f config] [command] [arg]\n",
		progname);
}

int
cmd_list (int argc, char *argv[])
{
	size_t i;
	char *repository = NULL;
	
	size_t key_count = 0;
	hsm_key_t **keys;

	if (argc) {
		repository = strdup(argv[0]);
		argc--;
		argv++;

		printf("Listing keys in repository: %s\n", repository);
		keys = hsm_list_keys_repository(NULL, &key_count, repository);	
	} else {
		printf("Listing keys in all repositories\n");	
		keys = hsm_list_keys(NULL, &key_count);
	}

	printf("%d keys found.\n", key_count);
	
	if (!keys) {
		return -1;
	}
	
	for (i = 0; i < key_count; i++) {
		hsm_print_key(keys[i]);
	}
	hsm_key_list_free(keys, key_count);
	
	return 0;
}

int
cmd_generate (int argc, char *argv[])
{
	printf("generate...\n");
	return 0;
}

int
cmd_delete (int argc, char *argv[])
{
	printf("delete...\n");
	return 0;
}

int
cmd_dnskey (int argc, char *argv[])
{
	printf("dnskey...\n");
	return 0;
}

int
main (int argc, char *argv[])
{
	int result;

	char *config = NULL;
	
	int ch;
	progname = argv[0];

	while ((ch = getopt(argc, argv, "f:r:")) != -1) {
		switch (ch) {
		case 'f':
			config = strdup(optarg);
			break;
		default:
			usage();
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (!config || !argc) {
		usage();
		exit(1);
	}

	result = hsm_open(config, hsm_prompt_pin, NULL);	
	if (result) {
		fprintf(stderr, "hsm_open() returned %d\n", result);
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
	} else if (!strcasecmp(argv[0], "delete")) {
		argc --;
		argv ++;
		result = cmd_delete(argc, argv);
	} else if (!strcasecmp(argv[0], "dnskey")) {
		argc --;
		argv ++;
		result = cmd_dnskey(argc, argv);
	} else {
		usage();
		result = -1;
	}

	(void) hsm_close();
	if (config) free(config);
	
	exit(result);
}
