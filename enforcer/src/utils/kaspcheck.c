/*
 * Copyright (c) 2012 Nominet UK. All rights reserved.
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

#define _GNU_SOURCE
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "config.h"

#include "kc_helper.h"

#include <libxml/parser.h>

const char *progname = NULL;

/*
 * Display usage
 */
static void usage()
{
	fprintf(stderr,
			"usage: %s [options]\n\n"
			"Options:\n"
			"  -c, --conf [PATH_TO_CONF_FILE]  Path to OpenDNSSEC configuration file\n"
			"             (defaults to %s)\n"
			"  -k, --kasp [PATH_TO_KASP_FILE]  Path to KASP policy file\n"
			"             (defaults to the path from the conf.xml file)\n",
			progname, OPENDNSSEC_CONFIG_FILE);
	fprintf(stderr,
			 "  -z, --zonelist [PATH_TO_ZONELIST_FILE]  Path to zonelist file\n"
			 "             (defaults to the path from the conf.xml file)\n"
			 "  -V, --version                   Display the version information\n"
			 "  -v, --verbose                   Print extra DEBUG messages\n"
			 "  -h, --help                      Show this message\n");
}

/* 
 * Fairly basic main.
 */
int main (int argc, char *argv[])
{
	extern int kc_helper_printto_stdout;
	char *conffile = NULL, *kaspfile = NULL, *zonelistfile = NULL;
	int status = 0; /* Will be non-zero on error (NOT warning) */
	char **repo_list = NULL;
	int repo_count = 0;
	int ch, i, verbose = 0, option_index = 0;
	static struct option long_options[] =
	{
		{"config",  required_argument, 0, 'c'},
		{"help",    no_argument,       0, 'h'},
		{"kasp",  required_argument, 0, 'k'},
		{"zonelist",  required_argument, 0, 'z'},
		{"version", no_argument,       0, 'V'},
		{"verbose", no_argument,       0, 'v'},
		{0,0,0,0}
	};
	char **policy_names = NULL;
	int policy_count = 0;

	/* The program name is the last component of the program file name */
	if ((progname = strrchr(argv[0], '/'))) {	/* EQUALS */
		++progname;			/* Point to character after last "/" */
	} else {
		progname = argv[0];
	}

	while ((ch = getopt_long(argc, argv, "c:hk:Vvz:", long_options, &option_index)) != -1)
	{
		switch (ch)
		{
			case 'c':
				conffile = StrStrdup(optarg);
				break;
			case 'h':
				usage();
				exit(0);
				break;
			case 'k':
				kaspfile = StrStrdup(optarg);
				break;
			case 'z':
				zonelistfile = StrStrdup(optarg);
				break;
			case 'V':
				printf("%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
				exit(0);
				break;
			case 'v':
				verbose = 1;
				break;
		}
	}

	kc_helper_printto_stdout = 1;

	if (!conffile)
		conffile = StrStrdup((char *)OPENDNSSEC_CONFIG_FILE);
		
	/* 0) Some basic setup */
	log_init(DEFAULT_LOG_FACILITY, progname);
	/* 1) Check on conf.xml - set kasp.xml (if -k flag not given) */
	status = check_conf(conffile, &kaspfile, &zonelistfile, &repo_list, 
		&repo_count, verbose);
	/* 2) Checks on kasp.xml */
	status += check_kasp(kaspfile, repo_list, repo_count, verbose,
	    &policy_names, &policy_count);
	/* 3) Checks on zonelist.xml */
	status += check_zonelist(zonelistfile, verbose, policy_names, policy_count);

	for (i = 0; i < policy_count; i++) {
		free(policy_names[i]);
	}
	free(policy_names);

	xmlCleanupParser();
	for (i = 0; i < repo_count; i++)
		free(repo_list[i]);
	free(repo_list);
	free(conffile);
	free(kaspfile);
	free(zonelistfile);

	if (verbose)
		dual_log("DEBUG: finished %d", status);
	return status;
}
