/*
 * $Id: zone_reader.c 2644 2009-12-18 13:45:33Z matthijs $
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
 * This tool reads sorted zone files.
 * It resorts the zone according in the needed order (either canonical
 * or in NSEC3 order)
 * It also marks empty non-terminals, glue and out-of-zone data, and
 * converts those to comments. For NSEC3, it adds an NSEC3PARAM RR if
 * not present. NSEC3PARAMS with other parameters are removed.
 * RRSIG records will be sorted right after the RRset they cover
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#include <unistd.h>
#include <errno.h>

#include <ldns/ldns.h>
#include "util.h"
#include "v2/zone.h"
#include "v2/hsm.h"
#include "v2/se_malloc.h"

void
usage(FILE *out)
{
	fprintf(out, "Usage: nsecifier [OPTIONS]\n");
	fprintf(out, "Nsecifies the zone.\n");
	fprintf(out, "Options:\n");
	fprintf(out, "-c <file\tUse <file> instead of conf.xml\n");
	fprintf(out, "-o <origin>\tZone origin\n");
	fprintf(out, "-f <file>\tRead zone from <file> instead of stdin\n");
	fprintf(out, "-k <class>\tZone class\n");
	fprintf(out, "-s <file>\tSigner configuration file\n");
	fprintf(out, "-w <file>\tWrite NSECCED zone to <file> instead of stdout\n");
	fprintf(out, "-x <file>\tWrite Opt-Out zone to <file> instead of stdout\n");
	fprintf(out, "-h\t\tShow this help\n");
}

static void
nzr_print_nsec_domain(FILE* fd, domain_type* domain)
{
	rrset_type* walk_rrset = NULL;
	int ns_printed = 0;
	int ds_printed = 0;

	if (domain) {
		walk_rrset = domain->auth_rrset;
		while (walk_rrset) {
			if (domain->domain_status == DOMAIN_STATUS_OCCLUDED) {
				walk_rrset = walk_rrset->next;
				continue;
			}

			if (!walk_rrset->rrs || !walk_rrset->rrs->rr) {
				walk_rrset = walk_rrset->next;
				continue;
			}

			if (!ns_printed && walk_rrset->rr_type > LDNS_RR_TYPE_NS) {
				rrset_print(fd, domain->ns_rrset, NULL, 1, 0, 0);
				ns_printed = 1;
			}

			if (!ds_printed && walk_rrset->rr_type > LDNS_RR_TYPE_DS) {
				rrset_print(fd, domain->ds_rrset, NULL, 1, 0, 0);
				ds_printed = 1;
			}

			ldns_dnssec_rrs_print(fd, walk_rrset->rrs);
			if (walk_rrset->rrsigs) {
				ldns_dnssec_rrs_print(fd, walk_rrset->rrsigs);
			}

			walk_rrset = walk_rrset->next;
		}

		if (!ns_printed) {
			rrset_print(fd, domain->ns_rrset, NULL, 1, 0, 0);
		}

		if (!ds_printed) {
			rrset_print(fd, domain->ds_rrset, NULL, 1, 0, 0);
		}

	}
}

static void
nzr_print_nsec(FILE* fd, zone_type* zone)
{
	ldns_rbnode_t* node = LDNS_RBTREE_NULL;
	domain_type* domain = NULL;

	node = ldns_rbtree_first(zone->zonedata->domains);
	if (!node || node == LDNS_RBTREE_NULL)
		fprintf(fd, "; empty zone\n");

	while (node && node != LDNS_RBTREE_NULL) {
		domain = (domain_type*) node->data;
		nzr_print_nsec_domain(fd, domain);
		rrset_print(fd, domain->nsec_rrset, NULL, 1, 0, 0);
		node = ldns_rbtree_next(node);
	}
}

static void
nzr_print_nsec3(FILE* fd, zone_type* zone)
{
	ldns_rbnode_t* node = LDNS_RBTREE_NULL;
	domain_type* domain = NULL;

	node = ldns_rbtree_first(zone->zonedata->nsec3_domains);
	if (!node || node == LDNS_RBTREE_NULL)
		fprintf(fd, "; empty zone\n");

	while (node && node != LDNS_RBTREE_NULL) {
		domain = (domain_type*) node->data;
		if (domain->nsec3) {
			nzr_print_nsec_domain(fd, domain->nsec3);
			rrset_print(fd, domain->nsec_rrset, NULL, 1, 0, 0);
		}
		node = ldns_rbtree_next(node);
	}
}

static void
nzr_print_optout_domain(FILE* fd, domain_type* domain, int nsec3)
{
	if (domain && domain->domain_status == DOMAIN_STATUS_OCCLUDED) {
		/* glue */
		rrset_print(fd, domain->auth_rrset, NULL, 1, 1, 0);
	} else if (nsec3 && domain && !domain->nsec3) {
		/* unsigned delegation, optout */
		rrset_print(fd, domain->auth_rrset, NULL, 1, 1, 0);
		rrset_print(fd, domain->ns_rrset, NULL, 1, 0, 0);
	}
}

static void
nzr_print_optout(FILE* fd, zone_type* zone, int nsec3)
{
	ldns_rbnode_t* node = LDNS_RBTREE_NULL;
	domain_type* domain = NULL;

	node = ldns_rbtree_first(zone->zonedata->domains);
	if (!node || node == LDNS_RBTREE_NULL)
		fprintf(fd, "; empty zone\n");

	while (node && node != LDNS_RBTREE_NULL) {
		domain = (domain_type*) node->data;
		nzr_print_optout_domain(fd, domain, nsec3);
		node = ldns_rbtree_next(node);
	}
}

int
main(int argc, char **argv)
{
	zone_type* zone = NULL;
	int c;
	FILE *in_file;
	FILE *out_file;
	FILE *optout_file;

	char *param_zname = NULL;
	char *param_conf_filename = NULL;
	char *param_sc_filename = NULL;
	char *param_in_filename = NULL;
	char *param_out_filename = NULL;
	char *param_optout_filename = NULL;
	int result = 0;

	ldns_rr_class param_klass = LDNS_RR_CLASS_IN;

	in_file = stdin;
	out_file = stdout;
	optout_file = stdout;

	while ((c = getopt(argc, argv, "c:f:hk:o:s:w:x:")) != -1) {
		switch (c) {
		case 'c':
			param_conf_filename = optarg;
			break;
		case 'f':
			in_file = fopen(optarg, "r");
			if (!in_file) {
				fprintf(stderr, "Error reading %s: %s\n",
				        optarg, strerror(errno));
				exit(1);
			}
			fclose(in_file);
			param_in_filename = optarg;
			break;
		case 'k':
			param_klass = (ldns_rr_class) atoi(optarg);
			break;
		case 'h':
			usage(stdout);
			exit(EXIT_SUCCESS);
			break;
		case 'o':
			param_zname = optarg;
			break;
		case 's':
			param_sc_filename = optarg;
			break;
		case 'w':
			param_out_filename = optarg;
                        break;
		case 'x':
			param_optout_filename = optarg;
			break;
		}
	}

	if (argc > optind) {
		fprintf(stderr, "Error: extraneous arguments\n");
		usage(stderr);
		exit(EXIT_FAILURE);
	}

	if (!param_zname) {
		fprintf(stderr, "Error, no zone name specified (-o)\n");
		exit(EXIT_FAILURE);
	}

	if (param_out_filename) {
		out_file = fopen(param_out_filename, "w");
		if (!out_file) {
			printf("Error opening %s for writing: %s\n",
				  param_out_filename,
				  strerror(errno));
			exit(2);
		}
	}

	if (param_optout_filename) {
		optout_file = fopen(param_optout_filename, "w");
		if (!optout_file) {
			printf("Error opening %s for writing: %s\n",
				  param_optout_filename,
				  strerror(errno));
			exit(2);
		}
	}

	result = hsm_open(param_conf_filename, hsm_prompt_pin, NULL);
	if (result != 0) {
		fprintf(stderr, "Error, unable to open HSM for zone %s", zone->name);
		exit(1);
	}

	zone = zone_create(param_zname, param_klass);
	zone->policy_name = NULL;
	zone->signconf_filename = se_strdup(param_sc_filename);
	zone->inbound_adapter = adapter_create(param_in_filename, 1);
	zone->signconf = signconf_read(zone->signconf_filename, 0);

	result = adapter_read_file(zone);
	if (result != 0) {
		fprintf(stderr, "Error, unable to read .sorted file for zone %s", zone->name);
		exit(1);
	}
	result = zone_publish_dnskeys(zone);
	if (result != 0) {
		fprintf(stderr, "Error, unable to publish DNSKEYs for zone %s", zone->name);
		exit(1);
	}
	result = zone_nsecify(zone);
	if (result != 0) {
		fprintf(stderr, "Error, unable to add NSEC(3)s for zone %s", zone->name);
		exit(1);
	}

	hsm_close();

 	if (zone->signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
		nzr_print_optout(optout_file, zone, 1);
		nzr_print_nsec3(out_file, zone);
	} else {
		nzr_print_optout(optout_file, zone, 0);
		nzr_print_nsec(out_file, zone);
	}

	zone_cleanup(zone);

	if (optout_file != stdout) {
		fclose(optout_file);
	}
	if (out_file != stdout) {
		fclose(out_file);
	}

	return 0;
}
