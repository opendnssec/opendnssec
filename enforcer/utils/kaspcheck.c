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
#include <string.h>
#include <syslog.h>

#include "config.h"

#include "kaspcheck.h"
#include "kc_helper.h"

#include "ksm/database.h"

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>

const char *progname = NULL;

char *config = (char *) OPENDNSSEC_CONFIG_FILE;
char *kasp = NULL;
int verbose = 0;
char **repo_list = NULL;
int repo_count = 0;

#define StrFree(ptr) {if(ptr != NULL) {free(ptr); (ptr) = NULL;}}

/*
 * Display usage
 */
void usage ()
{
    fprintf(stderr,
			 "usage: %s [options]\n\n"
			 "Options:\n"
			 "  -c, --conf [PATH_TO_CONF_FILE]  Path to OpenDNSSEC configuration file\n"
			 "             (defaults to %s)\n"
			 "  -k, --kasp [PATH_TO_KASP_FILE]  Path to KASP policy file\n"
			 "             (defaults to the path from the conf.xml file)\n"
			 "  -V, --version                   Display the version information\n"
			 "  -v, --verbose                   Print extra DEBUG messages\n"
             "  -h, --help                      Show this message\n", progname, OPENDNSSEC_CONFIG_FILE);
}

/* 
 * Fairly basic main.
 */
int main (int argc, char *argv[])
{
	int status = 0; /* Will be non-zero on error (NOT warning) */
    int ch;
	int option_index = 0;
	int i = 0;
	int free_config = 0;
	static struct option long_options[] =
    {
        {"config",  required_argument, 0, 'c'},
        {"help",    no_argument,       0, 'h'},
        {"kasp",  required_argument, 0, 'k'},
        {"version", no_argument,       0, 'V'},
        {"verbose", no_argument,       0, 'v'},
        {0,0,0,0}
    };

	/* The program name is the last component of the program file name */
    if ((progname = strrchr(argv[0], '/'))) {	/* EQUALS */
        ++progname;			/* Point to character after last "/" */
	}
	else {
		progname = argv[0];
	}

    while ((ch = getopt_long(argc, argv, "c:hk:Vv", long_options, &option_index)) != -1) {
        switch (ch) {
            case 'c':
				config = StrStrdup(optarg);
				free_config = 1;
                break;
			case 'h':
				usage();
				exit(0);
				break;
            case 'k':
				kasp = StrStrdup(optarg);
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

	/* 0) Some basic setup */
	log_init(DEFAULT_LOG_FACILITY, progname);

	/* 1) Check on conf.xml - set kasp.xml (if -k flag not given) */
	status = check_conf(&kasp);

	/* 2) Checks on kasp.xml */
	status += check_kasp();

	if (verbose) {
		dual_log("DEBUG: finished %d\n", status);
	}

	xmlCleanupParser();

	for (i = 0; i < repo_count; i++) {
		StrFree(repo_list[i]);
	}
	StrFree(repo_list);
	if (free_config) {
		StrFree(config);
	}
	StrFree(kasp);

	return status;
}

/*
 * Check the conf.xml file
 * Set kasp.xml from file (unless -k flag was given)
 * Return status (0 == success; 1 == error)
 */

int check_conf(char** kasp) {
	int status = 0;
	int i = 0;
	int j = 0;
	int temp_status = 0;

	xmlDocPtr doc;
    xmlXPathContextPtr xpath_ctx;
    xmlXPathObjectPtr xpath_obj;
    xmlNode *curNode;
    xmlChar *xexpr;
	char* temp_char = NULL;

	KC_REPO* repo = NULL;
	int* repo_mods = NULL; /* To see if we have looked at this module before */

	const char* rngfilename = OPENDNSSEC_SCHEMA_DIR "/conf.rng";
	const char* zonerngfilename = OPENDNSSEC_SCHEMA_DIR "/zonelist.rng";

	/* Check that the file is well-formed */
	status = check_rng(config, rngfilename);

	if (status == 0) {
		dual_log("INFO: The XML in %s is valid\n", config);
	} else {
		return status; /* Don't try to read the file if it is invalid */
	}

	 /* Load XML document */
    doc = xmlParseFile(config);
    if (doc == NULL) {
        return 1;
    }

    /* Create xpath evaluation context */
    xpath_ctx = xmlXPathNewContext(doc);
    if(xpath_ctx == NULL) {
        xmlFreeDoc(doc);
        return 1;
    }

    /* REPOSITORY section */
    xexpr = (xmlChar *)"//Configuration/RepositoryList/Repository";
    xpath_obj = xmlXPathEvalExpression(xexpr, xpath_ctx);
    if(xpath_obj == NULL) {
        xmlXPathFreeContext(xpath_ctx);
        xmlFreeDoc(doc);
        return 1;
    }

    if (xpath_obj->nodesetval) {
		repo_count = xpath_obj->nodesetval->nodeNr;
		
		repo = (KC_REPO*)malloc(sizeof(KC_REPO) * repo_count);
		repo_mods = (int*)malloc(sizeof(int) * repo_count);
		repo_list = (char**)malloc(sizeof(char*) * repo_count);

		if (repo == NULL || repo_mods == NULL || repo_list == NULL) {
			dual_log("ERROR: malloc for repo information failed\n");
			exit(1);
		}

        for (i = 0; i < repo_count; i++) {
			repo_mods[i] = 0;
                 
            curNode = xpath_obj->nodesetval->nodeTab[i]->xmlChildrenNode;
			/* Default for capacity */

            repo[i].name = (char *) xmlGetProp(xpath_obj->nodesetval->nodeTab[i],
                                             (const xmlChar *)"name");
			repo_list[i] = StrStrdup(repo[i].name);

            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar *)"TokenLabel"))
                    repo[i].TokenLabel = (char *) xmlNodeGetContent(curNode);
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Module"))
                    repo[i].module = (char *) xmlNodeGetContent(curNode);
                curNode = curNode->next;
            }
        }
    }
    xmlXPathFreeObject(xpath_obj);

	/* Now we have all the information we need do the checks */
	for (i = 0; i < repo_count; i++) {
		
		if (repo_mods[i] == 0) {

			/* 1) Check that the module exists */
			status += check_file(repo[i].module, "Module");

			repo_mods[i] = 1; /* Done this module */

			/* 2) Check repos on the same modules have different TokenLabels */
			for (j = i+1; j < repo_count; j++) {
				if ( repo_mods[j] == 0 && 
						(strcmp(repo[i].module, repo[j].module) == 0) ) {
					repo_mods[j] = 1; /* done */

					if (strcmp(repo[i].TokenLabel, repo[j].TokenLabel) == 0) {
						dual_log("ERROR: Multiple Repositories (%s and %s) in %s have the same Module (%s) and TokenLabel (%s)\n", repo[i].name, repo[j].name, config, repo[i].module, repo[i].TokenLabel);
						status += 1;
					}
				}
			}
		}

		/* 3) Check that the name is unique */
		for (j = i+1; j < repo_count; j++) {
			if (strcmp(repo[i].name, repo[j].name) == 0) {
				dual_log("ERROR: Two repositories exist with the same name (%s)\n", repo[i].name);
				status += 1;
			}
		}
	}

	/* COMMON section */
	/* PolicyFile (aka KASP); we will validate it later */
	if (*kasp == NULL) {
		xexpr = (xmlChar *)"//Configuration/Common/PolicyFile";
		xpath_obj = xmlXPathEvalExpression(xexpr, xpath_ctx);
		if(xpath_obj == NULL) {
			xmlXPathFreeContext(xpath_ctx);
			xmlFreeDoc(doc);

			for (i = 0; i < repo_count; i++) {
				free(repo[i].name);
				free(repo[i].module);
				free(repo[i].TokenLabel);
			}
			free(repo);
			free(repo_mods);

			return -1;
		}
		temp_char = (char*) xmlXPathCastToString(xpath_obj);
		StrAppend(kasp, temp_char);
		StrFree(temp_char);
		xmlXPathFreeObject(xpath_obj);
	}
    

	/* Check that the  Zonelist file is well-formed */
	xexpr = (xmlChar *)"//Configuration/Common/ZoneListFile";
	xpath_obj = xmlXPathEvalExpression(xexpr, xpath_ctx);
	if(xpath_obj == NULL) {
		xmlXPathFreeContext(xpath_ctx);
		xmlFreeDoc(doc);

		for (i = 0; i < repo_count; i++) {
			free(repo[i].name);
			free(repo[i].module);
			free(repo[i].TokenLabel);
		}
		free(repo);
		free(repo_mods);

		return -1;
	}
	temp_char = (char*) xmlXPathCastToString(xpath_obj);

	if (check_rng(temp_char, zonerngfilename) == 0) {
		dual_log("INFO: The XML in %s is valid\n", temp_char);
	} else {
		status += 1;
	}

    xmlXPathFreeObject(xpath_obj);
	StrFree(temp_char);

	/* ENFORCER section */

	/* Check defined user/group */
	status += check_user_group(xpath_ctx, 
			(xmlChar *)"//Configuration/Enforcer/Privileges/User", 
			(xmlChar *)"//Configuration/Enforcer/Privileges/Group");

	/* Check datastore exists (if sqlite) */
	/* TODO check datastore matches libksm without building against libksm */
	temp_status = check_file_from_xpath(xpath_ctx, "SQLite datastore",
			(xmlChar *)"//Configuration/Enforcer/Datastore/SQLite");
	if (temp_status == -1) {
		/* Configured for Mysql DB */
		/*if (DbFlavour() != MYSQL_DB) {
			dual_log("ERROR: libksm compiled for sqlite3 but conf.xml configured for MySQL\n");
		}*/
	} else {
		status += temp_status;
		/* Configured for sqlite DB */
		/*if (DbFlavour() != SQLITE_DB) {
			dual_log("ERROR: libksm compiled for MySQL but conf.xml configured for sqlite3\n");
		}*/
	}

	/* Warn if Interval is M or Y */
	status += check_time_def_from_xpath(xpath_ctx, (xmlChar *)"//Configuration/Enforcer/Interval", "Configuration", "Enforcer/Interval", config);

	/* Warn if RolloverNotification is M or Y */
	status += check_time_def_from_xpath(xpath_ctx, (xmlChar *)"//Configuration/Enforcer/RolloverNotification", "Configuration", "Enforcer/RolloverNotification", config);

	/* Check DelegationSignerSubmitCommand exists (if set) */
	temp_status = check_file_from_xpath(xpath_ctx, "DelegationSignerSubmitCommand",
			(xmlChar *)"//Configuration/Enforcer/DelegationSignerSubmitCommand");
	if (temp_status > 0) {
		status += temp_status;
	}

	/* SIGNER section */
	/* Check defined user/group */
	status += check_user_group(xpath_ctx, 
			(xmlChar *)"//Configuration/Signer/Privileges/User", 
			(xmlChar *)"//Configuration/Signer/Privileges/Group");

	/* Check WorkingDirectory exists (or default) */
	temp_status = check_path_from_xpath(xpath_ctx, "WorkingDirectory",
			(xmlChar *)"//Configuration/Signer/WorkingDirectory");
	if (temp_status == -1) {
		/* Check the default location */
		check_path(OPENDNSSEC_STATE_DIR "/tmp", "default WorkingDirectory");
	} else {
		status += temp_status;
	}
		
    xmlXPathFreeContext(xpath_ctx);
    xmlFreeDoc(doc);

	for (i = 0; i < repo_count; i++) {
		free(repo[i].name);
		free(repo[i].module);
		free(repo[i].TokenLabel);
	}
	free(repo);
	free(repo_mods);

	return status;
}

/*
 * Check the kasp.xml file
 * Return status (0 == success; 1 == error)
 */

int check_kasp() {
	int status = 0;
	int i = 0;
	int j = 0;
	const char* rngfilename = OPENDNSSEC_SCHEMA_DIR "/kasp.rng";
	xmlDocPtr doc;
    xmlXPathContextPtr xpath_ctx;
    xmlXPathObjectPtr xpath_obj;
    xmlNode *curNode;
    xmlChar *xexpr;

	int policy_count = 0;
	char **policy_names = NULL;
	int default_found = 0;

	if (kasp == NULL) {
		dual_log("ERROR: No location for kasp.xml set\n");
		return 1;
	}

/* Check that the file is well-formed */
	status = check_rng(kasp, rngfilename);

	if (status ==0) {
		dual_log("INFO: The XML in %s is valid\n", kasp);
	} else {
		return 1;
	}

	/* Load XML document */
    doc = xmlParseFile(kasp);
    if (doc == NULL) {
        return 1;
    }

    /* Create xpath evaluation context */
    xpath_ctx = xmlXPathNewContext(doc);
    if(xpath_ctx == NULL) {
        xmlFreeDoc(doc);
        return 1;
    }

	/* First pass through the whole document to test for a policy called "default" and no duplicate names */

    xexpr = (xmlChar *)"//KASP/Policy";
    xpath_obj = xmlXPathEvalExpression(xexpr, xpath_ctx);
    if(xpath_obj == NULL) {
        xmlXPathFreeContext(xpath_ctx);
        xmlFreeDoc(doc);
        return 1;
    }

	if (xpath_obj->nodesetval) {
		policy_count = xpath_obj->nodesetval->nodeNr;

		policy_names = (char**)malloc(sizeof(char*) * policy_count);
		if (policy_names == NULL) {
			dual_log("ERROR: Malloc for policy names failed\n");
			exit(1);
		}

		for (i = 0; i < policy_count; i++) {

			policy_names[i] = (char *) xmlGetProp(xpath_obj->nodesetval->nodeTab[i],
					(const xmlChar *)"name");
		}
	}

	/* Now we have all the information we need do the checks */
	for (i = 0; i < policy_count; i++) {
		if (strcmp(policy_names[i], "default") == 0) {
			default_found = 1;
		}
		for (j = i+1; j < policy_count; j++) {
			if ( (strcmp(policy_names[i], policy_names[j]) == 0) ) {
				dual_log("ERROR: Two policies exist with the same name (%s)\n", policy_names[i]);
				status += 1;
			}
		}
	}
	if (default_found == 0) {
		dual_log("WARNING: No policy named 'default' in %s. This means you will need to refer explicitly to the policy for each zone\n", kasp);
	}

	/* Go again; this time check each policy */
	for (i = 0; i < policy_count; i++) {
		 curNode = xpath_obj->nodesetval->nodeTab[i]->xmlChildrenNode;

		 status += check_policy(curNode, policy_names[i], repo_list, repo_count, kasp);
	}

	for (i = 0; i < policy_count; i++) {
		free(policy_names[i]);
	}
	free(policy_names);

    xmlXPathFreeObject(xpath_obj);
	xmlXPathFreeContext(xpath_ctx);
	xmlFreeDoc(doc);

	return status;
}
