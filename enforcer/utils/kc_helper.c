/*
 * $Id$
 *
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
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <ctype.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>

#include "kc_helper.h"

extern int verbose;

#define StrFree(ptr) {if(ptr != NULL) {free(ptr); (ptr) = NULL;}}

void log_init(int facility, const char *program_name)
{
	openlog(program_name, 0, facility);
}

/* Switch log to new facility */
void log_switch(int facility, const char *program_name)
{
    closelog();
	openlog(program_name, 0, facility);
}

/* As far as possible we send messages both to syslog and STDOUT */
void dual_log(const char *format, ...) {

	/* If the variable arg list is bad then random errors can occur */ 
    va_list args;
    va_list args2;
	va_start(args, format);
	va_copy(args2, args);

	if (strncmp(format, "ERROR:", 6) == 0) {
		vsyslog(LOG_ERR, format, args);
	}
	else if (strncmp(format, "WARNING:", 8) == 0) {
		vsyslog(LOG_WARNING, format, args);
	}
	else if (strncmp(format, "DEBUG:", 6) == 0) {
		vsyslog(LOG_DEBUG, format, args);
	}
	else {
		vsyslog(LOG_INFO, format, args);
	}

	vprintf(format, args2);
	printf("\n");
	
	va_end(args);
	va_end(args2);
}

/* Check an XML file against its rng */
int check_rng(const char *filename, const char *rngfilename) {

	xmlDocPtr doc = NULL;
	xmlDocPtr rngdoc = NULL;
	xmlRelaxNGParserCtxtPtr rngpctx = NULL;
    xmlRelaxNGValidCtxtPtr rngctx = NULL;
    xmlRelaxNGPtr schema = NULL;

	if (verbose) {
		dual_log("DEBUG: About to check XML validity in %s", filename);
	}

   	/* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        dual_log("ERROR: unable to parse file \"%s\"", filename);
		/* Maybe the file doesn't exist? */
		check_file(filename, "Configuration file");

        return(1);
    }

    /* Load rng document */
    rngdoc = xmlParseFile(rngfilename);
    if (rngdoc == NULL) {
        dual_log("ERROR: unable to parse file \"%s\"", rngfilename);
		/* Maybe the file doesn't exist? */
		check_file(rngfilename, "RNG file");

        xmlFreeDoc(doc);
        
		return(1);
    }

    /* Create an XML RelaxNGs parser context for the relax-ng document. */
    rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);
    if (rngpctx == NULL) {
        dual_log("ERROR: unable to create XML RelaxNGs parser context");

        xmlFreeDoc(doc);
        xmlFreeDoc(rngdoc);
        
		return(1);
    }

	xmlRelaxNGSetParserErrors(rngpctx,
		(xmlRelaxNGValidityErrorFunc) fprintf,
		(xmlRelaxNGValidityWarningFunc) fprintf,
		stderr);

    /* parse a schema definition resource and build an internal XML Shema struture which can be used to validate instances. */
    schema = xmlRelaxNGParse(rngpctx);
    if (schema == NULL) {
        dual_log("ERROR: unable to parse a schema definition resource");

		xmlRelaxNGFreeParserCtxt(rngpctx);
		xmlFreeDoc(doc);
		xmlFreeDoc(rngdoc);

        return(1);
    }

    /* Create an XML RelaxNGs validation context based on the given schema */
    rngctx = xmlRelaxNGNewValidCtxt(schema);
    if (rngctx == NULL) {
        dual_log("ERROR: unable to create RelaxNGs validation context based on the schema");

		xmlRelaxNGFree(schema);
		xmlRelaxNGFreeParserCtxt(rngpctx);
		xmlFreeDoc(doc);
		xmlFreeDoc(rngdoc);
        
		return(1);
    }

	xmlRelaxNGSetValidErrors(rngctx,
		(xmlRelaxNGValidityErrorFunc) fprintf,
		(xmlRelaxNGValidityWarningFunc) fprintf,
		stderr);

    /* Validate a document tree in memory. */
    if (xmlRelaxNGValidateDoc(rngctx,doc) != 0) {
        dual_log("ERROR: %s fails to validate", filename);

		xmlRelaxNGFreeValidCtxt(rngctx);
		xmlRelaxNGFree(schema);
		xmlRelaxNGFreeParserCtxt(rngpctx);
		xmlFreeDoc(doc);
		xmlFreeDoc(rngdoc);

        return(1);
    }

    xmlRelaxNGFreeValidCtxt(rngctx);
	xmlRelaxNGFree(schema);
    xmlRelaxNGFreeParserCtxt(rngpctx);
    xmlFreeDoc(doc);
    xmlFreeDoc(rngdoc);

	return 0;
}

int check_file(const char *filename, const char *log_string) {
	struct stat stat_ret;

	if (stat(filename, &stat_ret) != 0) {

		if (errno != ENOENT) {
			dual_log("ERROR: cannot stat file %s: %s",
					filename, strerror(errno));
			return 1;
		}

		dual_log("ERROR: %s (%s) does not exist", log_string, filename);
		return 1;
	}

    if (S_ISREG(stat_ret.st_mode)) {
        /* The file exists */
		return 0;
    }

	dual_log("ERROR: %s (%s) does not exist", log_string, filename);
	return 1;
}

int check_file_from_xpath(xmlXPathContextPtr xpath_ctx, const char *log_string, const xmlChar *file_xexpr) {
	int status = 0;
	xmlXPathObjectPtr xpath_obj;
	char* temp_char = NULL;
	char* str = NULL;

	xpath_obj = xmlXPathEvalExpression(file_xexpr, xpath_ctx);
	if(xpath_obj == NULL) {
		dual_log("ERROR: unable to evaluate xpath expression: %s", file_xexpr);
		return 1;
	}
    if (xpath_obj->nodesetval != NULL && xpath_obj->nodesetval->nodeNr > 0) {
		temp_char = (char*) xmlXPathCastToString(xpath_obj);

		/* strip off any trailing characters (needed for DSSub with cks_id) */
		str = strrchr(temp_char, ' ');
		if (str) {
			*str = 0;
		}

		status = check_file(temp_char, log_string);

        StrFree(temp_char);
	} else {
		/* Not set; return -1 so that we can test the default path */
		xmlXPathFreeObject(xpath_obj);
		return -1;
	}

    xmlXPathFreeObject(xpath_obj);
	return status;
}

int check_path(const char *pathname, const char *log_string) {
	struct stat stat_ret;

	if (stat(pathname, &stat_ret) != 0) {
		if (errno != ENOENT) {
			dual_log("ERROR: cannot stat directory %s: %s",
					pathname, strerror(errno));
			return 1;
		}

		dual_log("ERROR: %s (%s) does not exist", log_string, pathname);
		return 1;
	}

	if (S_ISDIR(stat_ret.st_mode)) {
		/* The directory exists */
		return 0;
	}

	dual_log("ERROR: %s (%s) is not a directory", log_string, pathname);
	return 1;
}

int check_path_from_xpath(xmlXPathContextPtr xpath_ctx, const char *log_string, const xmlChar *path_xexpr) {
	int status = 0;
	xmlXPathObjectPtr xpath_obj;
	char* temp_char = NULL;

	xpath_obj = xmlXPathEvalExpression(path_xexpr, xpath_ctx);
	if(xpath_obj == NULL) {
		dual_log("ERROR: unable to evaluate xpath expression: %s", path_xexpr);
		return 1;
	}
    if (xpath_obj->nodesetval != NULL && xpath_obj->nodesetval->nodeNr > 0) {
		temp_char = (char*) xmlXPathCastToString(xpath_obj);

		status = check_path(temp_char, log_string);

        StrFree(temp_char);
	} else {
		/* Not set; return -1 so that we can test the default path */
		xmlXPathFreeObject(xpath_obj);
		return -1;
	}

    xmlXPathFreeObject(xpath_obj);
	return status;
}

int check_user_group(xmlXPathContextPtr xpath_ctx, const xmlChar *user_xexpr, const xmlChar *group_xexpr) {
	int status = 0;
	xmlXPathObjectPtr xpath_obj;
	char* temp_char = NULL;
	
	struct passwd *pwd;
    struct group  *grp;

	/* Group if specified */
	xpath_obj = xmlXPathEvalExpression(group_xexpr, xpath_ctx);
	if(xpath_obj == NULL) {
		dual_log("ERROR: unable to evaluate xpath expression: %s", group_xexpr);
		return(1);
	}
    if (xpath_obj->nodesetval != NULL && xpath_obj->nodesetval->nodeNr > 0) {
        temp_char = (char*) xmlXPathCastToString(xpath_obj);

		if ((grp = getgrnam(temp_char)) == NULL) {
            dual_log("ERROR: Group '%s' does not exist", temp_char);
            status += 1;
        }
		endgrent();

        StrFree(temp_char);
    }
    xmlXPathFreeObject(xpath_obj);

	/* User if specified */
	xpath_obj = xmlXPathEvalExpression(user_xexpr, xpath_ctx);
    if(xpath_obj == NULL) {
        dual_log("ERROR: unable to evaluate xpath expression: %s", user_xexpr);
        return(1);
    }
    if (xpath_obj->nodesetval != NULL && xpath_obj->nodesetval->nodeNr > 0) {
        temp_char = (char*) xmlXPathCastToString(xpath_obj);

		if ((pwd = getpwnam(temp_char)) == NULL) {
            dual_log("ERROR: User '%s' does not exist", temp_char);
            status += 1;
        }
		endpwent();

        StrFree(temp_char);
    }

    xmlXPathFreeObject(xpath_obj);

	return status;
}

int check_time_def(const char *time_expr, const char *location, const char *field, const char *filename, int* interval) {

	int status = DtXMLIntervalSeconds(time_expr, interval);

	if (status != 0) {
		switch (status) {
			case -1:
				dual_log("WARNING: In %s M used in duration field for %s (%s) in %s - this will be interpreted as 31 days", location, field, time_expr, filename);
				break;
			case -2:
				dual_log("WARNING: In %s Y used in duration field for %s (%s) in %s - this will be interpreted as 365 days", location, field, time_expr, filename);
				break;
			case -3:
				dual_log("WARNING: In %s M & Y used in duration field for %s (%s) in %s - these will be interpreted as 31 and 365 days respectively", location, field, time_expr, filename);
				break;
			case 2:
				dual_log("ERROR: unable to translate %s (%s) to seconds.", field, time_expr);
				break;
			case 3:
				dual_log("ERROR: %s (%s) too long to be an int. E.g. Maximum is ~68 years on a system with 32-bit integers.", field, time_expr);
				break;
			case 4:
				dual_log("ERROR: invalid pointers or text string NULL in %s (%s).", field, time_expr);
				break;
			default:
				dual_log("ERROR: unknown error converting %s (%s) to seconds", field, time_expr);
		}
	}

	if (status > 0) {
		*interval = 0;
		return 1;
	}

	return 0;
}

int check_time_def_from_xpath(xmlXPathContextPtr xpath_ctx, const xmlChar *time_xexpr, const char *location, const char *field, const char *filename) {
	
	xmlXPathObjectPtr xpath_obj;
	char* temp_char = NULL;
	int status = 0;
	int ignore = 0;

	xpath_obj = xmlXPathEvalExpression(time_xexpr, xpath_ctx);
	if(xpath_obj == NULL) {
		dual_log("ERROR: unable to evaluate xpath expression: %s", time_xexpr);
		return 1;
	}
    if (xpath_obj->nodesetval != NULL && xpath_obj->nodesetval->nodeNr > 0) {
		temp_char = (char *)xmlXPathCastToString(xpath_obj);
		status += check_time_def(temp_char, location, field, filename, &ignore);
		StrFree(temp_char);
	}

    xmlXPathFreeObject(xpath_obj);

	return status;
}

int check_policy(xmlNode *curNode, const char *policy_name, char **repo_list, int repo_count, const char *kasp) {
	int status = 0;
	int i = 0;
	char* temp_char = NULL;
	xmlNode *childNode;
	xmlNode *childNode2;
	xmlNode *childNode3;
	char my_policy[KC_NAME_LENGTH];
	int resign = 0;
	int resigns_per_day = 0;
	int refresh = 0;
	int defalt = 0;	/* default is not a suitable variable name */
	int denial = 0;
	int jitter = 0;
	int inception = 0;
	int ttl = 0;
	int retire = 0;
	int publish = 0;
	int nsec = 0;
	int hash_algo = 0;
	int resalt = 0;
	int ksk_algo = 0;
	int ksk_length = 0;
	int ksk_life = 0;
	char *ksk_repo = NULL;
	int zsk_algo = 0;
	int zsk_length = 0;
	int zsk_life = 0;
	char *zsk_repo = NULL;
	char *serial = NULL;
 
	snprintf(my_policy, KC_NAME_LENGTH, "policy %s,", policy_name);

	while (curNode) {
		if (xmlStrEqual(curNode->name, (const xmlChar *)"Signatures")) {
			childNode = curNode->children;
			while (childNode){
				if (xmlStrEqual(childNode->name, (const xmlChar *)"Resign")) {
					temp_char = (char *) xmlNodeGetContent(childNode);
					status += check_time_def(temp_char, my_policy, "Signatures/Resign", kasp, &resign);
					StrFree(temp_char);
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"Refresh")) {
					temp_char = (char *) xmlNodeGetContent(childNode);
					status += check_time_def(temp_char, my_policy, "Signatures/Refresh", kasp, &refresh);
					StrFree(temp_char);
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"Validity")) {
					childNode2 = childNode->children;
					while (childNode2){
						if (xmlStrEqual(childNode2->name, (const xmlChar *)"Default")) {
							temp_char = (char *) xmlNodeGetContent(childNode2);
							status += check_time_def(temp_char, my_policy, "Signatures/Validity/Default", kasp, &defalt);
							StrFree(temp_char);
						}
						else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Denial")) {
							temp_char = (char *) xmlNodeGetContent(childNode2);
							status += check_time_def(temp_char, my_policy, "Signatures/Validity/Denial", kasp, &denial);
							StrFree(temp_char);
						}
						childNode2 = childNode2->next;
					}
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"Jitter")) {
					temp_char = (char *) xmlNodeGetContent(childNode);
					status += check_time_def(temp_char, my_policy, "Signatures/Jitter", kasp, &jitter);
					StrFree(temp_char);
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"InceptionOffset")) {
					temp_char = (char *) xmlNodeGetContent(childNode);
					status += check_time_def(temp_char, my_policy, "Signatures/InceptionOffset", kasp, &inception);
					StrFree(temp_char);
				}

				childNode = childNode->next;
			}
		}
		else if (xmlStrEqual(curNode->name, (const xmlChar *)"Denial")) {
			childNode = curNode->children;
			while (childNode) {
				
				if (xmlStrEqual(childNode->name, (const xmlChar *)"NSEC")) {
					nsec = 1;
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"NSEC3")) {
					nsec = 3;
					childNode2 = childNode->children;
					while (childNode2){
						
						if (xmlStrEqual(childNode2->name, (const xmlChar *)"Resalt")) {
							temp_char = (char *) xmlNodeGetContent(childNode2);
							status += check_time_def(temp_char, my_policy, "Denial/NSEC3/Resalt", kasp, &resalt);
							StrFree(temp_char);
						} else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Hash")) {
							childNode3 = childNode2->children;
							while (childNode3) {
								
								if (xmlStrEqual(childNode3->name, (const xmlChar *)"Algorithm")) {
									temp_char = (char *) xmlNodeGetContent(childNode3);
									/* we know temp_char is a number */
									hash_algo = atoi(temp_char);
									if (hash_algo != 1) {
										dual_log("ERROR: NSEC3 Hash algorithm for %s Policy "
											"in %s is %d but should be 1", policy_name,
											kasp, hash_algo);
										status++;
									}
									StrFree(temp_char);
								}
								childNode3 = childNode3->next;

							}
						}

						childNode2 = childNode2->next;
					}
				}

				childNode = childNode->next;
			}
		}
		else if (xmlStrEqual(curNode->name, (const xmlChar *)"Keys")) {
			childNode = curNode->children;
			while (childNode) {

				if (xmlStrEqual(childNode->name, (const xmlChar *)"TTL")) {
					temp_char = (char *) xmlNodeGetContent(childNode);
					status += check_time_def(temp_char, my_policy, "Keys/TTL", kasp, &ttl);
					StrFree(temp_char);
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"RetireSafety")) {
					temp_char = (char *) xmlNodeGetContent(childNode);
					status += check_time_def(temp_char, my_policy, "Keys/RetireSafety", kasp, &retire);
					StrFree(temp_char);
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"PublishSafety")) {
					temp_char = (char *) xmlNodeGetContent(childNode);
					status += check_time_def(temp_char, my_policy, "Keys/PublishSafety", kasp, &publish);
					StrFree(temp_char);
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"KSK")) {
					childNode2 = childNode->children;
					while (childNode2){

						if (xmlStrEqual(childNode2->name, (const xmlChar *)"Algorithm")) {
							temp_char = (char *) xmlNodeGetContent(childNode2);
							StrStrtoi(temp_char, &ksk_algo);
							StrFree(temp_char);

							temp_char = (char *)xmlGetProp(childNode2, (const xmlChar *)"length");
							StrStrtoi(temp_char, &ksk_length);
							StrFree(temp_char);
						}
						else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Lifetime")) {
							temp_char = (char *) xmlNodeGetContent(childNode2);
							status += check_time_def(temp_char, my_policy, "Keys/KSK Lifetime", kasp, &ksk_life);
							StrFree(temp_char);
						}
						else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Repository")) {
							ksk_repo = (char *) xmlNodeGetContent(childNode2);
						}

						childNode2 = childNode2->next;
					}
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"ZSK")) {
					childNode2 = childNode->children;
					while (childNode2){

						if (xmlStrEqual(childNode2->name, (const xmlChar *)"Algorithm")) {
							temp_char = (char *) xmlNodeGetContent(childNode2);
							StrStrtoi(temp_char, &zsk_algo);
							StrFree(temp_char);

							temp_char = (char *)xmlGetProp(childNode2, (const xmlChar *)"length");
							StrStrtoi(temp_char, &zsk_length);
							StrFree(temp_char);

						}
						else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Lifetime")) {
							temp_char = (char *) xmlNodeGetContent(childNode2);
							status += check_time_def(temp_char, my_policy, "Keys/ZSK Lifetime", kasp, &zsk_life);
							StrFree(temp_char);
						}
						else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Repository")) {
							zsk_repo = (char *) xmlNodeGetContent(childNode2);
						}

						childNode2 = childNode2->next;
					}
				}
				
				childNode = childNode->next;
			}
		}
		else if (xmlStrEqual(curNode->name, (const xmlChar *)"Zone")) {
			childNode = curNode->children;
			while (childNode) {
				
				if (xmlStrEqual(childNode->name, (const xmlChar *)"SOA")) {
					childNode2 = childNode->children;
					while (childNode2){

						if (xmlStrEqual(childNode2->name, (const xmlChar *)"Serial")) {
							serial = (char *) xmlNodeGetContent(childNode2);
						}

						childNode2 = childNode2->next;
					}
				}

				childNode = childNode->next;
			}
		}


		curNode = curNode->next;
	}

	/* Now for the actual tests, from 
	 * https://wiki.opendnssec.org/display/OpenDNSSEC/Configuration+Checker+%28ods-kaspcheck%29 */

	/* For all policies, check that the "Re-sign" interval is less 
	 * than the "Refresh" interval. */
	if (refresh && refresh <= resign) {
		dual_log("ERROR: The Refresh interval (%d seconds) for "
				"%s Policy in %s is less than or equal to the Resign interval "
				"(%d seconds)", refresh, policy_name, kasp, resign);
		status++;
	}

	/* Ensure that the "Default" and "Denial" validity periods are 
	 * greater than the "Refresh" interval. */
	if (defalt <= refresh) {
		dual_log("ERROR: Validity/Default (%d seconds) for "
				"%s policy in %s is less than or equal to the Refresh interval "
				"(%d seconds)", defalt, policy_name, kasp, refresh);
		status++;
	}
	if (denial <= refresh) {
		dual_log("ERROR: Validity/Denial (%d seconds) for "
				"%s policy in %s is less than or equal to the Refresh interval "
				"(%d seconds)", denial, policy_name, kasp, refresh);
		status++;
	}

	/* Warn if "Jitter" is greater than 50% of the maximum of the "default" 
	 * and "Denial" period. (This is a bit arbitrary. The point is to get 
	 * the user to realise that there will be a large spread in the signature 
	 * lifetimes.) */
	if (defalt > denial) {
		if (jitter > (defalt * 0.5)) {
			dual_log("WARNING: Jitter time (%d seconds) is large " 
					"compared to Validity/Default (%d seconds) " 
					"for %s policy in %s", jitter, defalt, policy_name, kasp);
		}
	} else {
		if (jitter > (denial * 0.5)) {
			dual_log("WARNING: Jitter time (%d seconds) is large " 
					"compared to Validity/Denial (%d seconds) " 
					"for %s policy in %s", jitter, denial, policy_name, kasp);
		}
	}
	

	/* Warn if the InceptionOffset is greater than one hour. (Again arbitrary 
	 * - but do we really expect the times on two systems to differ by more 
	 *   than this?) */
	if (inception > 3600) {
		dual_log("WARNING: InceptionOffset is higher than expected "
				"(%d seconds) for %s policy in %s",
				inception, policy_name, kasp);
	}

	/* Warn if the "PublishSafety" and "RetireSafety" margins are less 
	 * than 0.1 * TTL or more than 5 * TTL. */
	if (publish < (ttl * 0.1)) {
		dual_log("WARNING: Keys/PublishSafety (%d seconds) is less than "
				"0.1 * TTL (%d seconds) for %s policy in %s",
				publish, ttl, policy_name, kasp);
	}
	else if (publish > (ttl * 5)) {
		dual_log("WARNING: Keys/PublishSafety (%d seconds) is greater than "
				"5 * TTL (%d seconds) for %s policy in %s",
				publish, ttl, policy_name, kasp);
	}

	if (retire < (ttl * 0.1)) {
		dual_log("WARNING: Keys/RetireSafety (%d seconds) is less than "
				"0.1 * TTL (%d seconds) for %s policy in %s",
				retire, ttl, policy_name, kasp);
	}
	else if (retire > (ttl * 5)) {
		dual_log("WARNING: Keys/RetireSafety (%d seconds) is greater than "
				"5 * TTL (%d seconds) for %s policy in %s",
				retire, ttl, policy_name, kasp);
	}

	/* The algorithm should be checked to ensure it is consistent with the 
	 * NSEC/NSEC3 choice for the zone. */
	if (nsec == 1) {
	}
	else if (nsec == 3) {
		if (ksk_algo <= 5) {
			dual_log("ERROR: In policy %s, incompatible algorithm (%d) used for "
					"KSK NSEC3 in %s. Policy must have id greater than 5.", policy_name, ksk_algo, kasp);
			status++;
		}
		if (zsk_algo <= 5) {
			dual_log("ERROR: In policy %s, incompatible algorithm (%d) used for "
					"ZSK NSEC3 in %s. Policy must have id greater than 5.", policy_name, zsk_algo, kasp);
			status++;
		}

		/* Warn if resalt is less than resign interval. */
		if (resalt < resign) {
			dual_log("WARNING: NSEC3 resalt interval (%d secs) is less than "
					"signature resign interval (%d secs) for %s Policy",
					resalt, resign, policy_name);
		}

	}

	/* If datecounter is used for serial, then no more than 99 signings 
	 * should be done per day (there are only two digits to play with in the 
	 * version number). */
	if (serial != NULL && strncmp(serial, "datecounter", 11) == 0) {
		if (resign != 0) {
			resigns_per_day = (60 * 60 * 24) / resign;
			if (resigns_per_day > 99) {
				dual_log("ERROR: In %s, policy %s, serial type datecounter used "
						"but %d re-signs requested. No more than 99 re-signs per "
						"day should be used with datecounter as only 2 digits are "
						"allocated for the version number.",
						kasp, policy_name, resigns_per_day);
				status++;
			}
		}
	}

	/* The key strength should be checked for sanity 
	 * - warn if less than 1024 or error if more than 4096. 
	 *   Only do this check for RSA. */
	if (ksk_algo == 5 || ksk_algo == 7 || ksk_algo == 8 || ksk_algo == 10) {
		if (ksk_length < 1024) {
			dual_log("WARNING: Key length of %d used for KSK in %s policy in %s. Should "
					"probably be 1024 or more", ksk_length, policy_name, kasp);
		}
		else if (ksk_length > 4096) {
			dual_log("ERROR: Key length of %d used for KSK in %s policy in %s. Should "
					"be 4096 or less", ksk_length, policy_name, kasp);
			status++;
		}
	}
	if (zsk_algo == 5 || zsk_algo == 7 || zsk_algo == 8 || zsk_algo == 10) {
		if (zsk_length < 1024) {
			dual_log("WARNING: Key length of %d used for ZSK in %s policy in %s. Should "
					"probably be 1024 or more", zsk_length, policy_name, kasp);
		}
		else if (zsk_length > 4096) {
			dual_log("ERROR: Key length of %d used for ZSK in %s policy in %s. Should "
					"be 4096 or less", zsk_length, policy_name, kasp);
			status++;
		}
	}

	/* Check that repositories listed in the KSK and ZSK sections are defined
	 * in conf.xml. */
	if (ksk_repo != NULL) {
		for (i = 0; i < repo_count; i++) {
			if (strcmp(ksk_repo, repo_list[i]) == 0) {
				break;
			}
		}
		if (i >= repo_count) {
			dual_log("ERROR: Unknown repository (%s) defined for KSK in "
					"%s policy in %s", ksk_repo, policy_name, kasp);
			status++;
		}
	}

	if (zsk_repo != NULL) {
		for (i = 0; i < repo_count; i++) {
			if (strcmp(zsk_repo, repo_list[i]) == 0) {
				break;
			}
		}
		if (i >= repo_count) {
			dual_log("ERROR: Unknown repository (%s) defined for ZSK in "
					"%s policy", zsk_repo, policy_name);
			status++;
		}
	}
	
	/* Warn if for any zone, the KSK lifetime is less than the ZSK lifetime. */
	if (ksk_life < zsk_life) {
		dual_log("WARNING: KSK minimum lifetime (%d seconds) is less than "
				"ZSK minimum lifetime (%d seconds) for %s Policy in %s",
				ksk_life, zsk_life, policy_name, kasp);
	}

	/* Check that the value of the "Serial" tag is valid. (Done by rng) */

	/* Error if Jitter is greater than either the Default or Denial Validity. */
	if (jitter > defalt) {
		dual_log("ERROR: Jitter time (%d seconds) is greater than the " 
				"Default Validity (%d seconds) for %s policy in %s",
				jitter, defalt, policy_name, kasp);
		status++;
	}
	if (jitter > denial) {
		dual_log("ERROR: Jitter time (%d seconds) is greater than the " 
				"Denial Validity (%d seconds) for %s policy in %s",
				jitter, denial, policy_name, kasp);
		status++;
	}

	StrFree(ksk_repo);
	StrFree(zsk_repo);
	StrFree(serial);

	return status;
}

/* NOTE: The following are taken from various files within libksm */

/*+
 * DtXMLIntervalSeconds - Parse xsd:durations Interval String
 *
 * Description:
 *      Parses an interval string which is of the form:
 *
 *          P<number>
 *      or  P<number><interval-type>
 *      or  PT<number><interval-type> (if the interval-type is H, M or S)
 *
 *      Without an interval type, the interval is assumed to be in seconds.
 *      Otherwise, the following interval types recognised are:
 *
 *          S       Seconds
 *          M       Minutes - multiply number by 60 (no. seconds in a minute)
 *          H       Hours - multiply number by 3600 (no. seconds in an hour)
 *          D       Day - multiply number by 86400 (no. seconds in a day)
 *          W       Week - multiply number by 604,800 (no. seconds in a week)
 *          M       Month - multiply number by 2,678,400 (no. seconds in 31 days)
 *          Y       Year - multiply number by 31,536,000 (no. seconds in 365 days)
 *
 *      Lower-case characters are not recognised.
 *
 *      Example: The string P2D would translate to 172,800
 *
 * Arguments:
 *      const char* text
 *          Interval as a string.
 *
 *      long* interval
 *          Returned interval.
 *
 * Returns:
 *      int
 *        < 0       Success, string translated OK _BUT_ may not be what was expected
 *                          (Year or Month used which gives approximate answer).
 *          0       Success, string translated OK
 *          2       Error - unable to translate string.
 *          3       Error - string too long to be a number.
 *          4       Error - invalid pointers or text string NULL.
 *
 * Known issues:
 * 
 *      1. Years and months are only approximate as it has no concept of "now"
 *         We use 31 days = 1 month and 365 days = 1 year.
 *      2. The "T" only effects the value of "M" (P1S should be illegal as correctly
 *         it would be PT1S)
 *
 * NOTE: This is copied from ksm/datatime.c and modified slightly to separate
 * 		 "Y" and "M" warnings
 *
-*/

int DtXMLIntervalSeconds(const char* text, int* interval)
{
    int     length = 0;         /* Length of the string */
    short   is_time = 0;    /* Do we have a Time section or not */
    short   is_neg = 0;    /* Do we have a negative number */
    short   warning = 0;    /* Do we need a warning code for duration approximation? */
    short   got_temp = 0;    /* Have we seen a number? */
    long long    temp = 0;       /* Number from this section */
    const char  *ptr = text;    /* allow us to read through */

    int status = 0;

    long long temp_interval = 0;

    if (text && interval && *text) {
        length = strlen(text);
    } else {
        return(4);
    }

    if (ptr && length && interval) {
        const char *end = text + length;
        if (*ptr == '-') {
            is_neg = 1;
            ptr++;
        }
        if (*ptr == 'P') {
            ptr++;
        }
        do {
            switch (*ptr) {
                case 'S':
                    if (got_temp) {
                        temp_interval += temp;
                        temp = 0;
                        got_temp = 0;
                    } else {
                        return(2);
                    }
                    break;

                case 'M':
                    if (got_temp) {
                        if (is_time) {
                            temp_interval += 60 * temp;
                        } else {
                            temp_interval += 31 * 24 * 60 * 60 * temp;
                            warning -= 1;
                        }
                        temp = 0;
                        got_temp = 0;
                    } else {
                        return(2);
                    }
                    break;

                case 'H':
                    if (got_temp) {
                        temp_interval += 60 * 60 * temp;
                        temp = 0;
                        got_temp = 0;
                    } else {
                        return(2);
                    }
                    break;

                case 'D':
                    if (got_temp) {
                        temp_interval += 24 * 60 * 60 * temp;
                        temp = 0;
                        got_temp = 0;
                    } else {
                        return(2);
                    }
                    break;

                case 'W':
                    if (got_temp) {
                        temp_interval += 7 * 24 * 60 * 60 * temp;
                        temp = 0;
                        got_temp = 0;
                    } else {
                        return(2);
                    }
                    break;

                case 'Y':
                    if (got_temp) {
                        temp_interval += 365 * 24 * 60 * 60 * temp;
                        temp = 0;
                        warning -= 2;
                        got_temp = 0;
                    } else {
                        return(2);
                    }
                    break;

                case 'T':
                    is_time = 1;
                    break;

                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    if (!temp) {
                        temp = atoll(ptr);
                        got_temp = 1;
                        if ((temp_interval <= INT_MIN) || (temp_interval >= INT_MAX)) {
                            return(3);
                        }
                    }
                    break;

                default:
                    if (ptr != end) {
                        return(2);
                    }
            }
        } while (ptr++ < end);
    }
    else {
        status = 2;     /* Can't translate string/overflow */
    }

    /* If we had no trailing letter then it is an implicit "S" */
    if (temp) {
        temp_interval += temp;
        temp = 0;
    }

    if (is_neg == 1) {
        temp_interval = 0 - temp_interval;
    }

    if (warning < 0) {
        status = warning;
    }

    if ((temp_interval >= INT_MIN) && (temp_interval <= INT_MAX)) {
        *interval = (int) temp_interval;
    }
    else {
        status = 3;     /* Integer overflow */
    }

    return status;
}

/*+
 * StrStrtoi - Convert String to int
 *
 * Description:
 *      Converts a string to a "int".
 *
 *      This version strips out tabs and whitespace characters.
 *
 * Arguments:
 *      const char* string (input)
 *          String to convert.
 *
 *      int* value (returned)
 *          Return value.
 *
 * Returns:
 *      int
 *          0   Success
 *          1   Conversion failed
-*/

int StrStrtoi(const char* string, int* value)
{
    long    longval;    /* "long" to be passed to StrStrtol */
    int     status;     /* Status return */

    if (value == NULL) {
        dual_log("ERROR: NULL value passed to StrStrtoi");
        return 1;
    }
    status = StrStrtol(string, &longval);
    if (status == 0) {
        if ((longval >= INT_MIN) && (longval <= INT_MAX)) {
            *value = (int) longval;
        }
        else {
            status = 1;     /* Integer overflow */
        }
    }

    return status;
}

/*+
 * StrStrtol - Convert String to long
 *
 * Description:
 *      Converts a string to a "long".  It uses strtol, but also passes
 *      back a status code to indicate if the conversion was successful.
 *
 *      This version strips out tabs and whitespace characters.
 *
 * Arguments:
 *      const char* string (input)
 *          String to convert.
 *
 *      long* value (returned)
 *          Return value.
 *
 * Returns:
 *      int
 *          0   Success
 *          1   Conversion failed
-*/

int StrStrtol(const char* string, long* value)
{
    char*   endptr;         /* End of string pointer */
    int     status = 1;     /* Assume failure */
    char*   copy;           /* Copy of the string */
    char*   start;          /* Start of the trimmed string */

    if (value == NULL) {
        dual_log("ERROR: NULL value passed to StrStrtol");
        return 1;
    }
    if (string) {
        copy = StrStrdup(string);
        StrTrimR(copy);             /* Remove trailing spaces */
        start = StrTrimL(copy);     /* ... and leading ones */
        if (*start) {

            /* String is not NULL, so try a conversion */

            errno = 0;
            *value = strtol(start, &endptr, 10);

            /* Only success if all characters converted */

            if (errno == 0) {
                status = (*endptr == '\0') ? 0 : 1;
            }
            else {
                status = 1;
            }
        }
        StrFree(copy);
    }

    return status;
}

/*+
 * StrStrdup - Duplicate String
 *
 * Description:
 *      Wrapper for "strdup" that always returns, or exits the program (after
 *      outputting a message to stderr) if the string duplication fails.
 *
 * Arguments:
 *      const char* string (input)
 *          String to be duplicated.
 *
 * Returns:
 *      char*
 *          Pointer to duplicated string (guaranteed to be non-null).  The
 *          string should be freed with StrFree() - a macro wrapper for "free".
-*/

char* StrStrdup(const char* string)
{
    char* duplicate = NULL; /* Pointer to the duplicated string */

    if (string) {
        duplicate = strdup(string);
        if (duplicate == NULL) {
			dual_log("ERROR: StrStrdup: Call to malloc() returned null - out of swap space?");
            exit(1);
        }
    }
    else {
        duplicate = MemCalloc(1, 1);    /* Allocate a single zeroed byte */
    }

    return duplicate;
}

/*+
 * StrAppend - Append String with Reallocation
 *
 * Description:
 *      Appends the given string to a dynamically-allocated string, reallocating
 *      the former as needed.
 *
 *      The function is a no-op if either of its arguments are NULL.
 *
 * Arguments:
 *      char** str1
 *          On input this holds the current string.  It is assumed that the
 *          string has been dynamically allocated (with malloc or the like).
 *          On output, this holds the concatenation of the two strings.
 *
 *          If, on input, the string is NULL (i.e. *str is NULL, *not* str1 is
 *          NULL), a new string is allocated and str2 copied to it.
 *
 *          On exit, the string can be freed via a call to StrFree.
 *
 *      const char* str2
 *          The string to be appended.
-*/

void StrAppend(char** str1, const char* str2)
{
    int len1;   /* Length of string 1 */
    int len2;   /* Length of string 2 */

    if (str1 && str2) {

        /* Something to append and we can append it */

        len2 = strlen(str2);
        if (*str1) {
            len1 = strlen(*str1);

            /* Allocate space for combined string and concatenate */

            *str1 = MemRealloc(*str1, (len1 + len2 + 1) * sizeof(char));
            strcat(*str1, str2);
        }
        else {

            /* Nothing in string 1, so just duplicate string 2 */

            *str1 = StrStrdup(str2);
        }
    }

    return;
}

/*+
 * StrTrimR - Trim Right
 *
 * Description:
 *      Modifies a string by trimming white-space characters from the right of
 *      the string.  It does this by modifying the string, inserting a null
 *      character after the last non white-space character.
 *
 * Arguments:
 *      char *text (modified)
 *          Text to modify.  If this is NULL, the routine is a no-op.
 *
 * Returns:
 *      void
-*/

void StrTrimR(char *text)
{
    if (text) {

        /* Work backwards through the string */

        int textlen = strlen(text);
        while (-- textlen >= 0) {
            if (! isspace((int) text[textlen])) {
                text[textlen + 1] = '\0';
                return;
            }
        }

        /* Get here if the entire string is white space */

        text[0] = '\0';
    }
    return;
}

/*+
 * StrTrimL - Trim Left
 *
 * Description:
 *      Searches a string and returns a pointer to the first non white-space
 *      character in it.
 *
 * Arguments:
 *      char* text (input)
 *          Text to search.
 *
 * Returns:
 *      char* 
 *          Pointer to first non white-space character in the string.  If the
 *          string is NULL, NULL is returned.  If the string is all white space,
 *          a pointer to the trailing null character is returned.
-*/

char* StrTrimL(char* text)
{
    if (text) {
        while (*text && isspace((int) *text)) {
            ++text;
        }
    }

    return text;
}

void* MemCalloc(size_t nmemb, size_t size)
{
    void *ptr = calloc(nmemb, size);
    if (ptr == NULL) {
		dual_log("ERROR: calloc: Out of swap space");
		exit(1);
    }
    return ptr;
}

void* MemRealloc(void *ptr, size_t size)
{
    void *ptr1 = realloc(ptr, size);
    if (ptr1 == NULL) {
		dual_log("ERROR: realloc: Out of swap space");
        exit(1);
    }
    return ptr1;
}
