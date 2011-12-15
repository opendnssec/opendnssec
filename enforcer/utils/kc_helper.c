/*
 * $Id$
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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

#include "ksm/string_util.h"
#include "ksm/string_util2.h"

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>

#include "kc_helper.h"

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
	else {
		vsyslog(LOG_INFO, format, args);
	}

	vprintf(format, args2);
	
	va_end(args);
	va_end(args2);
}

/* XML Error Message */
    void
log_xml_error(void *ignore, const char *format, ...)
{
    va_list args;
    va_list args2;

    (void) ignore;

    /* If the variable arg list is bad then random errors can occur */ 
    va_start(args, format);
	va_copy(args2, args);

    vsyslog(LOG_ERR, format, args);
	vprintf(format, args2);

    va_end(args);
	va_end(args2);
}

/* XML Warning Message */
    void
log_xml_warn(void *ignore, const char *format, ...)
{
    va_list args;
    va_list args2;

    (void) ignore;

    /* If the variable arg list is bad then random errors can occur */ 
    va_start(args, format);
	va_copy(args2, args);

    vsyslog(LOG_INFO, format, args);
	vprintf(format, args2);

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

   	/* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        dual_log("ERROR: unable to parse file \"%s\"\n", filename);
        return(1);
    }

    /* Load rng document */
    rngdoc = xmlParseFile(rngfilename);
    if (rngdoc == NULL) {
        dual_log("ERROR: unable to parse file \"%s\"\n", rngfilename);
        return(1);
    }

    /* Create an XML RelaxNGs parser context for the relax-ng document. */
    rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);
    if (rngpctx == NULL) {
        dual_log("ERROR: unable to create XML RelaxNGs parser context\n");
        return(1);
    }

	xmlRelaxNGSetValidErrors(rngctx,
		(xmlRelaxNGValidityErrorFunc) log_xml_error,
		(xmlRelaxNGValidityWarningFunc) log_xml_warn,
		NULL);

    /* parse a schema definition resource and build an internal XML Shema struture which can be used to validate instances. */
    schema = xmlRelaxNGParse(rngpctx);
    if (schema == NULL) {
        dual_log("ERROR: unable to parse a schema definition resource\n");
        return(1);
    }

    /* Create an XML RelaxNGs validation context based on the given schema */
    rngctx = xmlRelaxNGNewValidCtxt(schema);
    if (rngctx == NULL) {
        dual_log("ERROR: unable to create RelaxNGs validation context based on the schema\n");
        return(1);
    }

    /* Validate a document tree in memory. */
    if (xmlRelaxNGValidateDoc(rngctx,doc) != 0) {
        dual_log("ERROR: %s fails to validate\n", filename);
        return(1);
    }

	xmlRelaxNGFree(schema);
    xmlRelaxNGFreeValidCtxt(rngctx);
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
	}

    if (S_ISREG(stat_ret.st_mode)) {
        /* The file exists */
		return 0;
    }

	dual_log("ERROR: %s (%s) does not exist\n", log_string, filename);
	return 1;
}

int check_file_from_xpath(xmlXPathContextPtr xpath_ctx, const char *log_string, const xmlChar *file_xexpr) {
	int status = 0;
	xmlXPathObjectPtr xpath_obj;
	char* temp_char = NULL;

	xpath_obj = xmlXPathEvalExpression(file_xexpr, xpath_ctx);
	if(xpath_obj == NULL) {
		dual_log("ERROR: unable to evaluate xpath expression: %s", file_xexpr);
		return 1;
	}
    if (xpath_obj->nodesetval != NULL && xpath_obj->nodesetval->nodeNr > 0) {
		temp_char = (char*) xmlXPathCastToString(xpath_obj);

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
	}

    if (S_ISDIR(stat_ret.st_mode)) {
        /* The directory exists */
		return 0;
    }

	dual_log("ERROR: %s (%s) does not exist\n", log_string, pathname);

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
            dual_log("ERROR: group '%s' does not exist.\n", temp_char);
            status += 1;
        }
		endgrent();

        StrFree(temp_char);
    }

	/* User if specified */
	xpath_obj = xmlXPathEvalExpression(user_xexpr, xpath_ctx);
    if(xpath_obj == NULL) {
        dual_log("ERROR: unable to evaluate xpath expression: %s", user_xexpr);
        return(1);
    }
    if (xpath_obj->nodesetval != NULL && xpath_obj->nodesetval->nodeNr > 0) {
        temp_char = (char*) xmlXPathCastToString(xpath_obj);

		if ((pwd = getpwnam(temp_char)) == NULL) {
            dual_log("ERROR: user '%s' does not exist.\n", temp_char);
            status += 1;
        }
		endpwent();

        StrFree(temp_char);
    }

	return status;
}

int check_time_def(const char *time_expr, const char *location, const char *field, const char *filename, int* interval) {

	int status = DtXMLIntervalSeconds(time_expr, interval);

	if (status != 0) {
		switch (status) {
			case -1:
				dual_log("WARNING: In %s M used in duration field for %s (%s) in %s - this will be interpreted as 31 days\n", location, field, time_expr, filename);
				break;
			case -2:
				dual_log("WARNING: In %s Y used in duration field for %s (%s) in %s - this will be interpreted as 365 days\n", location, field, time_expr, filename);
				break;
			case -3:
				dual_log("WARNING: In %s M & Y used in duration field for %s (%s) in %s - these will be interpreted as 31 and 365 days respectively\n", location, field, time_expr, filename);
				break;
			case 2:
				dual_log("ERROR: unable to translate %s (%s) to seconds.\n", field, time_expr);
				break;
			case 3:
				dual_log("ERROR: %s (%s) too long to be an int. E.g. Maximum is ~68 years on a system with 32-bit integers.\n", field, time_expr);
				break;
			case 4:
				dual_log("ERROR: invalid pointers or text string NULL in %s (%s).\n", field, time_expr);
				break;
			default:
				dual_log("ERROR: unknown error converting %s (%s) to seconds\n", field, time_expr);
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

	return status;
}

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

int check_policy(xmlNode *curNode, const char *policy_name, char **repo_list, int repo_count, const char *kasp) {
	int status = 0;
	int i = 0;
	char* temp_char = NULL;
	xmlNode *childNode;
	xmlNode *childNode2;
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
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"Refresh")) {
					temp_char = (char *) xmlNodeGetContent(childNode);
					status += check_time_def(temp_char, my_policy, "Signatures/Refresh", kasp, &refresh);
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"Validity")) {
					childNode2 = childNode->children;
					while (childNode2){
						if (xmlStrEqual(childNode2->name, (const xmlChar *)"Default")) {
							temp_char = (char *) xmlNodeGetContent(childNode2);
							status += check_time_def(temp_char, my_policy, "Signatures/Validity/Default", kasp, &defalt);
						}
						else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Denial")) {
							temp_char = (char *) xmlNodeGetContent(childNode2);
							status += check_time_def(temp_char, my_policy, "Signatures/Validity/Denial", kasp, &denial);
						}
						childNode2 = childNode2->next;
					}
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"Jitter")) {
					temp_char = (char *) xmlNodeGetContent(childNode);
					status += check_time_def(temp_char, my_policy, "Signatures/Jitter", kasp, &jitter);
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"InceptionOffset")) {
					temp_char = (char *) xmlNodeGetContent(childNode);
					status += check_time_def(temp_char, my_policy, "Signatures/InceptionOffset", kasp, &inception);
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
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"RetireSafety")) {
					temp_char = (char *) xmlNodeGetContent(childNode);
					status += check_time_def(temp_char, my_policy, "Keys/RetireSafety", kasp, &retire);
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"PublishSafety")) {
					temp_char = (char *) xmlNodeGetContent(childNode);
					status += check_time_def(temp_char, my_policy, "Keys/PublishSafety", kasp, &publish);
				}
				else if (xmlStrEqual(childNode->name, (const xmlChar *)"KSK")) {
					childNode2 = childNode->children;
					while (childNode2){

						if (xmlStrEqual(childNode2->name, (const xmlChar *)"Algorithm")) {
							temp_char = (char *) xmlNodeGetContent(childNode2);
							StrStrtoi(temp_char, &ksk_algo);

							temp_char = (char *)xmlGetProp(childNode2, (const xmlChar *)"length");
							StrStrtoi(temp_char, &ksk_length);
						}
						else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Lifetime")) {
							temp_char = (char *) xmlNodeGetContent(childNode2);
							status += check_time_def(temp_char, my_policy, "Keys/KSK Lifetime", kasp, &ksk_life);
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

							temp_char = (char *)xmlGetProp(childNode2, (const xmlChar *)"length");
							StrStrtoi(temp_char, &zsk_length);

						}
						else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Lifetime")) {
							temp_char = (char *) xmlNodeGetContent(childNode2);
							status += check_time_def(temp_char, my_policy, "Keys/ZSK Lifetime", kasp, &zsk_life);
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
	if (refresh <= resign) {
		dual_log("ERROR: The Refresh interval (%d seconds) for "
				"%s Policy is less than or equal to the Resign interval "
				"(%d seconds)\n", refresh, policy_name, resign);
		status++;
	}

	/* Ensure that the "Default" and "Denial" validity periods are 
	 * greater than the "Refresh" interval. */
	if (defalt <= refresh) {
		dual_log("ERROR: Validity/Default (%d seconds) for "
				"%s Policy is less than or equal to the Refresh interval "
				"(%d seconds)\n", defalt, policy_name, refresh);
		status++;
	}
	if (denial <= refresh) {
		dual_log("ERROR: Validity/Denial (%d seconds) for "
				"%s Policy is less than or equal to the Refresh interval "
				"(%d seconds)\n", denial, policy_name, refresh);
		status++;
	}

	/* Warn if "Jitter" is greater than 50% of the maximum of the "default" 
	 * and "Denial" period. (This is a bit arbitrary. The point is to get 
	 * the user to realise that there will be a large spread in the signature 
	 * lifetimes.) */
	if (defalt > denial) {
		if (jitter > (defalt * 0.5)) {
			dual_log("WARNING: Jitter time (%d seconds) is large " 
					"compared to Validity/Default " 
					"(%d seconds) for %s policy\n", jitter, defalt, policy_name);
		}
	} else {
		if (jitter > (denial * 0.5)) {
			dual_log("WARNING: Jitter time (%d seconds) is large " 
					"compared to Validity/Denial " 
					"(%d seconds) for %s policy\n", jitter, denial, policy_name);
		}
	}
	

	/* Warn if the InceptionOffset is greater than one hour. (Again arbitrary 
	 * - but do we really expect the times on two systems to differ by more 
	 *   than this?) */
	if (inception > 3600) {
		dual_log("WARNING: InceptionOffset is higher than expected "
				"(%d seconds) for %s policy\n", inception, policy_name);
	}

	/* Warn if the "PublishSafety" and "RetireSafety" margins are less 
	 * than 0.1 * TTL or more than 5 * TTL. */
	if (publish < (ttl * 0.1)) {
		dual_log("WARNING: PublishSafety (%d seconds) is less than "
				"0.1 * TTL (%d seconds) for %s policy\n", publish, ttl, policy_name);
	}
	else if (publish > (ttl * 5)) {
		dual_log("WARNING: PublishSafety (%d seconds) is greater than "
				"5 * TTL (%d seconds) for %s policy\n", publish, ttl, policy_name);
	}

	if (retire < (ttl * 0.1)) {
		dual_log("WARNING: RetireSafety (%d seconds) is less than "
				"0.1 * TTL (%d seconds) for %s policy\n", retire, ttl, policy_name);
	}
	else if (retire > (ttl * 5)) {
		dual_log("WARNING: RetireSafety (%d seconds) is greater than "
				"5 * TTL (%d seconds) for %s policy\n", retire, ttl, policy_name);
	}

	/* The algorithm should be checked to ensure it is consistent with the 
	 * NSEC/NSEC3 choice for the zone. */
	if (nsec == 1) {
	}
	else if (nsec == 3) {
		if (ksk_algo != 6 && ksk_algo != 7 && ksk_algo != 8 && ksk_algo != 10) {
			dual_log("ERROR: In policy %s, incompatible algorithm (%d) used for "
					"KSK - should be 6,7,8 or 10.\n", policy_name, ksk_algo);
			status++;
		}
		if (zsk_algo != 6 && zsk_algo != 7 && zsk_algo != 8 && zsk_algo != 10) {
			dual_log("ERROR: In policy %s, incompatible algorithm (%d) used for "
					"ZSK - should be 6,7,8 or 10.\n", policy_name, zsk_algo);
			status++;
		}

		/* Warn if resalt is less than resign interval. */
		if (resalt < resign) {
			dual_log("WARNING: NSEC3 resalt interval (%d secs) is less than "
					"signature resign interval (%d secs) for %s Policy\n",
					resalt, resign, policy_name);
		}

	}

	/* If datecounter is used for serial, then no more than 99 signings 
	 * should be done per day (there are only two digits to play with in the 
	 * version number). */
	if (strncmp(serial, "datecounter", 11) == 0) {
		resigns_per_day = (60 * 60 * 24) / resign;
		if (resigns_per_day > 99) {
			dual_log("ERROR : In policy %s, serial type datecounter used "
					"but %d re-signs requested. No more than 99 re-signs per "
					"day should be used with datecounter as only 2 digits are "
					"allocated for the version number.\n", policy_name, resigns_per_day);
			status++;
		}
	}

	/* The key strength should be checked for sanity 
	 * - warn if less than 1024 or error if more than 4096. 
	 *   Only do this check for RSA. */
	if (ksk_algo == 5 || ksk_algo == 7 || ksk_algo == 8 || ksk_algo == 10) {
		if (ksk_length < 1024) {
			dual_log("WARNING: Key length of %d used for KSK in %s policy. Should "
					"probably be 1024 or more.\n", ksk_length, policy_name);
		}
		else if (ksk_length > 4096) {
			dual_log("ERROR: Key length of %d used for KSK in %s policy. Should "
					"be 4096 or less.\n", ksk_length, policy_name);
			status++;
		}
	}
	if (zsk_algo == 5 || zsk_algo == 7 || zsk_algo == 8 || zsk_algo == 10) {
		if (zsk_length < 1024) {
			dual_log("WARNING: Key length of %d used for ZSK in %s policy. Should "
					"probably be 1024 or more.\n", zsk_length, policy_name);
		}
		else if (zsk_length > 4096) {
			dual_log("ERROR: Key length of %d used for ZSK in %s policy. Should "
					"be 4096 or less.\n", zsk_length, policy_name);
			status++;
		}
	}

	/* Check that repositories listed in the KSK and ZSK sections are defined
	 * in conf.xml. */
	for (i = 0; i < repo_count; i++) {
		if (strcmp(ksk_repo, repo_list[i]) == 0) {
			break;
		}
	}
	if (i >= repo_count) {
		dual_log("ERROR: Unknown repository (%s) defined for KSK in "
				"%s policy\n", ksk_repo, policy_name);
		status++;
	}

	for (i = 0; i < repo_count; i++) {
		if (strcmp(zsk_repo, repo_list[i]) == 0) {
			break;
		}
	}
	if (i >= repo_count) {
		dual_log("ERROR: Unknown repository (%s) defined for ZSK in "
				"%s policy\n", zsk_repo, policy_name);
		status++;
	}
	

	/* Warn if for any zone, the KSK lifetime is less than the ZSK lifetime. */
	if (ksk_life < ksk_life) {
		dual_log("WARNING: KSK minimum lifetime (%d seconds) is less than "
				"ZSK minimum lifetime (%d seconds) for %s Policy\n", 
				ksk_life, zsk_life, policy_name);
	}

	/* Check that the value of the "Serial" tag is valid. (Done by rng) */

	/* Error if Jitter is greater than either the Default or Denial Validity. */
	if (jitter > defalt) {
		dual_log("ERROR: Jitter time (%d seconds) is greater than the " 
				"Validity/Default} (%d seconds) for %s policy\n", jitter, defalt, policy_name);
		status++;
	}
	if (jitter > denial) {
		dual_log("ERROR: Jitter time (%d seconds) is greater than the " 
				"Validity/Denial} (%d seconds) for %s policy\n", jitter, denial, policy_name);
		status++;
	}

	return status;
}
