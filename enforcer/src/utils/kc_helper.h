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

#ifndef KC_HELPER_H
#define KC_HELPER_H

#ifdef LOG_DAEMON
#define DEFAULT_LOG_FACILITY LOG_DAEMON
#define DEFAULT_LOG_FACILITY_STRING "LOG_DAEMON"
#else
#define DEFAULT_LOG_FACILITY LOG_USER
#define DEFAULT_LOG_FACILITY_STRING "LOG_USER"
#endif /* LOG_DAEMON */

#include "config.h"
#include <libxml/xpath.h>

#define KC_NAME_LENGTH     256

typedef struct {
	char *name;
	char *module;
	char *TokenLabel;
} KC_REPO;

int check_conf(const char *conf, char **kasp, char **zonelist, 
	char ***repo_listout, int *repo_countout, int verbose);
int check_kasp(const char *kasp, char **repo_list, int repo_count, int verbose,
    char ***policy_names_out, int *policy_count_out);
int check_zonelist(const char *zonelist, int verbose, char **policy_names,
    int policy_count);

void log_init(int facility, const char *program_name);
void log_switch(int facility, const char *program_name);
void dual_log(const char *format, ...)
#ifdef HAVE___ATTRIBUTE__
     __attribute__ ((format (printf, 1, 2)))
#endif
     ;


int check_rng(const char *filename, const char *rngfilename, int verbose);

int check_file(const char *filename, const char *log_string);
int check_file_from_xpath(xmlXPathContextPtr xpath_ctx, const char *log_string, const xmlChar *file_xexpr);

int check_path(const char *pathname, const char *log_string);
int check_path_from_xpath(xmlXPathContextPtr xpath_ctx, const char *log_string, const xmlChar *path_xexpr);

int check_user_group(xmlXPathContextPtr xpath_ctx, const xmlChar *user_xexpr, const xmlChar *group_xexpr);

int check_time_def(const char *time_expr, const char *location, const char *field, const char *filename, int* interval);
int check_time_def_from_xpath(xmlXPathContextPtr xpath_ctx, const xmlChar *time_xexpr, const char *location, const char *field, const char *filename);

/* if repo_list NULL, will skip the check to see all repositories in kasp are available in conf */
int check_policy(xmlNode *curNode, const char *policy_name, char **repo_list, int repo_count, const char *kasp);

int DtXMLIntervalSeconds(const char* text, int* interval);
int StrStrtoi(const char* string, int* value);
int StrStrtol(const char* string, long* value);
char* StrStrdup(const char* string);
void StrTrimR(char *text);
char* StrTrimL(char* text);
void* MemCalloc(size_t nmemb, size_t size);

#endif /* KC_HELPER_H */
