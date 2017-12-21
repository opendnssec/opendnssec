/*
 * Copyright (c) 2015 Stichting NLnet Labs
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
 *
 */

#include "enforcer/repositorylist_cmd.h"
#include "daemon/engine.h"
#include "clientpipe.h"
#include "log.h"
#include "str.h"
#include <libxml/xpath.h>
#include <libxml/xmlreader.h>
#include "file.h"

static const char *module_str = "repositorylist_cmd";

static int
perform_repositorylist(int sockfd)
{
	const char* cfgfile = ODS_SE_CFGFILE;
	xmlDocPtr doc = NULL;
        xmlNode *curNode;
        xmlXPathContextPtr xpathCtx = NULL;
        xmlXPathObjectPtr xpathObj = NULL;

	const char *fmt = "%-31s %-13s %-13s\n";
	char *capacity = NULL;
	int backup;
	char *repository = NULL;
	int i;


	xmlChar *xexpr = (unsigned char *)"//Configuration/RepositoryList/Repository";	
	doc = xmlParseFile(cfgfile);
	if (doc == NULL) {
        	ods_log_error("[%s] unable to read cfgfile %s", module_str, cfgfile);
	        return -1;
    	}

	xpathCtx = xmlXPathNewContext(doc);
	if (xpathCtx == NULL) {
        	ods_log_error("[%s] unable to create new XPath context for cfgfile"
            	"%s expr %s", module_str, cfgfile, xexpr);
        	xmlFreeDoc(doc);
        	return -1;
    	}

	xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
	if(xpathObj == NULL) {
		ods_log_error("[%s] unable to evaluate required element %s in "
                "cfgfile %s", module_str, xexpr, cfgfile);
	        xmlXPathFreeContext(xpathCtx);
        	xmlFreeDoc(doc);
	        return -1;
    	}

	client_printf(sockfd, "Repositories:\n");
	client_printf(sockfd, fmt, "Name:", "Capacity:", "RequireBackup:");

	if (xpathObj->nodesetval){
		for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
			curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
			repository = (char*)xmlGetProp(xpathObj->nodesetval->nodeTab[i], (const xmlChar *)"name");

			backup = 0;
			while (curNode) {
				if (xmlStrEqual(curNode->name, (const xmlChar *)"Capacity"))
					capacity = (char*) xmlNodeGetContent(curNode);
				if (xmlStrEqual(curNode->name, (const xmlChar *)"RequireBackup"))
					backup = 1;
				curNode = curNode->next;
			}
			client_printf(sockfd, fmt, repository, capacity?capacity:"-", backup?"Yes":"No");
			free(repository);
			repository = NULL;
			free(capacity);
			capacity = NULL;
		}
	}

	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);
	xmlFreeDoc(doc);
	
	
	return 0;
}

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"repository list\n");
}

static void
help(int sockfd)
{
	client_printf(sockfd, "List repositories.\n\n");
}

static int
run(int sockfd, cmdhandler_ctx_type* context, char *cmd)
{
	(void)cmd;
	ods_log_debug("[%s] %s command", module_str, 
		repositorylist_funcblock.cmdname);

	if (perform_repositorylist(sockfd)) {
		ods_log_error_and_printf(sockfd, module_str,
			"unable to list repositories ");
		return 1;
	}
	return 0;
}

struct cmd_func_block repositorylist_funcblock = {
	"repository list", &usage, &help, NULL, &run
};
