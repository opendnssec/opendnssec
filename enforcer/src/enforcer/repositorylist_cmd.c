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
perform_repositorylist(int sockfd, engine_type* engine)
{
	const char* cfgfile = ODS_SE_CFGFILE;
	xmlDocPtr doc = NULL;
        xmlNode *curNode;
        xmlXPathContextPtr xpathCtx = NULL;
        xmlXPathObjectPtr xpathObj = NULL;

	const char *fmt = "%-31s %-13s %-13s\n";
	char *capacity = NULL;
	char *backup = NULL;
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

			while (curNode) {
				if (xmlStrEqual(curNode->name, (const xmlChar *)"Capacity"))
					capacity = (char*) xmlNodeGetContent(curNode);
				if (xmlStrEqual(curNode->name, (const xmlChar *)"RequireBackup")){
                                        backup = strdup("Yes");
				}
				curNode = curNode->next;
			}
			client_printf(sockfd, fmt, repository, capacity?capacity:"-", backup?backup:"No");
			free(repository);
			repository = NULL;
			free(backup);
			backup = NULL;
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
		"Repository List  \n");
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, repositorylist_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	(void)cmd; (void)n, (void)dbconn;
	ods_log_debug("[%s] %s command", module_str, 
		repositorylist_funcblock()->cmdname);

	if (perform_repositorylist(sockfd, engine)) {
		ods_log_error_and_printf(sockfd, module_str,
			"unable to list repositories ");
		return 1;
	}
	return 0;
}

static struct cmd_func_block funcblock = {
	"repository list", &usage, NULL, &handles, &run
};

struct cmd_func_block*
repositorylist_funcblock(void)
{
	return &funcblock;
}
