/* 
* keygend_util.c utilities needed by keygend
*
* Copyright (c) 2008 2009, John Dickinson. All rights reserved.
*
* See LICENSE for the license.
*/
#include <stdlib.h>
#include <errno.h>

#include <config.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>

#include "daemon.h"
#include "daemon_util.h"

#include "datetime.h"
/*
* Go to sleep
*/

void
keygensleep(DAEMONCONFIG* config)
{
  struct timeval tv;

  tv.tv_sec = config->keygeninterval;
  tv.tv_usec = 0;
  log_msg(config, LOG_INFO, "Sleeping for %i seconds.",config->keygeninterval);
  select(0, NULL, NULL, NULL, &tv);
}

int
ReadConfig(DAEMONCONFIG *config)
{
  xmlDocPtr doc;
  xmlDocPtr rngdoc;
  xmlXPathContextPtr xpathCtx;
  xmlXPathObjectPtr xpathObj;
  xmlRelaxNGParserCtxtPtr rngpctx;
  xmlRelaxNGValidCtxtPtr rngctx;
  xmlRelaxNGPtr schema;
  xmlChar *xexpr;
  xexpr = "//Configuration/Enforcer/KeygenInterval";
  int mysec = 0;
  int status;
  char* filename = CONFIGFILE;
  char* rngfilename = CONFIGFILE;
  log_msg(config, LOG_INFO, "Reading config.\n");
  /* Load XML document */
  doc = xmlParseFile(filename);
  if (doc == NULL) {
	  log_msg(config, LOG_ERR, "Error: unable to parse file \"%s\"\n", filename);
	    return(-1);
  }

  /* Load rng document */
  rngdoc = xmlParseFile(rngfilename);
  if (rngdoc == NULL) {
	  log_msg(config, LOG_ERR, "Error: unable to parse file \"%s\"\n", rngfilename);
	    return(-1);
  }

  /* Create an XML RelaxNGs parser context for the relax-ng document. */
  rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);

  /* parse a schema definition resource and build an internal XML Shema struture which can be used to validate instances. */
  schema = xmlRelaxNGParse(rngpctx);

  /* Create an XML RelaxNGs validation context based on the given schema */
  rngctx = xmlRelaxNGNewValidCtxt(schema);

  /* Validate a document tree in memory. */
  status = xmlRelaxNGValidateDoc(rngctx,doc);
  if (status != 0) {
    log_msg(config, LOG_ERR, "Error validating file \"%s\"\n", filename);
  }

  /* Now parse a value out of the conf */
  /* lets try and get the keygeninterval */

  /* Create xpath evaluation context */
  xpathCtx = xmlXPathNewContext(doc);
  if(xpathCtx == NULL) {
      log_msg(config, LOG_ERR,"Error: unable to create new XPath context\n");
      xmlFreeDoc(doc);
      return(-1);
  }

  /* Evaluate xpath expression */
  xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
  if(xpathObj == NULL) {
      fprintf(stderr,"Error: unable to evaluate xpath expression\n");
      xmlXPathFreeContext(xpathCtx);
      xmlFreeDoc(doc);
      return(-1);
  }
  
  DtXMLIntervalSeconds(xmlXPathCastToString(xpathObj), &mysec);
  config->keygeninterval = mysec;
  log_msg(config, LOG_INFO, "Key Generation Interval: %i\n", config->keygeninterval);
  
  /* Cleanup */
  /* TODO: some other frees are needed */
  xmlXPathFreeObject(xpathObj);
  xmlXPathFreeContext(xpathCtx);
  xmlFreeDoc(doc);

  return(0);
  
}