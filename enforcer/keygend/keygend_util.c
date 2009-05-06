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
 *
 */

/* 
 * keygend_util.c utilities needed by keygend
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
  xmlChar *xexpr = "//Configuration/Enforcer/KeygenInterval";
  int mysec = 0;
  int status;
  char* filename = CONFIGFILE;
  char* rngfilename = CONFIGRNG;
 
  log_msg(config, LOG_INFO, "Reading config \"%s\"\n", filename);
  
  /* Load XML document */
  doc = xmlParseFile(filename);
  if (doc == NULL) {
	  log_msg(config, LOG_ERR, "Error: unable to parse file \"%s\"\n", filename);
	    return(-1);
  }

  /* Load rng document */
  log_msg(config, LOG_INFO, "Reading config schema \"%s\"\n", rngfilename);
  rngdoc = xmlParseFile(rngfilename);
  if (rngdoc == NULL) {
	  log_msg(config, LOG_ERR, "Error: unable to parse file \"%s\"\n", rngfilename);
	    return(-1);
  }

  /* Create an XML RelaxNGs parser context for the relax-ng document. */
  rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);
  if (rngpctx == NULL) {
	  log_msg(config, LOG_ERR, "Error: unable to create XML RelaxNGs parser context\n");
	    return(-1);
  }
  
  /* parse a schema definition resource and build an internal XML Shema struture which can be used to validate instances. */
  schema = xmlRelaxNGParse(rngpctx);
  if (schema == NULL) {
	  log_msg(config, LOG_ERR, "Error: unable to parse a schema definition resource\n");
	    return(-1);
  }
  
  /* Create an XML RelaxNGs validation context based on the given schema */
  rngctx = xmlRelaxNGNewValidCtxt(schema);
  if (rngctx == NULL) {
	  log_msg(config, LOG_ERR, "Error: unable to create RelaxNGs validation context based on the schema\n");
	    return(-1);
  }
  
  /* Validate a document tree in memory. */
  status = xmlRelaxNGValidateDoc(rngctx,doc);
  if (status != 0) {
    log_msg(config, LOG_ERR, "Error validating file \"%s\"\n", filename);
    return(-1);
  }

  /* Now parse a value out of the conf */
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
      log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s\n", xexpr);
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
  xmlRelaxNGFree(schema);
  xmlRelaxNGFreeValidCtxt(rngctx);
  xmlRelaxNGFreeParserCtxt(rngpctx);
  xmlFreeDoc(rngdoc);

  return(0);
  
}