/*
 * $Id$
 *
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation).
 * All rights reserved.
 *
 * Written by Björn Stenberg <bjorn@haxx.se> for .SE
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include "config.h"

#define CONFIG_FILE     "eppclientd.conf"

static xmlXPathContext* context;

char* config_registry_value(char* registry, char* value)
{
    char path[80];
    snprintf(path, sizeof path, "/eppclient/registry[suffix='%s']/%s",
             registry, value);
    return config_value(path);
}

char* config_value(char* path)
{
    static char result[256];
    result[0] = 0;
    int dlen = 0;

    xmlXPathObject* obj = xmlXPathEvalExpression((xmlChar*)path, context);
    if (obj) {
        if (obj->nodesetval && obj->nodesetval->nodeNr) {
            xmlNode* node = obj->nodesetval->nodeTab[0];
            
            if (node && node->children && node->children->content)
                node = node->children;

            while (node) {
                strncpy(result + dlen, (char*)node->content, sizeof(result) - dlen);
                dlen += strlen(result + dlen);

                if (dlen == sizeof result) {
                    result[sizeof result - 1] = 0;
                    syslog(LOG_WARNING, "config_value: Result buffer full");
                    break;
                }

                node = node->next;
            }
        }
        xmlXPathFreeObject(obj);
    }
    else
        syslog(LOG_DEBUG,
               "Error: unable to evaluate xpath expression '%s'", path);

    return result;
}

void read_config(void)
{
    xmlDoc* doc = xmlParseFile(CONFIG_FILE);
    if (!doc)
        doc = xmlParseFile("/etc/" CONFIG_FILE);
    if (!doc)
        doc = xmlParseFile("/etc/opt/" CONFIG_FILE);
    if (!doc)
        doc = xmlParseFile("/usr/local/etc/" CONFIG_FILE);
    if (!doc) {
        syslog(LOG_ERR, "%s: %s", CONFIG_FILE, strerror(errno));
        perror(CONFIG_FILE);
        exit(-1);
    }

    context = xmlXPathNewContext(doc);
    if(!context) {
        syslog(LOG_DEBUG,"error: unable to create new XPath context");
        xmlFreeDoc(doc); 
        exit(-1);
    }
}
