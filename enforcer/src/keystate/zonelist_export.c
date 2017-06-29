/*
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
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

#include "config.h"

#include "log.h"
#include "str.h"
#include "clientpipe.h"
#include "db/dbw.h"
#include "utils/kc_helper.h"

#include "keystate/zonelist_export.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int zonelist_export(int sockfd, db_connection_t* dbconn, const char* filename, int comment) {
    xmlDocPtr doc;
    xmlNodePtr root = NULL, node, node2, node3, node4;
    char path[PATH_MAX];
    char* dirname, *dirlast;

    if (!dbconn || !filename) {
        return ZONELIST_EXPORT_ERR_ARGS;
    }

    if (access(filename, W_OK)) {
        if (errno != ENOENT) {
            client_printf_err(sockfd, "Write access to file denied: %s\n", strerror(errno));
            return ZONELIST_EXPORT_ERR_FILE;
        }
        /* full path doesn't exist, try stripping filname */
        if (!(dirname = strdup(filename))) {
            client_printf_err(sockfd, "Memory error\n");
            return ZONELIST_EXPORT_ERR_FILE;
        }
        if (!(dirlast = strrchr(dirname, '/'))) {
            client_printf_err(sockfd, "Unable to construct path.\n");
            return ZONELIST_EXPORT_ERR_FILE;
        }
        *dirlast = 0;
        if (access(dirname, W_OK)) {
            client_printf_err(sockfd, "Write access to directory denied: %s\n", strerror(errno));
            free(dirname);
            return ZONELIST_EXPORT_ERR_FILE;
        }
        free(dirname);
    }

    if (!(doc = xmlNewDoc((xmlChar*)"1.0"))
        || !(root = xmlNewNode(NULL, (xmlChar*)"ZoneList")))
    {
        client_printf_err(sockfd, "Unable to create XML elements, memory allocation error!\n");
        xmlFreeDoc(doc);
        return ZONELIST_EXPORT_ERR_MEMORY;
    }

    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) {
        client_printf_err(sockfd, "Unable to get list of zones, memory"
            "allocation or database error!\n");
        xmlFreeDoc(doc);
        return ZONELIST_EXPORT_ERR_DATABASE ;
    }

    if (comment) {
        node = xmlNewComment((xmlChar*)
            "\n\n"
            "********* Important changes to zonelist.xml in 2.0 ***************\n"
            "\n"
            "In 2.0, the zonelist.xml file is no longer automatically updated when zones\n"
            "are added or deleted  via the command line by using the 'ods-enforcer zone add'\n"
            "command. However, in 2.0 it is possible to force an update of the zonelist.xml\n"
            "file by using the new 'xml' flag. This is in contrast to the behaviour in 1.4\n"
            "where zonelist.xml was always updated, unless the 'no-xml' flag was used. \n"
            "\n");
        xmlNodeAddContent(node, (xmlChar*)
            "As a result in 2.0 the contents of the enforcer database should be considered\n"
            "the 'master' for the list of currently configured zones, not the zonelist.xml\n"
            "file as the file can easily become out of sync with the database.\n"
            "\n");
        xmlNodeAddContent(node, (xmlChar*)
            "The contents of the database can be listed using:\n"
            "  ods-enforcer zone list\n"
            "and exported using the command\n"
            "  ods-enforcer zonelist export\n"
            "The contents of the database can still be updated in bulk from the zonelist.xml\n"
            "file by using the command:\n"
            "  ods-enforcer zonelist import    (or ods-enforcer update zonelist)\n\n"
        );
        xmlAddChild(root, node);
    }
    xmlDocSetRootElement(doc, root);

    for (size_t z = 0; z < db->zones->n; z++) {
        struct dbw_zone *zone = (struct dbw_zone *)db->zones->set[z];
        if (!(node = xmlNewChild(root, NULL, (xmlChar*)"Zone", NULL))
            || !xmlNewProp(node, (xmlChar*)"name", (xmlChar*)zone->name)
            || !xmlNewChild(node, NULL, (xmlChar*)"Policy", (xmlChar*)zone->policy->name)
            || !xmlNewChild(node, NULL, (xmlChar*)"SignerConfiguration", (xmlChar*)zone->signconf_path)
            || !(node2 = xmlNewChild(node, NULL, (xmlChar*)"Adapters", NULL))
            || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Input", NULL))
            || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Adapter", (xmlChar*)zone->input_adapter_uri))
            || !xmlNewProp(node4, (xmlChar*)"type", (xmlChar*)zone->input_adapter_type)
            || !(node3 = xmlNewChild(node2, NULL, (xmlChar*)"Output", NULL))
            || !(node4 = xmlNewChild(node3, NULL, (xmlChar*)"Adapter", (xmlChar*)zone->output_adapter_uri))
            || !xmlNewProp(node4, (xmlChar*)"type", (xmlChar*)zone->output_adapter_type))
        {
            client_printf_err(sockfd, "Unable to create XML elements for zone %s!\n", zone->name);
            xmlFreeDoc(doc);
            dbw_free(db);
            return ZONELIST_EXPORT_ERR_XML;
        }
    }
    dbw_free(db);

    if (snprintf(path, sizeof(path), "%s.new", filename) >= (int)sizeof(path)) {
        client_printf_err(sockfd, "Unable to write zonelist, memory allocation error!\n");
        xmlFreeDoc(doc);
        return ZONELIST_EXPORT_ERR_MEMORY;
    }
    unlink(path);
    if (xmlSaveFormatFileEnc(path, doc, "UTF-8", 1) == -1) {
        client_printf_err(sockfd, "Unable to write zonelist, LibXML error!\n");
        xmlFreeDoc(doc);
        return ZONELIST_EXPORT_ERR_FILE;
    }
    xmlFreeDoc(doc);

    if (check_zonelist(path, 0, NULL, 0)) {
        client_printf_err(sockfd, "Unable to validate the exported zonelist XML!\n");
        unlink(path);
        return ZONELIST_EXPORT_ERR_XML;
    }

    if (rename(path, filename)) {
        client_printf_err(sockfd, "Unable to write zonelist, rename failed!\n");
        unlink(path);
        return ZONELIST_EXPORT_ERR_FILE;
    }

    return ZONELIST_EXPORT_OK;
}
