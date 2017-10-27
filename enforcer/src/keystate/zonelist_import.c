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
#include "clientpipe.h"
#include "db/dbw.h"
#include "utils/kc_helper.h"
#include "hsmkey/hsm_key_factory.h"
#include "enforcer/enforce_task.h"
#include "keystate/zonelist_export.h"

#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "keystate/zonelist_import.h"

static const char* module_str = "zonelist_import";

struct xml_zone {
    char *name;
    char *policy;
    char *signconf;
    char *inadapter_type;
    char *inadapter_uri;
    char *outadapter_type;
    char *outadapter_uri;
};

static int
xml_read_child(xmlNodePtr node, struct xml_zone *zone);

static int
xml_read_children(xmlNodePtr pnode, struct xml_zone *zone)
{
    xmlNodePtr cnode = pnode->children;
    while (cnode) {
        if (cnode->type == XML_ELEMENT_NODE) {
            if (xml_read_child(cnode, zone)) return 1;
        }
        cnode = cnode->next;
    }
    return 0;
}

static int
xml_read_child(xmlNodePtr node, struct xml_zone *zone)
{
    if (!strcmp((char*)node->name, "Zone")) {
        zone->name = xmlGetProp(node, (xmlChar *)"name");
        if (xml_read_children(node, zone)) return 1;
    } else if (!strcmp((char*)node->name, "Policy")) {
        zone->policy = xmlNodeGetContent(node);
    } else if (!strcmp((char*)node->name, "SignerConfiguration")) {
        zone->signconf = xmlNodeGetContent(node);
    } else if (!strcmp((char*)node->name, "Adapters")) {
        if (xml_read_children(node, zone)) return 1;
    } else if (!strcmp((char*)node->name, "Input")) {
        if (xml_read_children(node, zone)) return 1;
    } else if (!strcmp((char*)node->name, "Output")) {
        if (xml_read_children(node, zone)) return 1;
    } else if (!strcmp((char*)node->name, "File")) {
        if (!strcmp(node->parent->name, "Input")) {
            zone->inadapter_type = strdup("File");
            zone->inadapter_uri = xmlNodeGetContent(node);
        } else if (!strcmp(node->parent->name, "Output")) {
            zone->outadapter_type = strdup("File");
            zone->outadapter_uri = xmlNodeGetContent(node);
        } else {
            return 1;
        }
    } else if (!strcmp((char*)node->name, "Adapter")) {
        if (!strcmp(node->parent->name, "Input")) {
            zone->inadapter_type = xmlGetProp(node, (xmlChar *)"type");
            zone->inadapter_uri = xmlNodeGetContent(node);
        } else if (!strcmp(node->parent->name, "Output")) {
            zone->outadapter_type = xmlGetProp(node, (xmlChar *)"type");
            zone->outadapter_uri = xmlNodeGetContent(node);
        } else {
            return 1;
        }
    } else {
        ods_log_deeebug("[zone_*_from_xml] unknown %s", (char*)node->name);
        return 1;
    }
    return 0;
}

/* 1 looks good, 0 some error */
static int
validate_zone(int sockfd, struct xml_zone *z)
{
    if (!(z->name && z->policy && z->signconf && z->inadapter_type
           && z->inadapter_uri && z->outadapter_type && z->outadapter_uri))
    {
        return 0;
    }
    if(!strcmp(z->inadapter_uri,"File")){
        if(access(z->inadapter_uri, F_OK) == -1) {
            client_printf_err(sockfd, "WARNING: The input file %s for zone %s "
                "does not currently exist. The zone will be added to the "
                "database anyway.\n", z->inadapter_uri, z->name);
            ods_log_warning("[%s] WARNING: The input file %s for zone %s "
                "does not currently exist. The zone will be added to the "
                "database anyway.", module_str, z->inadapter_uri, z->name);
        } else if (access(z->inadapter_uri, R_OK)) {
            client_printf_err(sockfd, module_str, "WARNING: Read access to "
                "input file %s for zone %s denied! \n", z->inadapter_uri, z->name);
            ods_log_warning("[%s] WARNING: Read access to input file %s for "
                "zone %s denied!", module_str, z->inadapter_uri, z->name);
        }
    }
    return 1;
}

static void
xml_zone_scrub(struct xml_zone *xml)
{
    free(xml->name);
    free(xml->policy);
    free(xml->signconf);
    free(xml->inadapter_uri);
    free(xml->inadapter_type);
    free(xml->outadapter_uri);
    free(xml->outadapter_type);
}

/* 0 for equal*/
static int
zone_xml_cmp(struct dbw_db *db, struct dbw_zone *zone, struct xml_zone *xml)
{
    return (strcasecmp(zone->policy->name, xml->policy)
        || strcasecmp(zone->signconf_path, xml->signconf)
        || strcasecmp(zone->input_adapter_uri, xml->inadapter_uri)
        || strcasecmp(zone->input_adapter_type, xml->inadapter_type)
        || strcasecmp(zone->output_adapter_uri, xml->outadapter_uri)
        || strcasecmp(zone->output_adapter_type, xml->outadapter_type));
}

static int
process_xml(int sockfd, xmlNodePtr root, struct dbw_db *db)
{
    xmlNodePtr node;
    struct xml_zone xz;

    for (; root; root = root->next) {
        if (root->type != XML_ELEMENT_NODE) continue;
        if (strcmp((char*)root->name, "ZoneList")) continue;
        for (node = root->children; node; node = node->next) {
            if (node->type != XML_ELEMENT_NODE) continue;
            memset(&xz, 0, sizeof (struct xml_zone));
            if (xml_read_child(node, &xz)) {
                client_printf_err(sockfd, "Unable to create zone %s from XML, XML "
                    "content may be improperly formatted.\n", xz.name?xz.name:"[unknown]");
                return 1;
            }
            if (!validate_zone(sockfd, &xz)) {
                client_printf_err(sockfd, "Unable to create zone %s from XML, XML "
                    "content may be invalid.\n", xz.name?xz.name:"[unknown]");
                xml_zone_scrub(&xz);
                return 1;
            }
            struct dbw_policy *p = dbw_get_policy(db, xz.policy);
            if (!p) {
                client_printf_err(sockfd, "Can't find policy %s in database.\n", xz.policy);
                xml_zone_scrub(&xz);
                return 1;
            }
            struct dbw_zone *zone = dbw_get_zone(db, xz.name);
            if (!zone) { /* create new  */
                zone = calloc(1, sizeof (struct dbw_zone));
                if (!zone) {
                    client_printf_err(sockfd, "zonelist import memory error.\n");
                    xml_zone_scrub(&xz);
                    return 1;
                }
                zone->dirty = DBW_INSERT;
                zone->scratch = 1;
                zone->name                = xz.name;
                zone->policy              = p;
                zone->signconf_path       = xz.signconf;
                zone->input_adapter_uri   = xz.inadapter_uri;
                zone->input_adapter_type  = xz.inadapter_type;
                zone->output_adapter_uri  = xz.outadapter_uri;
                zone->output_adapter_type = xz.outadapter_type;
                if (dbw_add_zone(db, p, zone)) {
                    client_printf_err(sockfd, "zonelist import memory error.\n");
                    dbw_zone_free((struct dbrow *)zone);
                    return 1;
                }
            } else {
                zone->scratch = 1;
                if (!zone_xml_cmp(db, zone, &xz)) {
                    zone->dirty = DBW_CLEAN;
                    xml_zone_scrub(&xz);
                    continue;
                }
                zone->dirty = DBW_UPDATE;
                free(zone->signconf_path);
                free(zone->input_adapter_uri);
                free(zone->input_adapter_type);
                free(zone->output_adapter_uri);
                free(zone->output_adapter_type);
                free(xz.name);
                zone->policy              = p;
                zone->signconf_path       = xz.signconf;
                zone->input_adapter_uri   = xz.inadapter_uri;
                zone->input_adapter_type  = xz.inadapter_type;
                zone->output_adapter_uri  = xz.outadapter_uri;
                zone->output_adapter_type = xz.outadapter_type;
            }
        }
    }
    return 0;
}

int zonelist_import(int sockfd, engine_type* engine, db_connection_t *dbconn,
    int do_delete, const char* zonelist_path)
{
    xmlDocPtr doc;
    xmlNodePtr root;
    struct dbw_db *db = dbw_fetch(dbconn);
    if (!db) return ZONELIST_IMPORT_ERR_DATABASE;

    /* Validate, parse and walk the XML. */
    if (!zonelist_path)
        zonelist_path = engine->config->zonelist_filename;
    if (check_zonelist(zonelist_path, 0, NULL, 0)) {
        client_printf_err(sockfd, "Unable to validate the zonelist XML!\n");
        dbw_free(db);
        return ZONELIST_IMPORT_ERR_XML;
    } else if (!(doc = xmlParseFile(zonelist_path))) {
        client_printf_err(sockfd, "Unable to read/parse zonelist XML file %s!\n",
            zonelist_path);
        dbw_free(db);
        return ZONELIST_IMPORT_ERR_XML;
    } else if (!(root = xmlDocGetRootElement(doc))) {
        client_printf_err(sockfd, "Unable to get the root element in the zonelist XML!\n");
        xmlFreeDoc(doc);
        dbw_free(db);
        return ZONELIST_IMPORT_ERR_XML;
    }

    for (size_t z = 0; z < db->zones->n; z++) {
        /* All zones not mentioned xml will be deleted */
        db->zones->set[z]->scratch = 0;
    }
    int r = process_xml(sockfd, root, db);
    xmlFreeDoc(doc);
    if (r) {
        dbw_free(db);
        return ZONELIST_IMPORT_ERR_XML;
    }
    int updates = 0; /* did anything change at all?  */
    for (size_t z = 0; z < db->zones->n; z++) {
        struct dbw_zone *zone = (struct dbw_zone *)db->zones->set[z];
        updates |= zone->scratch;
        if (do_delete && !zone->scratch && zone->dirty == DBW_CLEAN) {
            /* This zone is not visited at all, therefore must be deleted */
            zone->dirty = DBW_DELETE;
            for (size_t k = 0; k < zone->key_count; k++) {
                struct dbw_key *key = zone->key[k];
                key->dirty = DBW_DELETE;
                for (size_t s = 0; s < key->keystate_count; s++) {
                    struct dbw_keystate *keystate = key->keystate[s];
                    keystate->dirty = DBW_DELETE;
                }
                hsm_key_factory_release_key(key->hsmkey, key);
            }
        }
    }
    if (dbw_commit(db)) {
        r = ZONELIST_IMPORT_ERR_DATABASE;
    } else if (updates) {
        /** export zonelist */
        if (zonelist_export(sockfd, dbconn, zonelist_path, 0) != ZONELIST_EXPORT_OK) {
            ods_log_error("[%s] internal zonelist update failed", module_str);
            client_printf_err(sockfd, "Unable to update the internal zonelist %s, updates will not reach the Signer!\n", zonelist_path);
        } else {
            ods_log_info("[%s] internal zonelist updated successfully", module_str);
        }

        hsm_key_factory_schedule_generate_all(engine, 0);
        /* schedule all changed zones */
        for (size_t z = 0; z < db->zones->n; z++) {
            struct dbw_zone *zone = (struct dbw_zone *)db->zones->set[z];
            if (!zone->scratch || !zone->dirty) continue;
            enforce_task_flush_zone(engine, zone->name);
        }
        r = ZONELIST_IMPORT_OK;
    } else {
        r = ZONELIST_IMPORT_NO_CHANGE;
    }
    dbw_free(db);
    return r;
}

