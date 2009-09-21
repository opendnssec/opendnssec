/*
 * $Id: zone_fetcher.c 1810 2009-09-15 14:49:55Z matthijs $
 *
 * Copyright (c) 2009 NLnet Labs. All rights reserved.
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

#include "config.h"
#include "util.h"

#include <getopt.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlsave.h>

/**
 * Zone list.
 */
typedef struct zonelist_struct zonelist_type;
struct zonelist_struct
{
    char* name;
    char* axfr_output;
    char* axfr_config;
    char* input_file;
    char* server_name;
    char* tsig_name;
    char* tsig_algo;
    char* tsig_secret;
    zonelist_type* next;
};

static void
usage(FILE *out)
{
    fprintf(out, "Usage: zone_fetcher [OPTIONS]\n");
    fprintf(out, "Transfers zones from their master.\n");
    fprintf(out, "Options:\n");
    fprintf(out, "-h\t\tShow this help\n");
    fprintf(out, "-z <file>\tThe zonelist.xml <file>\n");
}

static zonelist_type*
new_zone(char* zone_name, char* input_file, char* axfr_config)
{
    zonelist_type* zlt = (zonelist_type*) malloc(sizeof(zonelist_type));
    zlt->name = strdup(zone_name);
    zlt->input_file = strdup(input_file);
    zlt->axfr_config = strdup(axfr_config);
    zlt->next = NULL;
    return zlt;
}

static void
free_zonelist(zonelist_type* zlt)
{
    if (zlt) {
        free_zonelist(zlt->next);
        if (zlt->tsig_name)            free((void*) zlt->tsig_name);
        if (zlt->tsig_algo)            free((void*) zlt->tsig_algo);
        if (zlt->tsig_secret)          free((void*) zlt->tsig_secret);
        if (zlt->server_name)          free((void*) zlt->server_name);
        free((void*) zlt->name);
        free((void*) zlt->input_file);
        free((void*) zlt->axfr_config);
        free((void*) zlt);
    }
}

static int
read_axfr_config(zonelist_type* zonelist)
{
    int ret;
    int use_tsig = 0;
    char* tag_name, *zone_name, *tsig_name, *tsig_algo, *tsig_secret, *server_name;

    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlChar *name_expr = (unsigned char*) "name";
    xmlChar *tsig_expr = (unsigned char*) "//Zone/TSIG";
    xmlChar *tsig_name_expr = (unsigned char*) "//Zone/TSIG/Name";
    xmlChar *tsig_algo_expr = (unsigned char*) "//Zone/TSIG/Algorithm";
    xmlChar *tsig_secret_expr = (unsigned char*) "//Zone/TSIG/Secret";
    xmlChar *server_expr = (unsigned char*) "//Zone/Server";

    /* In case zonelist is huge use the XmlTextReader API so that we don't hold the whole file in memory */
    reader = xmlNewTextReaderFilename(zonelist->axfr_config);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            tag_name = (char*) xmlTextReaderLocalName(reader);
            /* Found <Zone> */
            if (strncmp(tag_name, "Zone", 4) == 0 &&
                xmlTextReaderNodeType(reader) == 1) {
                /* Get the zone name (TODO what if this is null?) */
                zone_name = (char*) xmlTextReaderGetAttribute(reader, name_expr);
                /* Make sure that we got something */
                if (zone_name == NULL || strcmp(zone_name, zonelist->name) != 0) {
                    /* error */
                    fprintf(stderr, "zone_fetcher: error extracting zone name from %s\n", zonelist->axfr_config);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    free(tag_name);
                    continue;
                }
                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                doc = xmlTextReaderCurrentDoc(reader);
                if (doc == NULL) {
                    fprintf(stderr, "zone_fetcher: can not read AXFR config for zone \"%s\"; skipping", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    free(tag_name);
                    continue;
                }
                xpathCtx = xmlXPathNewContext(doc);
                if (xpathCtx == NULL) {
                    fprintf(stderr, "zone_fetcher: can not create XPath context for AXFR config for zone \"%s\"; "
                        "skipping zone", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    free(tag_name);
                    continue;
                }

                xpathObj = xmlXPathEvalExpression(server_expr, xpathCtx);
                if (xpathObj == NULL) {
                    fprintf(stderr, "zone_fetcher: can not locate master server for zone \"%s\"; "
                        "skipping zone", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    free(tag_name);
                    continue;
                }
                server_name = (char*) xmlXPathCastToString(xpathObj);

                /* Extract the tsig credentials */
                xpathObj = xmlXPathEvalExpression(tsig_expr, xpathCtx);
                if (xpathObj != NULL) {
                    use_tsig = 1;
                }
                if (use_tsig) {
                    xpathObj = xmlXPathEvalExpression(tsig_name_expr, xpathCtx);
                    if (xpathObj == NULL) {
                        fprintf(stderr, "zone_fetcher: can not locate TSIG name for zone \"%s\"; "
                            "skipping zone", zone_name);
                        /* Don't return? try to parse the rest of the zones? */
                        ret = xmlTextReaderRead(reader);
                        free(server_name);
                        free(tag_name);
                        continue;
                    }
                    tsig_name = (char*) xmlXPathCastToString(xpathObj);

                    xpathObj = xmlXPathEvalExpression(tsig_algo_expr, xpathCtx);
                    if (xpathObj == NULL) {
                        fprintf(stderr, "zone_fetcher: can not locate TSIG algo for zone \"%s\"; "
                            "skipping zone", zone_name);
                        /* Don't return? try to parse the rest of the zones? */
                        ret = xmlTextReaderRead(reader);
                        free(server_name);
                        free(tag_name);
                        continue;
                    }
                    tsig_algo = (char*) xmlXPathCastToString(xpathObj);

                    xpathObj = xmlXPathEvalExpression(tsig_secret_expr, xpathCtx);
                    if (xpathObj == NULL) {
                        fprintf(stderr, "zone_fetcher: can not locate TSIG secret for zone \"%s\"; "
                            "skipping zone", zone_name);
                        /* Don't return? try to parse the rest of the zones? */
                        ret = xmlTextReaderRead(reader);
                        free(server_name);
                        free(tag_name);
                        continue;
                    }
                    tsig_secret = (char*) xmlXPathCastToString(xpathObj);

                    zonelist->tsig_name = strdup(tsig_name);
                    zonelist->tsig_algo = strdup(tsig_algo);
                    zonelist->tsig_secret = strdup(tsig_secret);
                    free(tsig_name);
                    free(tsig_algo);
                    free(tsig_secret);
                }

                zonelist->server_name = strdup(server_name);
                free(server_name);
            }

            /* Read the next line */
            ret = xmlTextReaderRead(reader);
            free(tag_name);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            fprintf(stderr, "zone_fetcher: failed to parse axfr_config %s\n", zonelist->axfr_config);
        }
    } else {
        fprintf(stderr, "zone_fetcher: unable to open axfr config %s\n", zonelist->axfr_config);
    }

    return 0;
}

static zonelist_type*
read_zonelist(const char* filename)
{
    zonelist_type* zonelist = NULL, *zonelist_start = NULL;
    char* tag_name, *zone_name, *input_file, *axfr_config;
    int ret;

    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlChar *name_expr = (unsigned char*) "name";
    xmlChar *adapter_expr = (unsigned char*) "//Zone/Adapters/Input/File";
    xmlChar *axfr_expr = (unsigned char*) "//Zone/AxfrConfiguration";

    /* In case zonelist is huge use the XmlTextReader API so that we don't hold the whole file in memory */
    reader = xmlNewTextReaderFilename(filename);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            tag_name = (char*) xmlTextReaderLocalName(reader);
            /* Found <Zone> */
            if (strncmp(tag_name, "Zone", 4) == 0 &&
                strncmp(tag_name, "ZoneList", 8) != 0 &&
                xmlTextReaderNodeType(reader) == 1) {
                /* Get the zone name (TODO what if this is null?) */
                zone_name = (char*) xmlTextReaderGetAttribute(reader, name_expr);
                /* Make sure that we got something */
                if (zone_name == NULL) {
                    /* error */
                    fprintf(stderr, "zone_fetcher: error extracting zone name from %s\n", filename);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                doc = xmlTextReaderCurrentDoc(reader);
                if (doc == NULL) {
                    fprintf(stderr, "zone_fetcher: can not read zone \"%s\"; skipping", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                xpathCtx = xmlXPathNewContext(doc);
                if (xpathCtx == NULL) {
                    fprintf(stderr, "zone_fetcher: can not create XPath context for \"%s\"; skipping zone", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                /* Extract the AXFR Configuration filename */
                xpathObj = xmlXPathEvalExpression(axfr_expr, xpathCtx);
                if (xpathObj == NULL) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                axfr_config = (char*) xmlXPathCastToString(xpathObj);

                /* Extract the Input File Adapter filename */
                xpathObj = xmlXPathEvalExpression(adapter_expr, xpathCtx);
                if (xpathObj == NULL) {
                    fprintf(stderr, "zone_fetcher: unable to evaluate xpath expression: %s; skipping zone", adapter_expr);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                input_file = (char*) xmlXPathCastToString(xpathObj);

                if (zonelist == NULL) {
                    zonelist = new_zone(zone_name, input_file, axfr_config);
                    zonelist_start = zonelist;
                }
                else {
                    zonelist->next = new_zone(zone_name, input_file, axfr_config);
                    zonelist = zonelist->next;
                }
				free(zone_name);
				free(input_file);
            }

            /* Read the next line */
            ret = xmlTextReaderRead(reader);
            free(tag_name);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            fprintf(stderr, "zone_fetcher: failed to parse zonelist %s\n", filename);
        }
    } else {
        fprintf(stderr, "zone_fetcher: unable to open zonelist %s\n", filename);
    }
    return zonelist_start;
}

int
main(int argc, char **argv)
{
    const char* zonelist_file = NULL;
    const char* axfr_dir = "/opt/opendnssec/var/opendnssec/axfr/";

    zonelist_type* zonelist = NULL, *zonelist_start = NULL;
    uint32_t serial = 0;
    FILE* fd;
    int c;

    while ((c = getopt(argc, argv, "hz:")) != -1) {
        switch (c) {
        case 'h':
            usage(stdout);
            exit(EXIT_SUCCESS);
        case 'z':
            zonelist_file = optarg;
            break;
        case '?':
        default:
            usage(stderr);
            exit(EXIT_FAILURE);
            break;
        }
    }

    if (argc > optind) {
        fprintf(stderr, "zone_fetcher: error: extraneous arguments\n");
        usage(stderr);
        exit(EXIT_FAILURE);
    }

    /* read zone list */
    zonelist_start = read_zonelist(zonelist_file);

    /* foreach zone, do a single axfr request */
    /* [TODO] daemonize */
    /* [TODO] listen to NOTIFY messages */
    /* [TODO] respect the EXPIRE value? */
    zonelist = zonelist_start;
    while (zonelist != NULL) {
        /* get latest serial */
        fd = fopen(zonelist->input_file, "r");
        if (!fd) {
            serial = 0;
        } else {
            serial = lookup_serial(fd);
        }

        if (zonelist->axfr_config && strlen(zonelist->axfr_config) > 0) {
            /* get tsig info */
            c = read_axfr_config(zonelist);
            /* send the request */
            if (zonelist->server_name && strlen(zonelist->server_name) > 0) {
                fprintf(stderr, "nsd-xfer -s %u [-T <%s:%s:%s>] -z %s -f %s%s %s\n",
                    serial, zonelist->tsig_name, zonelist->tsig_algo, zonelist->tsig_secret,
                    zonelist->name,  axfr_dir, zonelist->name, zonelist->server_name);
            }
        }
        /* next */
        zonelist = zonelist->next;
    }

    free_zonelist(zonelist);
    return 0;
}
