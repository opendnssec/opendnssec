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
 * Config.
 */
typedef struct config_struct config_type;
struct config_struct
{
    char* server_name;
    char* tsig_name;
    char* tsig_algo;
    char* tsig_secret;
    int use_tsig;
};

/**
 * Zone list.
 */
typedef struct zonelist_struct zonelist_type;
struct zonelist_struct
{
    char* name;
    char* input_file;
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

static config_type*
new_config(void)
{
    config_type* cfg = (config_type*) malloc(sizeof(config_type));
    cfg->server_name = NULL;
    cfg->tsig_name = NULL;
    cfg->tsig_algo = NULL;
    cfg->tsig_secret = NULL;
    return cfg;
}

static void
free_config(config_type* cfg)
{
    if (cfg) {
        if (cfg->tsig_name)   free((void*) cfg->tsig_name);
        if (cfg->tsig_algo)   free((void*) cfg->tsig_algo);
        if (cfg->tsig_secret) free((void*) cfg->tsig_secret);
        if (cfg->server_name) free((void*) cfg->server_name);
        free((void*) cfg);
    }
}

static zonelist_type*
new_zone(char* zone_name, char* input_file)
{
    zonelist_type* zlt = (zonelist_type*) malloc(sizeof(zonelist_type));
    zlt->name = strdup(zone_name);
    zlt->input_file = strdup(input_file);
    zlt->next = NULL;
    return zlt;
}

static void
free_zonelist(zonelist_type* zlt)
{
    if (zlt) {
        free_zonelist(zlt->next);
        free((void*) zlt->name);
        free((void*) zlt->input_file);
        free((void*) zlt);
    }
}

static int
read_axfr_config(const char* filename, config_type* cfg)
{
    int ret;
    int use_tsig = 0;
    char* tag_name, *tsig_name, *tsig_algo, *tsig_secret, *server_name;

    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlChar *tsig_expr = (unsigned char*) "//ZoneFetch/Default/TSIG";
    xmlChar *tsig_name_expr = (unsigned char*) "//ZoneFetch/Default/TSIG/Name";
    xmlChar *tsig_algo_expr = (unsigned char*) "//ZoneFetch/Default/TSIG/Algorithm";
    xmlChar *tsig_secret_expr = (unsigned char*) "//ZoneFetch/Default/TSIG/Secret";
    xmlChar *server_expr = (unsigned char*) "//ZoneFetch/Default/Address";

    /* In case zonelist is huge use the XmlTextReader API so that we don't hold the whole file in memory */
    reader = xmlNewTextReaderFilename(filename);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            tag_name = (char*) xmlTextReaderLocalName(reader);
            /* Found <Zone> */
            if (strncmp(tag_name, "ZoneFetch", 8) == 0 &&
                xmlTextReaderNodeType(reader) == 1) {

                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                doc = xmlTextReaderCurrentDoc(reader);
                if (doc == NULL) {
                    fprintf(stderr, "zone_fetcher: can not read config file %s\n", filename);
                    exit(EXIT_FAILURE);
                }
                xpathCtx = xmlXPathNewContext(doc);
                if (xpathCtx == NULL) {
                    fprintf(stderr, "zone_fetcher: can not create XPath context for %s\n",
                        filename);
                    exit(EXIT_FAILURE);
                }
                /* Extract the master server address */
                xpathObj = xmlXPathEvalExpression(server_expr, xpathCtx);
                if (xpathObj == NULL) {
                    fprintf(stderr, "zone_fetcher: can not locate master server(s) in %s\n",
                        filename);
                    exit(EXIT_FAILURE);
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
                        fprintf(stderr, "zone_fetcher: can not locate TSIG name in %s\n",
                            filename);
                        exit(EXIT_FAILURE);
                    }
                    tsig_name = (char*) xmlXPathCastToString(xpathObj);

                    xpathObj = xmlXPathEvalExpression(tsig_algo_expr, xpathCtx);
                    if (xpathObj == NULL) {
                        fprintf(stderr, "zone_fetcher: can not locate TSIG algorithm in %s\n",
                            filename);
                        exit(EXIT_FAILURE);
                    }
                    tsig_algo = (char*) xmlXPathCastToString(xpathObj);

                    xpathObj = xmlXPathEvalExpression(tsig_secret_expr, xpathCtx);
                    if (xpathObj == NULL) {
                        fprintf(stderr, "zone_fetcher: can not locate TSIG secret in %s\n",
                            filename);
                        exit(EXIT_FAILURE);
                    }
                    tsig_secret = (char*) xmlXPathCastToString(xpathObj);

                    cfg->tsig_name = strdup(tsig_name);
                    cfg->tsig_algo = strdup(tsig_algo);
                    cfg->tsig_secret = strdup(tsig_secret);
                    free(tsig_name);
                    free(tsig_algo);
                    free(tsig_secret);
                }

                cfg->server_name = strdup(server_name);
                free(server_name);
            }

            /* Read the next line */
            ret = xmlTextReaderRead(reader);
            free(tag_name);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            fprintf(stderr, "zone_fetcher: failed to parse config file %s\n", filename);
            exit(EXIT_FAILURE);
        }
    } else {
        fprintf(stderr, "zone_fetcher: unable to open config file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    cfg->use_tsig = use_tsig;
    return 0;
}

static zonelist_type*
read_zonelist(const char* filename)
{
    zonelist_type* zonelist = NULL, *zonelist_start = NULL;
    char* tag_name, *zone_name, *input_file;
    int ret;

    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlChar *name_expr = (unsigned char*) "name";
    xmlChar *adapter_expr = (unsigned char*) "//Zone/Adapters/Input/File";

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
                    fprintf(stderr, "zone_fetcher: can not read zone \"%s\"; skipping\n", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                xpathCtx = xmlXPathNewContext(doc);
                if (xpathCtx == NULL) {
                    fprintf(stderr, "zone_fetcher: can not create XPath context for \"%s\"; skipping zone\n", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                /* Extract the Input File Adapter filename */
                xpathObj = xmlXPathEvalExpression(adapter_expr, xpathCtx);
                if (xpathObj == NULL) {
                    fprintf(stderr, "zone_fetcher: unable to evaluate xpath expression: %s; skipping zone\n", adapter_expr);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                input_file = (char*) xmlXPathCastToString(xpathObj);

                if (zonelist == NULL) {
                    zonelist = new_zone(zone_name, input_file);
                    zonelist_start = zonelist;
                }
                else {
                    zonelist->next = new_zone(zone_name, input_file);
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
            exit(EXIT_FAILURE);
        }
    } else {
        fprintf(stderr, "zone_fetcher: unable to open zonelist %s\n", filename);
        exit(EXIT_FAILURE);
    }
    return zonelist_start;
}

int
main(int argc, char **argv)
{
    const char* zonelist_file = NULL, *config_file = NULL;
    zonelist_type* zonelist = NULL, *zonelist_start = NULL;
    config_type* config = NULL;
    uint32_t serial = 0;
    FILE* fd;
    int c;

    while ((c = getopt(argc, argv, "c:hz:")) != -1) {
        switch (c) {
        case 'c':
            config_file = optarg;
            break;
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

    /* read transfer configuration */
    config = new_config();
    c = read_axfr_config(config_file, config);

    /* [TODO] daemonize */
    /* [TODO] listen to NOTIFY messages */
    /* [TODO] respect the EXPIRE value? */

    if (config->server_name && strlen(config->server_name) > 0) {
        /* foreach zone, do a single axfr request */
        zonelist = zonelist_start;
        while (zonelist != NULL) {
            /* get latest serial */
            fd = fopen(zonelist->input_file, "r");
            if (!fd) {
                serial = 0;
            } else {
                serial = lookup_serial(fd);
            }
            /* send the request */
            if (config->use_tsig) {
                fprintf(stderr, "nsd-xfer -s %u [-T <%s:%s:%s>] -z %s -f %s.axfr %s\n",
                    serial, config->tsig_name, config->tsig_algo, config->tsig_secret,
                    zonelist->name, zonelist->input_file, config->server_name);
            } else {
                fprintf(stderr, "nsd-xfer -s %u -z %s -f %s.axfr %s\n",
                    serial, zonelist->name, zonelist->input_file, config->server_name);
            }
            /* next */
            zonelist = zonelist->next;
        }
    }

    free_config(config);
    free_zonelist(zonelist);
    return 0;
}
