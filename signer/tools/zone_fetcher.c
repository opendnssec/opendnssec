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
#include "logging.h"
#include "util.h"
#include "zone_fetcher.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <syslog.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlsave.h>

static int sig_quit = 0;

static void
usage(FILE *out)
{
    fprintf(out, "Usage: zone_fetcher [OPTIONS]\n");
    fprintf(out, "Transfers zones from their master.\n");
    fprintf(out, "Options:\n");
    fprintf(out, "-c <file>\t\tThe zonefetch.xml <file>\n");
    fprintf(out, "-d\t\tRun as daemon\n");
    fprintf(out, "-f <facility>\t\tLog with <facility>\n");
    fprintf(out, "-h\t\tShow this help\n");
    fprintf(out, "-h\t\tShow this help\n");
    fprintf(out, "-z <file>\tThe zonelist.xml <file>\n");
}

static zonelist_type*
new_zone(char* zone_name, char* input_file)
{
    zonelist_type* zlt = (zonelist_type*) malloc(sizeof(zonelist_type));
    zlt->name = strdup(zone_name);
    zlt->dname = ldns_dname_new_frm_str(zlt->name);
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
        ldns_rdf_deep_free(zlt->dname);
        free((void*) zlt->input_file);
        free((void*) zlt);
    }
}

static serverlist_type*
new_server(char* ipv4, char* ipv6, char* port)
{
    serverlist_type* slt = (serverlist_type*) malloc(sizeof(serverlist_type));
    slt->family = AF_UNSPEC;
    if (ipv4) {
        slt->family = AF_INET;
        slt->ipaddr = strdup(ipv4);
    }
    else if (ipv6) {
        slt->family = AF_INET6;
        slt->ipaddr = strdup(ipv6);
    }
    if (port)
        slt->port = strdup(port);
    else
        slt->port = NULL;
    memset(&slt->addr, 0, sizeof(union acl_addr_storage));

    if (slt->family == AF_INET6 && strlen(slt->ipaddr) > 0) {
        if (inet_pton(slt->family, slt->ipaddr, &slt->addr.addr6) != 1) {
            log_msg(LOG_ERR, "zone fetcher encountered bad ip address '%s'",
                slt->ipaddr);
        }
    }
    else if (slt->family == AF_INET && strlen(slt->ipaddr) > 0) {
        if (inet_pton(slt->family, slt->ipaddr, &slt->addr.addr) != 1) {
            log_msg(LOG_ERR, "zone fetcher encountered bad ip address '%s'",
                slt->ipaddr);
        }
    }

    slt->next = NULL;
    return slt;
}

static void
free_serverlist(serverlist_type* slt)
{
    if (slt) {
        free_serverlist(slt->next);
        if (slt->port)   free((void*) slt->port);
        if (slt->ipaddr) free((void*) slt->ipaddr);
        free((void*) slt);
    }
}

static config_type*
new_config(void)
{
    config_type* cfg = (config_type*) malloc(sizeof(config_type)); /* not freed */
    cfg->use_tsig = 0;
    cfg->pidfile = NULL;
    cfg->tsig_name = NULL;
    cfg->tsig_algo = NULL;
    cfg->tsig_secret = NULL;
    cfg->serverlist = NULL;
    cfg->notifylist = NULL;
    cfg->zonelist = NULL;
    return cfg;
}

static void
free_config(config_type* cfg)
{
    if (cfg) {
        if (cfg->tsig_name)   free((void*) cfg->tsig_name);
        if (cfg->tsig_algo)   free((void*) cfg->tsig_algo);
        if (cfg->tsig_secret) free((void*) cfg->tsig_secret);
        if (cfg->pidfile)     free((void*) cfg->pidfile);
        free_zonelist(cfg->zonelist);
        free_serverlist(cfg->serverlist);
        free_serverlist(cfg->notifylist);
        ldns_resolver_free(cfg->xfrd);
        free((void*) cfg);
    }
}

static int
read_axfr_config(const char* filename, config_type* cfg)
{
    int ret, i, use_tsig = 0;
    char* tag_name, *tsig_name, *tsig_algo, *tsig_secret, *ipv4, *ipv6, *port;
    serverlist_type* serverlist = NULL;
    serverlist_type* notifylist = NULL;

    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode *curNode = NULL;
    xmlChar *tsig_expr = (unsigned char*) "//ZoneFetch/Default/TSIG";
    xmlChar *tsig_name_expr = (unsigned char*) "//ZoneFetch/Default/TSIG/Name";
    xmlChar *tsig_algo_expr = (unsigned char*) "//ZoneFetch/Default/TSIG/Algorithm";
    xmlChar *tsig_secret_expr = (unsigned char*) "//ZoneFetch/Default/TSIG/Secret";
    xmlChar *server_expr = (unsigned char*) "//ZoneFetch/Default/RequestTransfer";
    xmlChar *notify_expr = (unsigned char*) "//ZoneFetch/NotifyListen";

    if (filename == NULL) {
        log_msg(LOG_CRIT, "no zone fetcher configfile provided");
        exit(EXIT_FAILURE);
    }

    /* In case zonelist is huge use the XmlTextReader API so that we don't
     * hold the whole file in memory */
    reader = xmlNewTextReaderFilename(filename); /* not properly freed */
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            tag_name = (char*) xmlTextReaderLocalName(reader);
            /* Found <ZoneFetch> */
            if (strncmp(tag_name, "ZoneFetch", 8) == 0 &&
                xmlTextReaderNodeType(reader) == 1) {

                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                doc = xmlTextReaderCurrentDoc(reader);
                if (doc == NULL) {
                    log_msg(LOG_ERR, "can not read zone fetcher configfile "
                        "%s", filename);
                    exit(EXIT_FAILURE);
                }
                xpathCtx = xmlXPathNewContext(doc);
                if (xpathCtx == NULL) {
                    log_msg(LOG_CRIT, "zone fetcher can not create XPath "
                        "context for %s", filename);
                    exit(EXIT_FAILURE);
                }

                /* Extract the master server address */
                xpathObj = xmlXPathEvalExpression(server_expr, xpathCtx);
                if (xpathObj == NULL) {
                    log_msg(LOG_CRIT, "zone fetcher can not locate master "
                        "server(s) in %s", filename);
                    exit(EXIT_FAILURE);
                }
                if (xpathObj->nodesetval) {
                    for (i=0; i < xpathObj->nodesetval->nodeNr; i++) {
                        ipv4 = NULL;
                        ipv6 = NULL;
                        port = NULL;
                        curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
                        while (curNode) {
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"IPv4"))
                                ipv4 = (char *) xmlNodeGetContent(curNode);
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"IPv6"))
                                ipv6 = (char *) xmlNodeGetContent(curNode);
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"Port"))
                                port = (char *) xmlNodeGetContent(curNode);
                            curNode = curNode->next;
                       }
                       if (ipv4 || ipv6) {
                           if (serverlist == NULL) {
                               serverlist = new_server(ipv4, ipv6, port); /* not freed */
                               cfg->serverlist = serverlist;
                           }
                           else {
                               serverlist->next = new_server(ipv4, ipv6, port); /* not freed */
                               serverlist = serverlist->next;
                           }
                       }

                       if (ipv4) free((void*) ipv4);
                       if (ipv6) free((void*) ipv6);
                       if (port) free((void*) port);
                    }
                }
                xmlXPathFreeObject(xpathObj);

                /* Extract the notify listen address */
                xpathObj = xmlXPathEvalExpression(notify_expr, xpathCtx);
                if (xpathObj != NULL && xpathObj->nodesetval) {
                    for (i=0; i < xpathObj->nodesetval->nodeNr; i++) {
                        ipv4 = NULL;
                        ipv6 = NULL;
                        port = NULL;
                        curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
                        while (curNode) {
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"IPv4"))
                                ipv4 = (char *) xmlNodeGetContent(curNode);
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"IPv6"))
                                ipv6 = (char *) xmlNodeGetContent(curNode);
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"Port"))
                                port = (char *) xmlNodeGetContent(curNode);
                            curNode = curNode->next;
                       }
                       if (ipv4 || ipv6 || port) {
                           if (!ipv4 && !ipv6) {
                               if (notifylist == NULL) {
                                   notifylist = new_server("", NULL, port);
                                   cfg->notifylist = notifylist;

                                   notifylist->next = new_server(NULL, "", port);
                                   notifylist = notifylist->next;
                               }
                               else {
                                   notifylist->next = new_server("", NULL, port);
                                   notifylist = notifylist->next;

                                   notifylist->next = new_server(NULL, "", port);
                                   notifylist = notifylist->next;
                               }
                           }
                           else if (notifylist == NULL) {
                               notifylist = new_server(ipv4, ipv6, port);
                               cfg->notifylist = notifylist;
                           }
                           else {
                               notifylist->next = new_server(ipv4, ipv6, port);
                               notifylist = notifylist->next;
                           }
                       }

                       if (ipv4) free((void*) ipv4);
                       if (ipv6) free((void*) ipv6);
                       if (port) free((void*) port);
                    }
                    xmlXPathFreeObject(xpathObj);
                }

                /* Extract the tsig credentials */
                xpathObj = xmlXPathEvalExpression(tsig_expr, xpathCtx);
                if (xpathObj != NULL) {
                    use_tsig = 1;
                    xmlXPathFreeObject(xpathObj);
                }
                if (use_tsig) {
                    xpathObj = xmlXPathEvalExpression(tsig_name_expr, xpathCtx);
                    if (xpathObj == NULL) {
                        log_msg(LOG_ERR, "zone fetcher can not locate TSIG "
                            " name in %s", filename);
                        exit(EXIT_FAILURE);
                    }
                    tsig_name = (char*) xmlXPathCastToString(xpathObj);
                    xmlXPathFreeObject(xpathObj);

                    xpathObj = xmlXPathEvalExpression(tsig_algo_expr, xpathCtx);
                    if (xpathObj == NULL) {
                        log_msg(LOG_ERR, "zone fetcher can not locate TSIG "
                            "algorithm in %s", filename);
                        exit(EXIT_FAILURE);
                    }
                    tsig_algo = (char*) xmlXPathCastToString(xpathObj);
                    xmlXPathFreeObject(xpathObj);

                    xpathObj = xmlXPathEvalExpression(tsig_secret_expr, xpathCtx);
                    if (xpathObj == NULL) {
                        log_msg(LOG_ERR, "zone fetcher can not locate TSIG "
                            "secret in %s", filename);
                        exit(EXIT_FAILURE);
                    }
                    tsig_secret = (char*) xmlXPathCastToString(xpathObj);
                    xmlXPathFreeObject(xpathObj);

                    cfg->tsig_name = strdup(tsig_name);
                    cfg->tsig_algo = strdup(tsig_algo);
                    cfg->tsig_secret = strdup(tsig_secret);
                    free((void*) tsig_name);
                    free((void*) tsig_algo);
                    free((void*) tsig_secret);
                }

                xmlXPathFreeContext(xpathCtx);
            }

            /* Read the next line */
            ret = xmlTextReaderRead(reader);
            free((void*) tag_name);
        }
        xmlFreeTextReader(reader);
        xmlFreeDoc(doc);
        if (ret != 0) {
            log_msg(LOG_ERR, "zone fetcher failed to parse config file %s",
                filename);
            exit(EXIT_FAILURE);
        }
    } else {
        log_msg(LOG_ERR, "zone fetcher was unable to open config file %s",
            filename);
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

    if (filename == NULL) {
        log_msg(LOG_CRIT, "no zonelist provided for zone fetcher");
        exit(EXIT_FAILURE);
    }

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
                    log_msg(LOG_ERR, "zone fetcher failed to extract zone "
                        "name from %s", filename);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                doc = xmlTextReaderCurrentDoc(reader);
                if (doc == NULL) {
                    log_msg(LOG_ERR, "zone fetcher could not read zone "
                        "\"%s\"; skipping", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                xpathCtx = xmlXPathNewContext(doc);
                if (xpathCtx == NULL) {
                    log_msg(LOG_ERR, "zone fetcher can not create XPath "
                        "context for \"%s\"; skipping zone", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* Extract the Input File Adapter filename */
                xpathObj = xmlXPathEvalExpression(adapter_expr, xpathCtx);
                if (xpathObj == NULL) {
                    log_msg(LOG_ERR, "zone fetcher was unable to evaluate "
                        "xpath expression: %s; skipping zone", adapter_expr);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                input_file = (char*) xmlXPathCastToString(xpathObj);
                xmlXPathFreeObject(xpathObj);

                if (zonelist == NULL) {
                    zonelist = new_zone(zone_name, input_file); /* not freed */
                    zonelist_start = zonelist;
                }
                else {
                    zonelist->next = new_zone(zone_name, input_file);
                    zonelist = zonelist->next;
                }
				free((void*) zone_name);
				free((void*) input_file);

                xmlXPathFreeContext(xpathCtx);
            }

            /* Read the next line */
            ret = xmlTextReaderRead(reader);
            free((void*) tag_name);
        }
        xmlFreeTextReader(reader);
        xmlFreeDoc(doc);
        if (ret != 0) {
            log_msg(LOG_ERR, "zone fetcher failed to parse zonelist %s",
                filename);
            exit(EXIT_FAILURE);
        }
    } else {
        log_msg(LOG_ERR, "zone fetcher was unable to open zonelist %s",
            filename);
        exit(EXIT_FAILURE);
    }

    return zonelist_start;
}

/** Write pidfile */
static int
writepid(char* pidfile, pid_t pid)
{
    FILE * fd;
    char pidbuf[32];
    size_t result = 0, size = 0;

    snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long) pid);
    if ((fd = fopen(pidfile, "w")) ==  NULL ) {
        log_msg(LOG_ERR, "zone fetcher could not open pidfile %s for "
            "writing: %s", pidfile, strerror(errno));
        return -1;
    }
    size = strlen(pidbuf);
    if (size == 0)
        result = 1;
    result = fwrite((const void*) pidbuf, 1, size, fd);
    if (result == 0) {
        log_msg(LOG_ERR, "zone fetcher failed to write to pidfile: %s",
            strerror(errno));
    } else if (result < size) {
        log_msg(LOG_ERR, "zone fetcher had short write to pidfile "
            "(disk full?)");
        result = 0;
    } else
        result = 1;
    if (!result) {
        log_msg(LOG_CRIT, "zone fetcher could not write pidfile %s: %s",
            pidfile, strerror(errno));
        fclose(fd);
        return -1;
    }
    fclose(fd);
    return 0;
}

/** Signal handling. */
static void
sig_handler(int sig)
{
    switch (sig)
    {
        case SIGTERM:
        case SIGHUP:
            sig_quit = 1;
            break;
        default:
            break;
    }
    return;
}

static pid_t
setup_daemon(config_type* config)
{
    pid_t pid = -1;
    struct sigaction action;

    switch ((pid = fork()))
    {
        case 0: /* child */
            break;
        case -1: /* error */
            log_msg(LOG_CRIT, "zone fetche fork() failed: %s",
                strerror(errno));
            exit(EXIT_FAILURE);
        default: /* parent is done */
            exit(0);
    }
    if (setsid() == -1)
    {
        log_msg(LOG_CRIT, "zone fetcher setsid() failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    /* setup signal handing */
    action.sa_handler = sig_handler;
    sigfillset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGHUP, &action, NULL);

    pid = getpid();
    if (writepid(config->pidfile, pid) == -1)
        exit(EXIT_FAILURE);

    return pid;
}

static int
init_sockets(sockets_type* sockets, serverlist_type* list)
{
    int r, ip6_support = 1, on = 0;
    size_t i;
    struct addrinfo hints[MAX_INTERFACES];
    serverlist_type* walk = list;
    const char* node = NULL;
    const char* port = NULL;
#if defined(SO_REUSEADDR) || defined(IPV6_V6ONLY)
    on = 1;
#endif

    for (i = 0; i < MAX_INTERFACES; i++) {
        memset(&hints[i], 0, sizeof(hints[i]));
        hints[i].ai_family = AF_INET6;
        hints[i].ai_flags = AI_PASSIVE;
        sockets->udp[i].s = -1;
        sockets->tcp[i].s = -1;
    }

    /* if no NotifyListen was provided, we create the default IPv4/IPv6
     * address info structures */
    if (!walk) {
#ifdef  IPV6_V6ONLY
        hints[0].ai_family = AF_INET6;
        hints[1].ai_family = AF_INET;
        walk = new_server(NULL, "", NULL);
        walk->next = new_server("", NULL, NULL);
#else   /* !IPV6_V6ONLY */
        hints[0].ai_family = AF_INET6;
        walk = new_server(NULL, "", NULL);
#endif  /* IPV6_V6ONLY */
    }

    i = 0;
    while (walk) {
#ifndef IPV6_V6ONLY
        hints[i].ai_family = walk->family;
#endif  /* IPV6_V6ONLY */
        node = strlen(walk->ipaddr) > 0 ? walk->ipaddr : NULL;
        port = walk->port ? walk->port : DNS_PORT_STRING;
        if (node != NULL)
            hints[i].ai_flags |= AI_NUMERICHOST;
        /* UDP */
        hints[i].ai_socktype = SOCK_DGRAM;
        /* getaddrinfo */
        if ((r = getaddrinfo(node, port, &hints[i],
            &(sockets->udp[i].addr))) != 0) {
            log_msg(LOG_ERR, "zone fetcher cannot parse address: getaddrinfo: "
                "%s %s", gai_strerror(r), r==EAI_SYSTEM?strerror(errno):"");
        }
        /* socket */
        if ((sockets->udp[i].s = socket(walk->family, SOCK_DGRAM, 0)) == -1)
        {
            if (walk->family == AF_INET6 && errno == EAFNOSUPPORT)
            {
                log_msg(LOG_ERR, "zone fetcher fallback to UDP4, no IPv6: "
                    " not supported");
                ip6_support = 0;
            }
            else {
                log_msg(LOG_CRIT, "zone fetcher can't create UDP socket: %s",
                    strerror(errno));
                return -1;
            }
        }

        if (walk->family != AF_INET6) {
            if (fcntl(sockets->udp[i].s, F_SETFL,
                O_NONBLOCK) == -1) {
                log_msg(LOG_ERR, "zone fetcher cannot fcntl "
                "UDP: %s", strerror(errno));
            }
            if (bind(sockets->udp[i].s,
                (struct sockaddr *) sockets->udp[i].addr->ai_addr,
                sockets->udp[i].addr->ai_addrlen) != 0)
            {
                log_msg(LOG_CRIT, "zone fetcher can't bind udp/ipv4 socket: %s",
                    strerror(errno));
                return -1;
            }
        }
        else if (ip6_support) {
#ifdef IPV6_V6ONLY
            if (setsockopt(sockets->udp[i].s, IPPROTO_IPV6, IPV6_V6ONLY, &on,
                sizeof(on)) < 0)
            {
                log_msg(LOG_CRIT, "zone fetcher setsockopt(..., IPV6_V6ONLY, "
                "...) failed: %s", strerror(errno));
                return -1;
            }
#endif /* IPV6_V6ONLY */
            if (fcntl(sockets->udp[i].s, F_SETFL, O_NONBLOCK) == -1) {
                log_msg(LOG_ERR, "zone fetcher cannot fcntl UDP: %s",
                    strerror(errno));
            }
            if (bind(sockets->udp[i].s,
                (struct sockaddr *) sockets->udp[i].addr->ai_addr,
                sockets->udp[i].addr->ai_addrlen) != 0) {
                log_msg(LOG_CRIT, "zone fetcher can't bind UDP socket: %s",
                    strerror(errno));
                return -1;
            }
        }

        /* TCP */
        hints[i].ai_socktype = SOCK_STREAM;
        /* getaddrinfo */
        if ((r = getaddrinfo(node, port, &hints[i],
            &(sockets->tcp[i].addr))) != 0) {
            log_msg(LOG_ERR, "zone fetcher cannot parse address: getaddrinfo: "
                "%s %s", gai_strerror(r), r==EAI_SYSTEM?strerror(errno):"");
        }
        /* socket */
        if ((sockets->tcp[i].s = socket(walk->family, SOCK_STREAM, 0)) == -1)
        {
            if (walk->family == AF_INET6 && errno == EAFNOSUPPORT)
            {
                log_msg(LOG_ERR, "zone fetcher fallback to TCP4, no IPv6: "
                    " not supported");
                ip6_support = 0;
            }
            else {
            log_msg(LOG_CRIT, "zone fetcher can't create TCP socket: %s",
                strerror(errno));
            return -1;
            }
        }
        /* setsockopt */
        if (walk->family != AF_INET6) {
            if (setsockopt(sockets->tcp[i].s, SOL_SOCKET, SO_REUSEADDR, &on,
                sizeof(on)) < 0) {
                log_msg(LOG_ERR, "zone fetcher setsockopt(..., SO_REUSEADDR, ...) "
                    "failed: %s", strerror(errno));
            }
            /* fcntl */
            if (fcntl(sockets->tcp[i].s, F_SETFL, O_NONBLOCK) == -1) {
                log_msg(LOG_ERR, "zone fetcher cannot fcntl TCP: %s",
                    strerror(errno));
            }
            /* bind */
            if (bind(sockets->tcp[i].s,
                (struct sockaddr *) sockets->tcp[i].addr->ai_addr,
                sockets->tcp[i].addr->ai_addrlen) != 0) {
                log_msg(LOG_CRIT, "zone fetcher can't bind TCP socket: %s",
                    strerror(errno));
                return -1;
            }
            /* listen */
            if (listen(sockets->tcp[i].s, 5) == -1) {
                log_msg(LOG_CRIT, "zone fetcher can't listen to TCP socket: "
                    "%s", strerror(errno));
                return -1;
            }
        } else if (ip6_support) {
            /* setsockopt */
            if (sockets->tcp[i].addr->ai_family == AF_INET6 && ip6_support) {
#ifdef IPV6_V6ONLY
                if (setsockopt(sockets->tcp[i].s, IPPROTO_IPV6, IPV6_V6ONLY, &on,
                    sizeof(on)) < 0)
                {
                    log_msg(LOG_CRIT, "zone fetcher setsockopt(..., IPV6_V6ONLY, "
                        "...) failed: %s", strerror(errno));
                    return -1;
                }
#endif /* IPV6_V6ONLY */
            }
            if (setsockopt(sockets->tcp[i].s, SOL_SOCKET, SO_REUSEADDR, &on,
                sizeof(on)) < 0) {
                log_msg(LOG_ERR, "zone fetcher setsockopt(..., SO_REUSEADDR, ...) "
                    "failed: %s", strerror(errno));
            }
            /* fcntl */
            if (fcntl(sockets->tcp[i].s, F_SETFL, O_NONBLOCK) == -1) {
                log_msg(LOG_ERR, "zone fetcher cannot fcntl TCP: %s",
                    strerror(errno));
            }
            /* bind */
            if (bind(sockets->tcp[i].s,
                (struct sockaddr *) sockets->tcp[i].addr->ai_addr,
                sockets->tcp[i].addr->ai_addrlen) != 0) {
                log_msg(LOG_CRIT, "zone fetcher can't bind TCP socket: %s",
                    strerror(errno));
                return -1;
            }
            /* listen */
            if (listen(sockets->tcp[i].s, 5) == -1) {
                log_msg(LOG_CRIT, "zone fetcher can't listen to TCP socket: "
                    "%s", strerror(errno));
                return -1;
            }
        }

        walk = walk->next;
        i++;
    }

    return 0;
}

static void
free_sockets(sockets_type* sockets)
{
    size_t i = 0;

    for (i=0; i < MAX_INTERFACES; i++) {
        if (sockets->udp[i].s != -1) {
            close(sockets->udp[i].s);
            free((void*)sockets->udp[i].addr);
        }
        if (sockets->tcp[i].s != -1) {
            close(sockets->tcp[i].s);
            free((void*)sockets->tcp[i].addr);
        }
    }
}

static void
odd_xfer(zonelist_type* zone, uint32_t serial, config_type* config)
{
    ldns_status status = LDNS_STATUS_OK;
    ldns_rr* axfr_rr = NULL, *soa_rr = NULL;
    uint32_t new_serial = 0;
    ldns_pkt* qpkt = NULL, *apkt;
    FILE* fd = NULL;
    char* lock_ext = ".axfr.lock";
    char* axfr_ext = ".axfr";
    char* axfr_file;
    int soa_seen = 0;
    size_t strlength = 0;

    /* soa serial query */
    qpkt = ldns_pkt_query_new(ldns_rdf_clone(zone->dname),
        LDNS_RR_TYPE_SOA, LDNS_RR_CLASS_IN, LDNS_RD);
    if (!qpkt) {
        log_msg(LOG_ERR, "zone fetcher failed to create SOA query. "
            "Aborting AXFR");
        return;
    }
    status = ldns_resolver_send_pkt(&apkt, config->xfrd, qpkt);
    if (status != LDNS_STATUS_OK) {
        log_msg(LOG_ERR, "zone fetcher failed to send SOA query: %s",
            ldns_get_errorstr_by_id(status));
        return;
    }
    ldns_pkt_free(qpkt);
    if (ldns_pkt_ancount(apkt) == 1) {
        soa_rr = ldns_rr_list_rr(ldns_pkt_answer(apkt), 0);
        new_serial = ldns_rdf2native_int32(ldns_rr_rdf(soa_rr, 2));
        ldns_pkt_free(apkt);
    }
    else {
        log_msg(LOG_ERR, "zone fetcher saw SOA response with ANCOUNT != 1"
            "Aborting AXFR");
        /* retry? */
        ldns_pkt_free(apkt);
        return;
    }

    if (serial < new_serial) {
        if (zone && zone->input_file) {
            strlength = strlen(zone->input_file) + strlen(lock_ext);
            axfr_file = (char*) malloc(sizeof(char) * (strlength + 1));
            if (axfr_file) {
                axfr_file = strcpy(axfr_file, zone->input_file);
                axfr_file = strcat(axfr_file, lock_ext);
                fd = fopen(axfr_file, "w");
                free((void*)axfr_file);
            }
        }
        if (!fd) {
            log_msg(LOG_ERR, "zone fetcher cannot store AXFR to file %s",
                axfr_file);
            return;
        }

        status = ldns_axfr_start(config->xfrd, zone->dname, LDNS_RR_CLASS_IN);
        if (status != LDNS_STATUS_OK) {
            if (errno != EINPROGRESS) {
                log_msg(LOG_ERR, "zone fetcher failed to start axfr: %s",
                    ldns_get_errorstr_by_id(status));
            }
        }

        axfr_rr = ldns_axfr_next(config->xfrd);
        if (!axfr_rr) {
            log_msg(LOG_ERR, "zone fetcher AXFR for %s failed", zone->name);
        }
        else {
            while (axfr_rr) {
                if (ldns_rr_get_type(axfr_rr) == LDNS_RR_TYPE_SOA) {
                    if (!soa_seen) {
                        soa_seen = 1;
                        ldns_rr_print(fd, axfr_rr);
                    }
                } else {
                    ldns_rr_print(fd, axfr_rr);
                }
                ldns_rr_free(axfr_rr);
                axfr_rr = ldns_axfr_next(config->xfrd);
            }
            log_msg(LOG_INFO, "zone fetcher transferred zone %s serial %u "
                "successfully", zone->name, new_serial);

            /* moving and kicking */
        }
        fclose(fd);
    }
    else {
        log_msg(LOG_INFO, "zone fetcher zone %s is already up to date, "
            "serial is %u", zone->name, serial);
    }
}

static ldns_resolver*
init_xfrd(config_type* config)
{
    serverlist_type* servers;
    ldns_rdf* ns = NULL;
    ldns_status status = LDNS_STATUS_OK;

    ldns_resolver* xfrd = ldns_resolver_new();
    if (config) {
        if (config->use_tsig) {
            ldns_resolver_set_tsig_keyname(xfrd, config->tsig_name);
            ldns_resolver_set_tsig_algorithm(xfrd, config->tsig_algo);
            ldns_resolver_set_tsig_keydata(xfrd, config->tsig_secret);
        }
        ldns_resolver_set_port(xfrd, atoi(DNS_PORT_STRING));
        ldns_resolver_set_recursive(xfrd, 0);

        servers = config->serverlist;
        while (servers) {
            if (servers->family == AF_INET6)
                ns = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, servers->ipaddr);
            else
                ns = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, servers->ipaddr);
            if (ns)
                status = ldns_resolver_push_nameserver(xfrd, ns);
            else {
                log_msg(LOG_ERR, "zone fetcher could not use %s for transfer "
                    "request: could not parse ip address", servers->ipaddr);
            }
            if (status != LDNS_STATUS_OK) {
                log_msg(LOG_ERR, "zone fetcher could not use %s for transfer "
                    "request: %s", servers->ipaddr,
                    ldns_get_errorstr_by_id(status));
            }
            servers = servers->next;
        }
    }
    return xfrd;
}

static void
send_udp(uint8_t* buf, size_t len, void* data)
{
    struct handle_udp_userdata *userdata = (struct handle_udp_userdata*)data;
    /* udp send reply */
    ssize_t nb;
    nb = sendto(userdata->udp_sock, buf, len, 0,
        (struct sockaddr*)&userdata->addr_him, userdata->hislen);
    if (nb == -1)
        log_msg(LOG_ERR, "zone fetcher sendto() failed: %s", strerror(errno));
    else if ((size_t)nb != len)
        log_msg(LOG_ERR, "zone fetcher sendto(): only sent %d of %d octets.",
            (int)nb, (int)len);
}

static void
write_n_bytes(int sock, uint8_t* buf, size_t sz)
{
    size_t count = 0;
    while(count < sz) {
        ssize_t nb = send(sock, buf+count, sz-count, 0);
        if(nb < 0) {
            log_msg(LOG_ERR, "zone fetcher send() failed: %s",
                strerror(errno));
            return;
        }
        count += nb;
    }
}

static void
send_tcp(uint8_t* buf, size_t len, void* data)
{
    struct handle_tcp_userdata *userdata = (struct handle_tcp_userdata*)data;
    uint16_t tcplen;
    /* tcp send reply */
    tcplen = htons(len);
    write_n_bytes(userdata->s, (uint8_t*)&tcplen, sizeof(tcplen));
    write_n_bytes(userdata->s, buf, len);
}

static void
handle_query(uint8_t* inbuf, ssize_t inlen,
    void (*sendfunc)(uint8_t*, size_t, void*),
    void* userdata, config_type* config)
{
    zonelist_type* zonelist = NULL;
    ldns_status status = LDNS_STATUS_OK;
    ldns_pkt *query_pkt = NULL;
    ldns_rr *query_rr = NULL;
    uint32_t serial = 0;
    char* owner_name = NULL;
    uint8_t *outbuf = NULL;
    size_t answer_size = 0;
    FILE* fd;

    /* packet parsing */
    status = ldns_wire2pkt(&query_pkt, inbuf, (size_t)inlen);
    if (status != LDNS_STATUS_OK) {
        log_msg(LOG_INFO, "zone fetcher got bad packet: %s",
            ldns_get_errorstr_by_id(status));
        return;
    }
    query_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);

    if (ldns_pkt_get_opcode(query_pkt) != LDNS_PACKET_NOTIFY ||
        ldns_pkt_get_rcode(query_pkt)  != LDNS_RCODE_NOERROR ||
        ldns_pkt_qr(query_pkt) ||
        !ldns_pkt_aa(query_pkt) ||
        ldns_pkt_tc(query_pkt) ||
        ldns_pkt_rd(query_pkt) ||
        ldns_pkt_ra(query_pkt) ||
        ldns_pkt_cd(query_pkt) ||
        ldns_pkt_ad(query_pkt) ||
        ldns_pkt_qdcount(query_pkt) != 1 ||
        ldns_pkt_nscount(query_pkt) != 0 ||
        ldns_pkt_arcount(query_pkt) != 0 ||
        ldns_rr_get_type(query_rr) != LDNS_RR_TYPE_SOA ||
        ldns_rr_get_class(query_rr) != LDNS_RR_CLASS_IN)
    {
        log_msg(LOG_INFO, "zone fetcher drop bad notify");
        return;
    }

    /* NOTIFY OK */
    log_msg(LOG_INFO, "zone fetcher received NOTIFY for zone %s",
        zonelist->name);
    ldns_pkt_set_qr(query_pkt, 1);
    status = ldns_pkt2wire(&outbuf, query_pkt, &answer_size);
    if (status != LDNS_STATUS_OK) {
        log_msg(LOG_ERR, "zone fetcher error creating notify response: %s",
            ldns_get_errorstr_by_id(status));
    }
    sendfunc(outbuf, answer_size, userdata);
    LDNS_FREE(outbuf);

    /* send AXFR request */
    if (config)
        zonelist = config->zonelist;
    while (zonelist) {
        if (ldns_dname_compare(ldns_rr_owner(query_rr), zonelist->dname) == 0)
        {
            /* get latest serial */
            fd = fopen(zonelist->input_file, "r");
            if (!fd) {
                serial = 0;
            } else {
                serial = lookup_serial(fd);
                fclose(fd);
            }
            odd_xfer(zonelist, serial, config);
            ldns_pkt_free(query_pkt);
            return;
        }
        /* next */
        zonelist = zonelist->next;
    }
    owner_name = ldns_rdf2str(ldns_rr_owner(query_rr));
    log_msg(LOG_NOTICE, "zone fetcher notify received for unknown zone: %s",
        owner_name);
    free((void*)owner_name);
    ldns_pkt_free(query_pkt);
}

static void
read_n_bytes(int sock, uint8_t* buf, size_t sz)
{
    size_t count = 0;
    while(count < sz) {
        ssize_t nb = recv(sock, buf+count, sz-count, 0);
        if(nb < 0) {
            log_msg(LOG_ERR, "zone fetcher recv() failed: %s",
                strerror(errno));
            return;
        }
        count += nb;
    }
}

static char*
addr2ip(struct sockaddr_storage addr, char* remote, size_t len)
{
    if (addr.ss_family == AF_INET6) {
        if (!inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr,
            remote, len)) {
            return NULL;
        }
    } else {
        if (!inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr,
            remote, len))
            return NULL;
    }

    return remote;
}

static int
acl_matches(struct sockaddr_storage* addr, config_type* config)
{
    serverlist_type* serverlist = NULL;

    if (config && config->serverlist) {
        serverlist = config->serverlist;
        while (serverlist) {
            if (serverlist->family == AF_INET6) {
                struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;
                if (serverlist->family == addr->ss_family &&
                    memcmp(&addr6->sin6_addr, &serverlist->addr.addr6,
                     sizeof(struct in6_addr)) == 0)
                {
                    return 1;
                }
            }
           else {
                struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
                if (serverlist->family == addr4->sin_family &&
                    memcmp(&addr4->sin_addr, &serverlist->addr.addr,
                     sizeof(struct in_addr)) == 0)
                {
                    return 1;
                }
            }

            serverlist = serverlist->next;
        }
    }
    return 0;
}

static void
handle_udp(int udp_sock, config_type* config)
{
    ssize_t nb;
    uint8_t inbuf[INBUF_SIZE];
    struct handle_udp_userdata userdata;
    char* remote;

    userdata.udp_sock = udp_sock;
    userdata.hislen = (socklen_t) sizeof(userdata.addr_him);
    nb = recvfrom(udp_sock, inbuf, INBUF_SIZE, 0,
        (struct sockaddr*) &userdata.addr_him, &userdata.hislen);
    if (nb < 1) {
        log_msg(LOG_ERR, "zone fetcher recvfrom() failed: %s",
            strerror(errno));
        return;
    }

    /* acl */
    if (!acl_matches(&userdata.addr_him, config)) {
        remote = (char*) malloc(sizeof(char)*userdata.hislen);
        log_msg(LOG_INFO, "zone fetcher refused message from "
            "unauthoritative source: %s",
            addr2ip(userdata.addr_him, remote,
            userdata.hislen));
        free((void*)remote);
        return;
    }
    handle_query(inbuf, nb, send_udp, &userdata, config);
}

static void
handle_tcp(int tcp_sock, config_type* config)
{
    int s;
    struct sockaddr_storage addr_him;
    socklen_t hislen;
    uint8_t inbuf[INBUF_SIZE];
    uint16_t tcplen;
    struct handle_tcp_userdata userdata;
    char* remote;

    /* accept */
    hislen = (socklen_t)sizeof(addr_him);
    if((s = accept(tcp_sock, (struct sockaddr*)&addr_him, &hislen)) < 0) {
        log_msg(LOG_ERR, "zone fetcher accept() failed: %s", strerror(errno));
        return;
    }
    userdata.s = s;

    /* tcp recv */
    read_n_bytes(s, (uint8_t*)&tcplen, sizeof(tcplen));
    tcplen = ntohs(tcplen);
    if(tcplen >= INBUF_SIZE) {
        log_msg(LOG_ERR, "zone fetcher query %d bytes too large, "
            "buffer %d bytes.", tcplen, INBUF_SIZE);
        close(s);
        return;
    }
    read_n_bytes(s, inbuf, tcplen);

    /* acl */
    if (!acl_matches(&addr_him, config)) {
        remote = (char*) malloc(sizeof(char)*hislen);
        log_msg(LOG_INFO, "zone fetcher refused message from "
            "unauthoritative source: %s",
            addr2ip(addr_him, remote, hislen));
        free((void*)remote);
        close(s);
        return;
    }
    handle_query(inbuf, (ssize_t) tcplen, send_tcp, &userdata, config);
    close(s);
}

static void
xfrd_ns(sockets_type* sockets, config_type* cfg)
{
    fd_set rset, wset, eset;
    struct timeval timeout;
    int count, maxfd = 0;
    size_t i;

    /* service */
    count = 0;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    while (1) {
        FD_ZERO(&rset);
        FD_ZERO(&wset);
        FD_ZERO(&eset);
        for (i=0; i < MAX_INTERFACES; i++) {
            if (sockets->udp[i].s != -1)
                FD_SET(sockets->udp[i].s, &rset);
            if (sockets->tcp[i].s != -1)
                FD_SET(sockets->tcp[i].s, &rset);
            if (sockets->udp[i].s > maxfd) maxfd = sockets->udp[i].s;
            if (sockets->tcp[i].s > maxfd) maxfd = sockets->tcp[i].s;
        }

        if (select(maxfd+1, &rset, &wset, &eset, NULL) < 0) {
            if (errno == EINTR)
                break;
            log_msg(LOG_ERR, "zone fetcher select(): %s", strerror(errno));
        }

        for (i=0; i < MAX_INTERFACES; i++) {
            if (sockets->udp[i].s != -1 && FD_ISSET(sockets->udp[i].s, &rset))
                handle_udp(sockets->udp[i].s, cfg);
            if (sockets->tcp[i].s != -1 && FD_ISSET(sockets->tcp[i].s, &rset))
                handle_tcp(sockets->tcp[i].s, cfg);
        }
    }
}

int
main(int argc, char **argv)
{
    const char* zonelist_file = NULL, *config_file = NULL;
    zonelist_type *zonelist = NULL;
    config_type* config = NULL;
    int c, run_as_daemon = 0;
    uint32_t serial = 0;
    pid_t pid = 0;
    FILE* fd;
    sockets_type sockets;
    int facility = LOG_DAEMON;

    while ((c = getopt(argc, argv, "c:df:hz:")) != -1) {
        switch (c) {
        case 'c':
            config_file = optarg;
            break;
        case 'd':
            run_as_daemon = 1;
            break;
        case 'h':
            usage(stdout);
            exit(EXIT_SUCCESS);
        case 'z':
            zonelist_file = optarg;
            break;
        default:
            exit(EXIT_FAILURE);
            break;
        }
    }

    log_open(facility, "OpenDNSSEC signer engine");

    if (argc > optind) {
        log_msg(LOG_CRIT, "zone fetcher error: extraneous arguments");
        exit(EXIT_FAILURE);
    }

    /* read transfer configuration */
    config = new_config();
    config->pidfile = strdup(PID_FILENAME_STRING); /* not freed */
    c = read_axfr_config(config_file, config);
    config->zonelist = read_zonelist(zonelist_file);
    config->xfrd = init_xfrd(config);

    log_msg(LOG_INFO, "zone fetcher started");


    /* foreach zone, do a single axfr request */
    zonelist = config->zonelist;
    while (zonelist != NULL) {
        /* get latest serial */
        fd = fopen(zonelist->input_file, "r");
        if (!fd) {
            serial = 0;
        } else {
            serial = lookup_serial(fd);
            fclose(fd);
        }
        /* send the request */
        odd_xfer(zonelist, serial, config);
        /* next */
        zonelist = zonelist->next;
    }

	if (run_as_daemon) {
        pid = setup_daemon(config);
        /* listen to NOTIFY messages */
        c = init_sockets(&sockets, config->notifylist);
        if (c == -1) {
            log_msg(LOG_CRIT, "zone fetcher failed to initialize sockets");
            exit(EXIT_FAILURE);
        }
        xfrd_ns(&sockets, config);

        if (unlink(config->pidfile) == -1) {
            log_msg(LOG_ERR, "unlink pidfile %s failed: %s", config->pidfile,
                strerror(errno));
        }
        free_sockets(&sockets);
    }

    /* done */
    log_msg(LOG_INFO, "zone fetcher done");
    free_config(config);
    log_close();
    return 0;
}

/* [TODO]:
 * - Hook into signer engine
 * - Store AXFR on disk
 * - PrivDrop
 * - fork it?
 */
