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
#include "zone_fetcher.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>

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
    fprintf(out, "-h\t\tShow this help\n");
    fprintf(out, "-h\t\tShow this help\n");
    fprintf(out, "-z <file>\tThe zonelist.xml <file>\n");
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

static serverlist_type*
new_server(char* ipv4, char* ipv6, char* port)
{
    serverlist_type* slt = (serverlist_type*) malloc(sizeof(serverlist_type));
    if (ipv4) {
        slt->family = AF_INET;
        slt->ipaddr = strdup(ipv4);
    }
    else if (ipv6) {
        slt->family = AF_INET6;
        slt->ipaddr = strdup(ipv6);
    }
    if (port)
        slt->port = atoi(port);
    else
        slt->port = atoi(DNS_PORT_STRING);
    slt->next = NULL;
    return slt;
}

static void
free_serverlist(serverlist_type* slt)
{
    if (slt) {
        free_serverlist(slt->next);
        free((void*) slt->ipaddr);
        free((void*) slt);
    }
}

static config_type*
new_config(void)
{
    config_type* cfg = (config_type*) malloc(sizeof(config_type));
    cfg->use_tsig = 0;
    cfg->pidfile = NULL;
    cfg->tsig_name = NULL;
    cfg->tsig_algo = NULL;
    cfg->tsig_secret = NULL;
    cfg->serverlist = NULL;
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
        free_serverlist(cfg->serverlist);
        free((void*) cfg);
    }
}

static int
read_axfr_config(const char* filename, config_type* cfg)
{
    int ret, i, use_tsig = 0;
    char* tag_name, *tsig_name, *tsig_algo, *tsig_secret, *pidfile, *ipv4, *ipv6, *port;
    serverlist_type* serverlist = NULL, *serverlist_start = NULL;

    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode *curNode = NULL;
    xmlChar *tsig_expr = (unsigned char*) "//ZoneFetch/Default/TSIG";
    xmlChar *tsig_name_expr = (unsigned char*) "//ZoneFetch/Default/TSIG/Name";
    xmlChar *tsig_algo_expr = (unsigned char*) "//ZoneFetch/Default/TSIG/Algorithm";
    xmlChar *tsig_secret_expr = (unsigned char*) "//ZoneFetch/Default/TSIG/Secret";
    xmlChar *server_expr = (unsigned char*) "//ZoneFetch/Default/Address";
    xmlChar *pidfile_expr = (unsigned char*) "//ZoneFetch/PidFile";

    if (filename == NULL) {
        fprintf(stderr, "zone_fetcher: no configfile provided\n");
        exit(EXIT_FAILURE);
    }

    /* In case zonelist is huge use the XmlTextReader API so that we don't hold the whole file in memory */
    reader = xmlNewTextReaderFilename(filename);
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
                    fprintf(stderr, "zone_fetcher: can not read config file %s\n", filename);
                    exit(EXIT_FAILURE);
                }
                xpathCtx = xmlXPathNewContext(doc);
                if (xpathCtx == NULL) {
                    fprintf(stderr, "zone_fetcher: can not create XPath context for %s\n",
                        filename);
                    exit(EXIT_FAILURE);
                }
                /* Extract the pid file */
                xpathObj = xmlXPathEvalExpression(pidfile_expr, xpathCtx);
                if (xpathObj != NULL)
                    pidfile = (char*) xmlXPathCastToString(xpathObj);

                /* Extract the master server address */
                xpathObj = xmlXPathEvalExpression(server_expr, xpathCtx);
                if (xpathObj == NULL) {
                    fprintf(stderr, "zone_fetcher: can not locate master server(s) in %s\n",
                        filename);
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
                               serverlist = new_server(ipv4, ipv6, port);
                               serverlist_start = serverlist;
                           }
                           else {
                               serverlist->next = new_server(ipv4, ipv6, port);
                               serverlist = serverlist->next;
                           }
                       }

                       if (ipv4) free(ipv4);
                       if (ipv6) free(ipv6);
                       if (port) free(port);
                    }
                }
                cfg->serverlist = serverlist_start;

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

                cfg->pidfile = strdup(pidfile);
                free(pidfile);
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

    if (filename == NULL) {
        fprintf(stderr, "zone_fetcher: no zonelist provided\n");
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

/** Write pidfile */
static int
writepid(char* pidfile, pid_t pid)
{
    FILE * fd;
    char pidbuf[32];
    size_t result = 0, size = 0;

    snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long) pid);
    if ((fd = fopen(pidfile, "w")) ==  NULL ) {
        fprintf(stderr, "zone_fetcher: cannot open pidfile %s: %s\n", pidfile, strerror(errno));
        return -1;
    }
    size = strlen(pidbuf);
    if (size == 0)
        result = 1;
    result = fwrite((const void*) pidbuf, 1, size, fd);
    if (result == 0) {
        fprintf(stderr, "zone_fetcher: write to pidfile failed: %s\n", strerror(errno));
    } else if (result < size) {
        fprintf(stderr, "zone_fetcher: short write to pidfile (disk full?)\n");
        result = 0;
    } else
        result = 1;
    if (!result) {
        fprintf(stderr, "zone_fetcher: cannot write pidfile %s: %s\n", pidfile, strerror(errno));
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
            fprintf(stderr, "zone_fetcher: fork() failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        default: /* parent is done */
            exit(0);
    }
    if (setsid() == -1)
    {
        fprintf(stderr, "setsid() failed: %s\n", strerror(errno));
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
init_sockets(sockets_type* sockets)
{
    int r, i, ip6_support = 1, on = 0;
    struct addrinfo hints[2];
#if defined(SO_REUSEADDR) || defined(IPV6_V6ONLY)
    on = 1;
#endif


    /* UDP / IPv6 */
    for (i = 0; i < 2; i++) {
        memset(&hints[i], 0, sizeof(hints[i]));
        hints[i].ai_family = AF_INET6;
        hints[i].ai_flags = AI_PASSIVE;
        hints[i].ai_socktype = SOCK_DGRAM;
    }

    if ((r = getaddrinfo(NULL, DNS_PORT_STRING, &hints[1], &(sockets->udp[1].addr))) != 0) {
        fprintf(stderr, "zone_fetcher: cannot parse address: getaddrinfo: %s %s\n",
            gai_strerror(r), r==EAI_SYSTEM?strerror(errno):"");
    }
    if ((sockets->udp[1].s = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
        if (errno == EAFNOSUPPORT) {
            fprintf(stderr, "zone_fetcher: fallback to UDP4, no IPv6: not supported\n");
            ip6_support = 0;
        } else {
            fprintf(stderr, "can't create udp/ipv6 socket: %s\n", strerror(errno));
            return -1;
        }
    }
    if (ip6_support) {
#ifdef IPV6_V6ONLY
        if (setsockopt(sockets->udp[1].s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
            fprintf(stderr, "zone_fetcher: setsockopt(..., IPV6_V6ONLY, ...) failed: %s",
                strerror(errno));
            return -1;
        }
#endif /* IPV6_V6ONLY */
        if (fcntl(sockets->udp[1].s, F_SETFL, O_NONBLOCK) == -1) {
            fprintf(stderr, "zone_fetcher: cannot fcntl udp/ipv6: %s\n", strerror(errno));
        }
        if (bind(sockets->udp[1].s,
                 (struct sockaddr *) sockets->udp[1].addr->ai_addr,
                 sockets->udp[1].addr->ai_addrlen) != 0) {
            fprintf(stderr, "zone_fetcher: can't bind udp/ipv6 socket: %s\n", strerror(errno));
            return -1;
        }
    }

    /* UDP / IPv4 */
#ifdef IPV6_V6ONLY
    for (i = 0; i < 2; i++) {
        hints[i].ai_family = AF_INET;
    }
#endif /* IPV6_V6ONLY */

    if ((r = getaddrinfo(NULL, DNS_PORT_STRING, &hints[0], &(sockets->udp[0].addr))) != 0) {
        fprintf(stderr, "zone_fetcher: cannot parse address: getaddrinfo: %s %s\n",
            gai_strerror(r), r==EAI_SYSTEM?strerror(errno):"");
    }
    if ((sockets->udp[0].s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        fprintf(stderr, "zone_fetcher: can't create udp/ipv4 socket: %s\n", strerror(errno));
        return -1;
    }
    if (fcntl(sockets->udp[0].s, F_SETFL, O_NONBLOCK) == -1) {
        fprintf(stderr, "zone_fetcher: cannot fcntl udp/ipv4: %s\n", strerror(errno));
    }
    if (bind(sockets->udp[0].s,
             (struct sockaddr *) sockets->udp[0].addr->ai_addr,
             sockets->udp[0].addr->ai_addrlen) != 0) {
        fprintf(stderr, "zone_fetcher: can't bind udp/ipv4 socket: %s\n", strerror(errno));
        return -1;
    }

    /* TCP / IPv6 */
    for (i = 0; i < 2; i++) {
        hints[i].ai_family = AF_INET6;
        hints[i].ai_socktype = SOCK_STREAM;
    }

    if ((r = getaddrinfo(NULL, DNS_PORT_STRING, &hints[1], &(sockets->tcp[1].addr))) != 0) {
        fprintf(stderr, "zone_fetcher: cannot parse address: getaddrinfo: %s %s\n",
            gai_strerror(r), r==EAI_SYSTEM?strerror(errno):"");
    }
    if ((sockets->tcp[1].s = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
        if (errno == EAFNOSUPPORT) {
            fprintf(stderr, "zone_fetcher: fallback to TCP4, no IPv6: not supported\n");
            ip6_support = 0;
        } else {
            fprintf(stderr, "can't create tcp/ipv6 socket: %s\n", strerror(errno));
            return -1;
        }
    }
    if (ip6_support) {
#ifdef IPV6_V6ONLY
        if (setsockopt(sockets->tcp[1].s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
            fprintf(stderr, "zone_fetcher: setsockopt(..., IPV6_V6ONLY, ...) failed: %s\n",
                strerror(errno));
            return -1;
        }
#endif /* IPV6_V6ONLY */
        if (setsockopt(sockets->tcp[1].s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            fprintf(stderr, "zone_fetcher: setsockopt(..., SO_REUSEADDR, ...) failed: %s\n", strerror(errno));
        }
        if (fcntl(sockets->tcp[1].s, F_SETFL, O_NONBLOCK) == -1) {
            fprintf(stderr, "zone_fetcher: cannot fcntl udp/ipv6: %s\n", strerror(errno));
        }
        if (bind(sockets->tcp[1].s,
                 (struct sockaddr *) sockets->tcp[1].addr->ai_addr,
                 sockets->tcp[1].addr->ai_addrlen) != 0) {
            fprintf(stderr, "zone_fetcher: can't bind tcp/ipv6 socket: %s\n", strerror(errno));
            return -1;
        }
        if (listen(sockets->tcp[1].s, 5) == -1) {
            fprintf(stderr, "zone_fetcher: can't listen to tcp/ipv6 socket: %s\n", strerror(errno));
            return -1;
        }
    }

    /* TCP / IPv4 */
#ifdef IPV6_V6ONLY
    for (i = 0; i < 2; i++) {
        hints[i].ai_family = AF_INET;
    }
#endif /* IPV6_V6ONLY */

    if ((r = getaddrinfo(NULL, DNS_PORT_STRING, &hints[0], &(sockets->tcp[0].addr))) != 0) {
        fprintf(stderr, "zone_fetcher: cannot parse address: getaddrinfo: %s %s\n",
            gai_strerror(r), r==EAI_SYSTEM?strerror(errno):"");
    }
    if ((sockets->tcp[0].s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "zone_fetcher: can't create tcp/ipv4 socket: %s\n", strerror(errno));
        return -1;
    }
#ifdef SO_REUSEADDR
    if (setsockopt(sockets->tcp[0].s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        fprintf(stderr, "zone_fetcher: setsockopt(..., SO_REUSEADDR, ...) failed: %s\n", strerror(errno));
    }
#endif /* SO_REUSEADDR */
    if (fcntl(sockets->tcp[0].s, F_SETFL, O_NONBLOCK) == -1) {
        fprintf(stderr, "zone_fetcher: cannot fcntl tcp/ipv4: %s\n", strerror(errno));
    }
    if (bind(sockets->tcp[0].s,
             (struct sockaddr *) sockets->tcp[0].addr->ai_addr,
             sockets->tcp[0].addr->ai_addrlen) != 0) {
        fprintf(stderr, "zone_fetcher: can't bind tcp/ipv4 socket: %s\n", strerror(errno));
        return -1;
    }
    if (listen(sockets->tcp[0].s, 5) == -1) {
        fprintf(stderr, "zone_fetcher: can't listen to tcp/ipv4 socket: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static void
free_sockets(sockets_type* sockets)
{
    close(sockets->udp[0].s);
    close(sockets->udp[1].s);
    close(sockets->tcp[0].s);
    close(sockets->tcp[1].s);

    free((void*)sockets->udp[0].addr);
    free((void*)sockets->udp[1].addr);
    free((void*)sockets->tcp[0].addr);
    free((void*)sockets->tcp[1].addr);
}

static void
odd_xfer(char* zone_name, char* output_file, uint32_t serial, config_type* config)
{
    serverlist_type* serverlist = NULL;

    if (config && config->serverlist) {
        serverlist = config->serverlist;
        while (serverlist) {
            if (config->use_tsig) {
                fprintf(stderr, "nsd-xfer -s %u -p %u %s [-T <%s:%s:%s>] -z %s -f %s.axfr %s\n",
                serial, serverlist->port, (serverlist->family==AF_INET6?"-6":"-4"),
                config->tsig_name, config->tsig_algo, config->tsig_secret,
                zone_name, output_file, serverlist->ipaddr);
            } else {
                fprintf(stderr, "nsd-xfer -s %u -p %u %s -z %s -f %s.axfr %s\n",
                serial, serverlist->port, (serverlist->family==AF_INET6?"-6":"-4"),
                zone_name, output_file, serverlist->ipaddr);
            }
            serverlist = serverlist->next;
        }
    }
}

static void
read_n_bytes(int sock, uint8_t* buf, size_t sz)
{
    size_t count = 0;
    while(count < sz) {
        ssize_t nb = recv(sock, buf+count, sz-count, 0);
        if(nb < 0) {
            fprintf(stderr, "zone_fetcher: recv() failed: %s\n", strerror(errno));
            return;
        }
        count += nb;
    }
}

static void
handle_udp(int udp_sock, int *count)
{
    ssize_t nb;
    uint8_t inbuf[INBUF_SIZE];
    struct handle_udp_userdata userdata;

    userdata.udp_sock = udp_sock;
    userdata.hislen = (socklen_t) sizeof(userdata.addr_him);
    nb = recvfrom(udp_sock, inbuf, INBUF_SIZE, 0,
        (struct sockaddr*)&userdata.addr_him, &userdata.hislen);
    if (nb < 1) {
        fprintf(stderr, "zone_fetcher: recvfrom() failed: %s\n", strerror(errno));
        return;
    }
    fprintf(stderr, "zone_fetcher: received NOTIFY over UDP.\n");
/*
    handle_query(inbuf, nb, entries, count, transport_udp, send_udp,
        &userdata, do_verbose?logfile:0);
*/
}

static void
handle_tcp(int tcp_sock, int *count)
{
    int s;
    struct sockaddr_storage addr_him;
    socklen_t hislen;
    uint8_t inbuf[INBUF_SIZE];
    uint16_t tcplen;
    struct handle_tcp_userdata userdata;

    /* accept */
    hislen = (socklen_t)sizeof(addr_him);
    if((s = accept(tcp_sock, (struct sockaddr*)&addr_him, &hislen)) < 0) {
        fprintf(stderr, "zone_fetcher: accept() failed: %s\n", strerror(errno));
        return;
    }
    userdata.s = s;

    /* tcp recv */
    read_n_bytes(s, (uint8_t*)&tcplen, sizeof(tcplen));
    tcplen = ntohs(tcplen);
    if(tcplen >= INBUF_SIZE) {
        fprintf(stderr, "zone_fetcher: query %d bytes too large, buffer %d bytes.\n",
            tcplen, INBUF_SIZE);
        close(s);
        return;
    }
    read_n_bytes(s, inbuf, tcplen);

    fprintf(stderr, "zone_fetcher: received NOTIFY over TCP.\n");
/*
    handle_query(inbuf, (ssize_t) tcplen, entries, count, transport_tcp,
        send_tcp, &userdata, do_verbose?logfile:0);
*/
    close(s);
}


static void
xfrd_ns(sockets_type* sockets, config_type* cfg)
{
    fd_set rset, wset, eset;
    struct timeval timeout;
    int count, maxfd;

    /* service */
    count = 0;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    while (1) {
        FD_ZERO(&rset);
        FD_ZERO(&wset);
        FD_ZERO(&eset);
        FD_SET(sockets->udp[0].s, &rset);
        FD_SET(sockets->udp[1].s, &rset);
        FD_SET(sockets->tcp[0].s, &rset);
        FD_SET(sockets->tcp[1].s, &rset);

        maxfd = sockets->udp[0].s;
        if (sockets->udp[1].s > maxfd) maxfd = sockets->udp[1].s;
        if (sockets->tcp[0].s > maxfd) maxfd = sockets->tcp[0].s;
        if (sockets->tcp[1].s > maxfd) maxfd = sockets->tcp[1].s;

        if (select(maxfd+1, &rset, &wset, &eset, NULL) < 0) {
            fprintf(stderr, "zone_fetcher: select(): %s\n", strerror(errno));
        }

        if (FD_ISSET(sockets->udp[0].s, &rset))
            handle_udp(sockets->udp[0].s, &count);
        if (FD_ISSET(sockets->udp[1].s, &rset))
            handle_udp(sockets->udp[1].s, &count);
        if (FD_ISSET(sockets->tcp[0].s, &rset))
            handle_tcp(sockets->tcp[0].s, &count);
        if (FD_ISSET(sockets->tcp[1].s, &rset))
            handle_tcp(sockets->tcp[1].s, &count);
    }
}

int
main(int argc, char **argv)
{
    const char* zonelist_file = NULL, *config_file = NULL;
    zonelist_type* zonelist = NULL, *zonelist_start = NULL;
    config_type* config = NULL;
    int c, run_as_daemon = 0, running = 0;
    uint32_t serial = 0;
    pid_t pid = 0;
    FILE* fd;
    sockets_type sockets;

    while ((c = getopt(argc, argv, "c:dhz:")) != -1) {
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

    running = run_as_daemon;
	if (run_as_daemon) {
        pid = setup_daemon(config);
        /* listen to NOTIFY messages */
        c = init_sockets(&sockets);
        if (c == -1) {
            fprintf(stderr, "zone_fetcher: failed to initialize sockets\n");
            exit(EXIT_FAILURE);
        }
    }

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
        odd_xfer(zonelist->name, zonelist->input_file, serial, config);
        /* next */
        zonelist = zonelist->next;
    }

    /* and now run our service */
    if (run_as_daemon) {
        xfrd_ns(&sockets, config);

        if (unlink(config->pidfile) == -1)
            fprintf(stderr, "zone_fetcher: unlink pidfile %s failed: %s\n", config->pidfile, strerror(errno));
        free_sockets(&sockets);
    }

    /* done */
    free_config(config);
    free_zonelist(zonelist);
    fprintf(stderr, "zone_fetcher: done\n");
    return 0;
}

/* [TODO]:
 * - respect the EXPIRE value?
 * ..
 */

