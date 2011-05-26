/*
 * $Id$
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

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "config.h"

#ifndef TOOLS_ZONEFETCHER_H
#define TOOLS_ZONEFETCHER_H

#define DNS_PORT_STRING "53"
#define INBUF_SIZE      4096 /* max size for incoming queries */
#define MAX_INTERFACES  128

/**
 * Access control.
 */
union acl_addr_storage {
    struct in_addr addr;
    struct in6_addr addr6;
};

/**
 * Servers.
 */
typedef struct serverlist_struct serverlist_type;
struct serverlist_struct
{
    int family;
    const char* port;  /* 0 == no port */
    const char* ipaddr;
    union acl_addr_storage addr;
    serverlist_type* next;
};

/**
 * Zone list.
 */
typedef struct zfzonelist_struct zfzonelist_type;
struct zfzonelist_struct
{
    const char* name;
    ldns_rdf* dname;
    char* input_file;
    zfzonelist_type* next;
};

/**
 * Config.
 */
typedef struct config_struct config_type;
struct config_struct
{
    int use_tsig;
    char* tsig_name;
    char* tsig_algo;
    char* tsig_secret;
    char* pidfile;
    const char* zonelist_file;
    zfzonelist_type* zonelist;
    serverlist_type* serverlist;
    serverlist_type* notifylist;
};

/**
 * Sockets.
 */
struct odd_socket
{
    struct addrinfo* addr;
    int s;
};

typedef struct sockets_struct sockets_type;
struct sockets_struct
{
    struct odd_socket tcp[MAX_INTERFACES];
    struct odd_socket udp[MAX_INTERFACES];
};

/**
 * User data.
 */
struct handle_udp_userdata {
    int udp_sock;
    struct sockaddr_storage addr_him;
    socklen_t hislen;
};

struct handle_tcp_userdata {
    int s;
};


/**
 * Start zone fetcher.
 *
 */
int
tools_zone_fetcher(const char* config_file, const char* zonelist_file,
    const char* group, const char* user, const char* chroot,
    const char* log_file, int use_syslog, int verbosity);

#endif /* TOOLS_ZONEFETCHER_H */
