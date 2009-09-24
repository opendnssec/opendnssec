/*
 * $Id: zone_fetcher.h 1810 2009-09-15 14:49:55Z matthijs $
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define DNS_PORT 53

/**
 * Servers.
 */
typedef struct serverlist_struct serverlist_type;
struct serverlist_struct
{
    int family;
    int port;
    char* ipaddr;
    serverlist_type* next;
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
    serverlist_type* serverlist;
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

/**
 * State of transfer.
 */
typedef struct axfr_state_struct axfr_state_type;
struct axfr_state_struct
{
    size_t packets_received;
    size_t bytes_received;

    int s;              /* AXFR socket.  */
    int    done;        /* AXFR is complete.  */
};
