/*
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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

/**
 * Listener.
 *
 */

#ifndef WIRE_LISTENER_H
#define WIRE_LISTENER_H

#include "config.h"
#include "status.h"

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

#define DNS_PORT_STRING "53"
#define INBUF_SIZE      4096 /* max size for incoming queries */
#define MAX_INTERFACES  32

/**
 * Access control.
 *
 */
union acl_addr_storage {
    struct in_addr addr;
    struct in6_addr addr6;
};

/**
 * Interface.
 *
 */
typedef struct interface_struct interface_type;
struct interface_struct {
    char* port;
    char* address;
    int family;
    union acl_addr_storage addr;
};

/**
 * Listener.
 *
 */
typedef struct listener_struct listener_type;
struct listener_struct {
    interface_type* interfaces;
    size_t count;
};

/**
 * Create listener.
 * \param[in] allocator memory allocator
 * \return listener_type* listener
 *
 */
extern listener_type* listener_create(void);

/**
 * Push an interface to the listener.
 * \param[in] listener listener
 * \param[in] address IP address
 * \param[in] family address family
 * \param[in] port port or NULL
 * \return interface_type* added interface
 *
 */
extern interface_type* listener_push(listener_type* list, char* address, int family,
    const char* port);

/**
 * Clean up interface.
 * \param[in] i interface
 *
 */
extern void interface_cleanup(interface_type* i);

/**
 * Clean up listener.
 * \param[in] listener listener to clean up
 *
 */
extern void listener_cleanup(listener_type* listener);

#endif /* WIRE_LISTENER_H */
