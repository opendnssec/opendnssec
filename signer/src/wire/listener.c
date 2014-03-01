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

#include "config.h"
#include "shared/log.h"
#include "wire/listener.h"

static const char* listener_str = "listener";


/**
 * Create listener.
 *
 */
listener_type*
listener_create(allocator_type* allocator)
{
    listener_type* listener = NULL;
    if (!allocator) {
        return NULL;
    }
    listener = (listener_type*) allocator_alloc(allocator,
        sizeof(listener_type));
    if (!listener) {
        ods_log_error("[%s] create listener failed: allocator_alloc() failed",
            listener_str);
        return NULL;
    }
    listener->allocator = allocator;
    listener->count = 0;
    listener->interfaces = NULL;
    return listener;
}


/**
 * Push an interface to the listener.
 *
 */
interface_type*
listener_push(listener_type* listener, char* address, int family, char* port)
{
    interface_type* ifs_old = NULL;
    ods_log_assert(listener);
    ods_log_assert(address);
    ifs_old = listener->interfaces;
    listener->interfaces = (interface_type*) allocator_alloc(
        listener->allocator, (listener->count + 1) * sizeof(interface_type));
    if (!listener->interfaces) {
        ods_fatal_exit("[%s] fatal unable to add interface: allocator_alloc() failed",
            listener_str);
    }
    if (ifs_old) {
        memcpy(listener->interfaces, ifs_old,
           (listener->count) * sizeof(interface_type));
    }
    allocator_deallocate(listener->allocator, (void*) ifs_old);
    listener->count++;
    listener->interfaces[listener->count -1].address =
        allocator_strdup(listener->allocator, address);
    listener->interfaces[listener->count -1].family = family;

    if (port) {
        listener->interfaces[listener->count -1].port =
            allocator_strdup(listener->allocator, port);
    } else{
        listener->interfaces[listener->count -1].port = NULL;
    }
    memset(&listener->interfaces[listener->count -1].addr, 0,
        sizeof(union acl_addr_storage));
    if (listener->interfaces[listener->count -1].family == AF_INET6 &&
        strlen(listener->interfaces[listener->count -1].address) > 0) {
        if (inet_pton(listener->interfaces[listener->count -1].family,
            listener->interfaces[listener->count -1].address,
            &listener->interfaces[listener->count -1].addr.addr6) != 1) {
            ods_log_error("[%s] bad ip address '%s'",
                listener->interfaces[listener->count -1].address);
            return NULL;
        }
    } else if (listener->interfaces[listener->count -1].family == AF_INET &&
        strlen(listener->interfaces[listener->count -1].address) > 0) {
        if (inet_pton(listener->interfaces[listener->count -1].family,
            listener->interfaces[listener->count -1].address,
            &listener->interfaces[listener->count -1].addr.addr) != 1) {
            ods_log_error("[%s] bad ip address '%s'",
                listener->interfaces[listener->count -1].address);
            return NULL;
        }
    }
    return &listener->interfaces[listener->count -1];
}


/**
 * Print interface.
 *
 */
static void
interface_print(FILE* fd, interface_type* i)
{
    if (!fd || !i) {
        return;
    }
    fprintf(fd, "<Interface>");
    if (i->family == AF_INET && i->address) {
        fprintf(fd, "<IPv4>%s</IPv4>", i->address);
    } else if (i->family == AF_INET6 && i->address) {
        fprintf(fd, "<IPv6>%s</IPv6>", i->address);
    }
    if (i->port) {
        fprintf(fd, "<Port>%s</Port>", i->port);
    }
    fprintf(fd, "</Interface>\n");
    return;
}


/**
 * Print listener.
 *
 */
void
listener_print(FILE* fd, listener_type* listener)
{
    uint16_t i = 0;
    if (!fd || !listener || listener->count <= 0) {
        return;
    }
    fprintf(fd, "<Listener>\n");
    for (i=0; i < listener->count; i++) {
        interface_print(fd, &listener->interfaces[i]);
    }
    fprintf(fd, "</Listener>\n");
    return;
}


/**
 * Log interface.
 *
 */
static void
interface_log(interface_type* i)
{
    if (!i) {
        return;
    }
    ods_log_debug("[%s] FAMILY[%s] ADDRESS[%s] PORT[%s]", listener_str,
        i->family==AF_INET6?"IPv6":"IPv4",
        i->address?i->address:"localhost",
        i->port?i->port:DNS_PORT_STRING);
    return;
}


/**
 * Log listener.
 *
 */
void
listener_log(listener_type* listener)
{
    uint16_t i = 0;
    if (!listener || listener->count <= 0) {
        return;
    }
    for (i=0; i < listener->count; i++) {
        interface_log(&listener->interfaces[i]);
    }
    return;
}


/**
 * Clean up interface.
 *
 */
void
interface_cleanup(interface_type* i)
{
    if (!i) {
        return;
    }
    free((void*)i->port);
    free((void*)i->address);
    return;
}


/**
 * Clean up listener.
 *
 */
void
listener_cleanup(listener_type* listener)
{
    uint16_t i = 0;
    allocator_type* allocator = NULL;
    if (!listener) {
        return;
    }
    for (i=0; i < listener->count; i++) {
        interface_cleanup(&listener->interfaces[i]);
    }
    allocator = listener->allocator;
    allocator_deallocate(allocator, (void*) listener->interfaces);
    allocator_deallocate(allocator, (void*) listener);
    return;
}
