/*
 * Copyright (c) 2011-2018 NLNet Labs.
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
 */

/**
 * Listener.
 *
 */

#include "config.h"
#include <stdlib.h>
#include "log.h"
#include "wire/listener.h"

static const char* listener_str = "listener";


/**
 * Create listener.
 *
 */
listener_type*
listener_create()
{
    listener_type* listener = NULL;
    CHECKALLOC(listener = (listener_type*) malloc(sizeof(listener_type)));
    listener->count = 0;
    listener->interfaces = NULL;
    return listener;
}


/**
 * Push an interface to the listener.
 *
 */
interface_type*
listener_push(listener_type* listener, char* address, int family, const char* port)
{
    interface_type* ifs_old = NULL;
    ods_log_assert(listener);
    ods_log_assert(address);
    ifs_old = listener->interfaces;
    CHECKALLOC(listener->interfaces = (interface_type*) malloc((listener->count + 1) * sizeof(interface_type)));
    if (ifs_old) {
        memcpy(listener->interfaces, ifs_old,
           (listener->count) * sizeof(interface_type));
    }
    free(ifs_old);
    listener->count++;
    listener->interfaces[listener->count -1].address = strdup(address);
    listener->interfaces[listener->count -1].family = family;

    if (port) {
        listener->interfaces[listener->count -1].port = strdup(port);
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
            ods_log_error("[%s] bad ip address '%s'", listener_str,
                listener->interfaces[listener->count -1].address);
            return NULL;
        }
    } else if (listener->interfaces[listener->count -1].family == AF_INET &&
        strlen(listener->interfaces[listener->count -1].address) > 0) {
        if (inet_pton(listener->interfaces[listener->count -1].family,
            listener->interfaces[listener->count -1].address,
            &listener->interfaces[listener->count -1].addr.addr) != 1) {
            ods_log_error("[%s] bad ip address '%s'", listener_str,
                listener->interfaces[listener->count -1].address);
            return NULL;
        }
    }
    return &listener->interfaces[listener->count -1];
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
}


/**
 * Clean up listener.
 *
 */
void
listener_cleanup(listener_type* listener)
{
    uint16_t i = 0;
    if (!listener) {
        return;
    }
    for (i=0; i < listener->count; i++) {
        interface_cleanup(&listener->interfaces[i]);
    }
    free(listener->interfaces);
    free(listener);
}
