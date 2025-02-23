/*
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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
 * Parsing DNS Adapter.
 *
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "settings.h"
#include "parser/addnsparser.h"
#include "adapter/addns.h"

static const char* parser_str = "parser";

int
parse_conf_dnsio(int inbound, const char* filename, dnsio_type* adapter)
{
    int count;
    int invalid = 0;
    settings_handle handle;
    tsig_type** tsigtail;
    acl_type** acltail;

    settings_access(&handle, -1, filename);

    tsigtail = &adapter->tsig;
    invalid |= settings_getcompound(handle, &count, "//Adapter/DNS/TSIG/Name");
    for(int i=0; i<count; i++) {
        char* name = NULL;
        char* algorithm = NULL;
        char* secret = NULL;
        invalid |= settings_getstring(handle, &name, NULL, "//Adapter/DNS/TSIG[%d]/Name",i+1);
        invalid |= settings_getstring(handle, &algorithm, NULL, "//Adapter/DNS/TSIG[%d]/Algorithm",i+1);
        invalid |= settings_getstring(handle, &secret, NULL, "//Adapter/DNS/TSIG[%d]/Secret",i+1);
        *tsigtail = tsig_create(name, algorithm, secret);
        if(!*tsigtail) {
            ods_log_error("[%s] unable to add tsig %s: tsig_create() failed", parser_str, name);
        }
        tsigtail = &(*tsigtail)->next;
        if(name) free(name);
        if(algorithm) free(algorithm);
        if(secret) free(secret);
    }
    *tsigtail = NULL;

    if(inbound) {
        acltail = &adapter->xfr_acl;
        invalid |= settings_getcompound(handle, &count, "//Adapter/DNS/Inbound/RequestTransfer/Remote");
        for(int i=0; i<count; i++) {
            char* address = NULL;
            char* port = NULL;
            char* key = NULL;
            invalid |= settings_getstring(handle, &address, settings_value_NULL, "//Adapter/DNS/Inbound/RequestTransfer/Remote[%d]/Address",i+1);
            invalid |= settings_getstring(handle, &port,    settings_value_NULL, "//Adapter/DNS/Inbound/RequestTransfer/Remote[%d]/Port",i+1);
            invalid |= settings_getstring(handle, &key,     settings_value_NULL, "//Adapter/DNS/Inbound/RequestTransfer/Remote[%d]/Key",i+1);
            *acltail = acl_create(address, port, key, adapter->tsig);
            if(!*acltail) {
                ods_log_error("[%s] unable to add acl for %s %s to list: acl_create() failed", parser_str, address?address:"",key?key:"");
            }
            acltail = &(*acltail)->next;
            if(address) free(address);
            if(port) free(port);
            if(key) free(key);
        }
        acltail = &adapter->notify_acl;
        invalid |= settings_getcompound(handle, &count, "//Adapter/DNS/Inbound/AllowNotify/Peer");
        for(int i=0; i<count; i++) {
            char* prefix = NULL;
            char* key = NULL;
            invalid |= settings_getstring(handle, &prefix, settings_value_NULL, "//Adapter/DNS/Inbound/AllowNotify/Peer[%d]/Prefix",i+1);
            invalid |= settings_getstring(handle, &key,     settings_value_NULL, "//Adapter/DNS/Inbound/AllowNotify/Peer[%d]/Key",i+1);
            *acltail = acl_create(prefix, NULL, key, adapter->tsig);
            if(!*acltail) {
                ods_log_error("[%s] unable to add acl for %s %s to list: acl_create() failed", parser_str, prefix?prefix:"",key?key:"");
            }
            acltail = &(*acltail)->next;
            if(prefix) free(prefix);
            if(key) free(key);
        }
    } else {
        acltail = &adapter->xfr_acl;
        invalid |= settings_getcompound(handle, &count, "//Adapter/DNS/Outbound/Notify/Remote");
        for(int i=0; i<count; i++) {
            char* address = NULL;
            char* port = NULL;
            char* key = NULL;
            invalid |= settings_getstring(handle, &address, settings_value_NULL, "//Adapter/DNS/Outbound/Notify/Remote[%d]/Address",i+1);
            invalid |= settings_getstring(handle, &port,    settings_value_NULL, "//Adapter/DNS/Outbound/Notify/Remote[%d]/Port",i+1);
            invalid |= settings_getstring(handle, &key,     settings_value_NULL, "//Adapter/DNS/Outbound/Notify/Remote[%d]/Key",i+1);
            *acltail = acl_create(address, port, key, adapter->tsig);
            if(!*acltail) {
                ods_log_error("[%s] unable to add acl for %s %s to list: acl_create() failed", parser_str, address?address:"",key?key:"");
            }
            acltail = &(*acltail)->next;
            if(address) free(address);
            if(port) free(port);
            if(key) free(key);
        }
        acltail = &adapter->notify_acl;
        invalid |= settings_getcompound(handle, &count, "//Adapter/DNS/Outbound/ProvideTransfer/Peer");
        for(int i=0; i<count; i++) {
            char* prefix = NULL;
            char* key = NULL;
            invalid |= settings_getstring(handle, &prefix, settings_value_NULL, "//Adapter/DNS/Outbound/ProvideTransfer/Peer[%d]/Prefix",i+1);
            invalid |= settings_getstring(handle, &key,     settings_value_NULL, "//Adapter/DNS/Outbound/ProvideTransfer/Peer[%d]/Key",i+1);
            *acltail = acl_create(prefix, NULL, key, adapter->tsig);
            if(!*acltail) {
                ods_log_error("[%s] unable to add acl for %s %s to list: acl_create() failed", parser_str, prefix?prefix:"",key?key:"");
            }
            acltail = &(*acltail)->next;
            if(prefix) free(prefix);
            if(key) free(key);
        }
    }

    settings_access(&handle, -1, NULL);
    return invalid;
}
