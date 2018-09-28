/*
 * Copyright (c) 2018 NLNet Labs.
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

#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <ldns/ldns.h>
#include <microhttpd.h>

#include "uthash.h"
#include "utilities.h"
#include "proto.h"
#include "httpd.h"

#define HTTPD_POOL_SIZE 1

struct connection_info {
    size_t buflen;
    char *buf;
};

static int
deleterecordsets(names_view_type view, struct rpc *rpc)
{
    int i;
    char* owner;
    recordset_type record;
    /* Not a delegation. Remove any rrsets mentioned in the request. */
    for(i=0; i<rpc->rr_count; i++) {
        ldns_rr *rr = rpc->rr[i];
        owner = ldns_rdf2str(ldns_rr_owner(rr));
        record = names_take(view, 0, owner);
        free(owner);
        if (!record) {
            names_viewreset(view);
            rpc->status = RPC_ERR;
            return 0;
        }
        names_recorddelall(record, ldns_rr_get_type(rr));
    }
    return 0;
}

static int
deletedelegation(names_view_type view, struct rpc *rpc)
{
    /* delete everything below delegation point, inclusive */
    names_iterator iter;
    recordset_type record;
    for (iter = names_viewiterator(view, names_iteratordescendants, rpc->delegation_point); names_iterate(&iter, &record); names_advance(&iter, NULL)) {
        names_overwrite(view, &record);
        names_recorddelall(record, 0);
    }
    /* in case of error  rpc->status = RPC_ERR; */
    return 0;
}

static int
insertrecords(names_view_type view, struct rpc *rpc)
{
    int i;
    /* now insert all rr's from rpc */
    for(i=0; i<rpc->rr_count; i++) {
        ldns_rr *rr = ldns_rr_clone(rpc->rr[i]);
        if (!rr) {
            names_viewreset(view);
            rpc->status = RPC_ERR;
            return 0;
        }
        char* owner = ldns_rdf2str(ldns_rr_owner(rr));
        /* this shouldn't be in the database anymore so we get a new object */
        recordset_type record = names_place(view, owner);
        free(owner);
        if (!record) {
            names_viewreset(view);
            rpc->status = RPC_ERR;
            return 0;
        }

        names_overwrite(view, &record);
        names_recordadddata(record, rr);
    }

    rpc->status = RPC_OK;
    return 0;
}

int
httpd_dispatch(names_view_type view, struct rpc *rpc)
{
    if (!view) {
        rpc->status = RPC_RESOURCE_NOT_FOUND;
        return 1;
    } else {
        names_viewreset(view);
        switch (rpc->opc) {
            case RPC_CHANGE_DELEGATION:
                deletedelegation(view, rpc);
                insertrecords(view, rpc);
                names_viewcommit(view);
                return 0;
            case RPC_CHANGE_NAME:
                deleterecordsets(view, rpc);
                insertrecords(view, rpc);
                names_viewcommit(view);
                return 0;
            default:
                rpc->status = RPC_ERR;
                return 1;
        }
    }
}

static int
handle_content(struct httpd* httpd, const char *url, const char *buf, size_t buflen,
    struct MHD_Response **response, int *http_code)
{
    /* DECODE (url, buf) HERE */
    int ret;
    names_view_type view;
    struct rpc *rpc = rpc_decode_json(url, buf, buflen);
    if (!rpc) {
        char *body = strdup("Can't parse\n");
        *response = MHD_create_response_from_buffer(strlen(body),
            (void*) body, MHD_RESPMEM_MUST_FREE);
        *http_code = MHD_HTTP_BAD_REQUEST;
        return 0;
    }

    /* PROCESS DB STUFF HERE */
    view = zonelist_obtainresource(httpd->zonelist, rpc->zone, offsetof(zone_type, inputview));
    ret = httpd_dispatch(view, rpc);
    if (ret) {
        /* Failed to apply to database, status is set by rpcproc_apply */
        /* PASS */
    }

    /* ENCODE (...) HERE */
    char *answer;
    size_t answer_len;
    ret = rpc_encode_json(rpc, &answer, &answer_len);
    if (ret) {
        /* If we can't formulate a respone just hang up. */
        /* A negative response should still have ret==0  */
        rpc_destroy(rpc);
        return 1;
    }

    *response = MHD_create_response_from_buffer(answer_len,
        (void*)answer, MHD_RESPMEM_MUST_FREE);
    if (rpc->status == RPC_OK)
        *http_code = MHD_HTTP_OK;
    else if (rpc->status == RPC_RESOURCE_NOT_FOUND)
        *http_code = MHD_HTTP_NOT_FOUND;
    else
        *http_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    rpc_destroy(rpc);
    return !(*response);
}

static int
handle_connection(void *cls, struct MHD_Connection *connection,
    const char *url,
    const char *method, const char *version,
    const char *upload_data,
    size_t *upload_data_size, void **con_cls)
{
    struct httpd* httpd = (struct httpd*) cls;
    (void)version;
    if(!*con_cls) {
        struct connection_info *con_info = malloc(sizeof(struct connection_info));
        if (!con_info) return MHD_NO;
        *con_cls = (void *)con_info;
        con_info->buf = malloc(*upload_data_size);
        memcpy(con_info->buf, upload_data, *upload_data_size);
        con_info->buflen = *upload_data_size;
        *upload_data_size = 0;
        return MHD_YES;
    }

    struct connection_info *con_info = (struct connection_info *)*con_cls;
    if (*upload_data_size) {
        con_info->buf = realloc(con_info->buf, con_info->buflen + *upload_data_size);
        memcpy(con_info->buf + con_info->buflen, upload_data, *upload_data_size);
        con_info->buflen += *upload_data_size;
        *upload_data_size = 0;
        return MHD_YES;
    }

    MHD_get_connection_values(connection, MHD_HEADER_KIND, NULL/*&print_headers*/, NULL);
    struct MHD_Response *response = NULL;
    int http_status_code = MHD_HTTP_OK;
    if (!strcmp(method, "POST")) {
        if (handle_content(httpd, url, con_info->buf,
            con_info->buflen, &response, &http_status_code))
        {
            const char *body = "some error?\n";
            response = MHD_create_response_from_buffer(strlen(body),
                (void*) body, MHD_RESPMEM_PERSISTENT);
        }
    } else if (!strcmp(method, "GET")) {
        char *body  = strdup("I don't GET it\n");
        response = MHD_create_response_from_buffer(strlen(body),
            (void*) body, MHD_RESPMEM_MUST_FREE);
    } else {
        const char *body = "Who are you?\n";
        response = MHD_create_response_from_buffer(strlen(body),
            (void*) body, MHD_RESPMEM_PERSISTENT);
        http_status_code = MHD_HTTP_BAD_REQUEST;
    }
  int ret = MHD_queue_response(connection, http_status_code, response);
  MHD_destroy_response(response);
  return ret;
}

static void
handle_connection_done(void *cls, struct MHD_Connection *connection,
    void **con_cls, enum MHD_RequestTerminationCode toe)
{
    struct connection_info *con_info = *con_cls;
    (void)cls;
    (void)connection;
    (void)toe;
    if (con_info) {
        free(con_info->buf);
    }
    free(con_info);
    *con_cls = NULL;
}

struct httpd *
httpd_create(struct http_listener_struct* config, zonelist_type* zonelist)
{
    struct httpd *httpd;
    CHECKALLOC(httpd = (struct httpd *) malloc(sizeof(struct httpd)));
    httpd->zonelist = zonelist;
    httpd->if_count = config->count;
    httpd->ifs = NULL;
    CHECKALLOC(httpd->ifs = (struct sockaddr_storage *) malloc(httpd->if_count * sizeof(struct sockaddr_storage)));
    for (int i = 0; i < httpd->if_count; i++) {
        struct http_interface_struct *cif = config->interfaces + i;

        if (cif->family == AF_INET6) {
            struct sockaddr_in6 *inf6 = (struct sockaddr_in6 *)&(httpd->ifs[i]);
            inf6->sin6_family = AF_INET6;
            const char *addr = cif->address[0]? cif->address : "::0";
            if (inet_pton(AF_INET6, addr, &(inf6->sin6_addr)) != 1) {
                return NULL;
            }
            inf6->sin6_port = htons(atoi(cif->port));
        } else {
            struct sockaddr_in *inf4 = (struct sockaddr_in *)&(httpd->ifs[i]);
            inf4->sin_family = AF_INET;
            const char *addr = cif->address[0]? cif->address : "0.0.0.0";
            if (inet_pton(AF_INET, addr, &(inf4->sin_addr)) != 1) {
                return NULL;
            }
            inf4->sin_port = htons(atoi(cif->port));
        }
    }
    return httpd;
}

void
httpd_destroy(struct httpd *httpd)
{
    free(httpd->ifs);
    free(httpd);
}

void
httpd_start(struct httpd *httpd)
{
    int flags, numdefaultops, i;
    int useipv4 = 0;
    int useipv6 = 0;
    struct MHD_OptionItem* ops;
    struct MHD_OptionItem defaultops[] = {
        { MHD_OPTION_THREAD_POOL_SIZE, HTTPD_POOL_SIZE, NULL },
        { MHD_OPTION_NOTIFY_COMPLETED, (intptr_t)handle_connection_done, NULL },
        //{ MHD_OPTION_NOTIFY_CONNECTION, (intptr_t)handle_connection_start, NULL },
        { MHD_OPTION_CONNECTION_LIMIT, 100, NULL },
        { MHD_OPTION_CONNECTION_TIMEOUT, 10, NULL },
        { MHD_OPTION_END, 0, NULL }
    };

    ops = malloc(sizeof(defaultops) + sizeof(struct MHD_OptionItem) * httpd->if_count);
    memcpy(ops,defaultops,sizeof(defaultops));
    numdefaultops = sizeof(defaultops) / sizeof(struct MHD_OptionItem);
    ops[numdefaultops + httpd->if_count - 1] = defaultops[numdefaultops - 1];
    --numdefaultops;
    for(i=0; i<httpd->if_count; i++) {
        ops[numdefaultops+i].option = MHD_OPTION_SOCK_ADDR;
        ops[numdefaultops+i].value = 0;
        ops[numdefaultops+i].ptr_value = &(httpd->ifs[i]);
        switch(httpd->ifs[i].ss_family) {
            case AF_INET:
                useipv4 = 1;
                break;
            case AF_INET6:
                useipv6 = 1;
                break;
        }
    }
    flags = MHD_USE_DEBUG | MHD_USE_SELECT_INTERNALLY;
    if(useipv4 && useipv6) {
        flags |= MHD_USE_DUAL_STACK;
    } else if(useipv6) {
        flags |= MHD_USE_IPv6;
    }
    httpd->daemon = MHD_start_daemon(flags,
        0, NULL, NULL,
        &handle_connection, httpd,
        MHD_OPTION_ARRAY, ops, MHD_OPTION_END);
}

void
httpd_stop(struct httpd *httpd)
{
    MHD_stop_daemon(httpd->daemon);
}

http_interface_type*
http_listener_push(http_listener_type* listener, char* address, int family, const char* port, char* user, char* pass)
{
    listener->count++;
    CHECKALLOC(listener->interfaces = (http_interface_type*) realloc(listener->interfaces, listener->count * sizeof(http_interface_type)));
    listener->interfaces[listener->count-1].address = strdup(address);
    listener->interfaces[listener->count-1].family = family;
    listener->interfaces[listener->count-1].port = strdup(port);
    listener->interfaces[listener->count-1].user = (user ? strdup(user) : NULL);
    listener->interfaces[listener->count-1].pass = (pass ? strdup(pass) : NULL);

    memset(&listener->interfaces[listener->count -1].addr, 0,
        sizeof(union acl_addr_storage));
    if (listener->interfaces[listener->count -1].family == AF_INET6 &&
        strlen(listener->interfaces[listener->count -1].address) > 0) {
        if (inet_pton(listener->interfaces[listener->count -1].family,
            listener->interfaces[listener->count -1].address,
            &listener->interfaces[listener->count -1].addr.addr6) != 1) {
            return NULL;
        }
    } else if (listener->interfaces[listener->count -1].family == AF_INET &&
        strlen(listener->interfaces[listener->count -1].address) > 0) {
        if (inet_pton(listener->interfaces[listener->count -1].family,
            listener->interfaces[listener->count -1].address,
            &listener->interfaces[listener->count -1].addr.addr) != 1) {
            return NULL;
        }
    }
    return &listener->interfaces[listener->count -1];
}
