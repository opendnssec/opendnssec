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
 * Access Control List.
 *
 */

#ifndef WIRE_ACL_H
#define WIRE_ACL_H

#include "config.h"
#include "status.h"
#include "wire/listener.h"
#include "wire/tsig.h"


/**
 * Address range type.
 *
 */
enum acl_range_enum {
    ACL_RANGE_SINGLE = 0,   /* single adress */
    ACL_RANGE_MASK = 1,     /* 10.20.30.40&255.255.255.0 */
    ACL_RANGE_SUBNET = 2,   /* 10.20.30.40/28 */
    ACL_RANGE_MINMAX = 3    /* 10.20.30.40-10.20.30.60 (mask=max) */
};
typedef enum acl_range_enum acl_range_type;

/**
 * ACL.
 *
 */
typedef struct acl_struct acl_type;
struct acl_struct {
    acl_type* next;
    /* address */
    char* address;
    unsigned int port;
    int family;
    union acl_addr_storage addr;
    union acl_addr_storage range_mask;
    acl_range_type range_type;
    /* tsig */
    const char* tsig_name;
    tsig_type* tsig;
    /* cache */
    time_t ixfr_disabled;
};

/**
 * Create ACL.
 * \param[in] allocator memory allocator
 * \param[in] address IP address
 * \param[in] port port
 * \param[in] tsig_name TSIG name
 * \param[in] tsig list of TSIGs
 * \return acl_type* ACL
 *
 */
extern acl_type* acl_create(char* address,
    char* port, char* tsig_name, tsig_type* tsig);

/**
 * Find ACL.
 * \param[in] acl ACL
 * \param[in] addr remote address storage
 * \param[in] tsig tsig credentials
 * \return acl_type* ACL that matches
 *
 */
extern acl_type* acl_find(acl_type* acl, struct sockaddr_storage* addr,
    tsig_rr_type* tsig);

/**
 * Parse family from address.
 * \param[in] a address in string format
 * \return int address family
 *
 */
extern int acl_parse_family(const char* a);

/**
 * Address storage to IP string.
 * \param[in] addr socket address storage
 * \param[out] ip ip address
 * \param[in] len max strlen of ip address
 * \return int 0 if failed, 1 otherwise
 *
 */
extern int addr2ip(struct sockaddr_storage addr, char* ip, size_t len);

/**
 * Clean up ACL.
 * \param[in] acl ACL
 * \param[in] allocator memory allocator
 *
 */
extern void acl_cleanup(acl_type* acl);

#endif /* WIRE_ACL_H */
