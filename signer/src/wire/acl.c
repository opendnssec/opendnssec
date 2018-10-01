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
 * Access Control List.
 *
 */

#include "config.h"
#include "log.h"
#include "file.h"
#include "status.h"
#include "wire/acl.h"

static const char* acl_str = "acl";


/**
 * Returns range type.
 * mask is the 2nd part of the range.
 *
 */
static acl_range_type
acl_parse_range_type(char* ip, char** mask)
{
    char *p;
    if((p=strchr(ip, '&'))!=0) {
        *p = 0;
        *mask = p+1;
        return ACL_RANGE_MASK;
    }
    if((p=strchr(ip, '/'))!=0) {
        *p = 0;
        *mask = p+1;
        return ACL_RANGE_SUBNET;
    }
    if((p=strchr(ip, '-'))!=0) {
        *p = 0;
        *mask = p+1;
        return ACL_RANGE_MINMAX;
    }
    *mask = 0;
    return ACL_RANGE_SINGLE;
}


/**
 * Parses subnet mask, fills 0 mask as well
 *
 */
static ods_status
acl_parse_range_subnet(char* p, void* addr, int maxbits)
{
    int subnet_bits = atoi(p);
    uint8_t* addr_bytes = (uint8_t*)addr;
    if (subnet_bits == 0 && strcmp(p, "0")!=0) {
        return ODS_STATUS_ACL_SUBNET_BAD_RANGE;
    }
    if (subnet_bits < 0 || subnet_bits > maxbits) {
        return ODS_STATUS_ACL_SUBNET_OUT_RANGE;
    }
    /* fill addr with n bits of 1s (struct has been zeroed) */
    while(subnet_bits >= 8) {
        *addr_bytes++ = 0xff;
        subnet_bits -= 8;
    }
    if(subnet_bits > 0) {
        uint8_t shifts[] =
            {0x0, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};
        *addr_bytes = shifts[subnet_bits];
    }
    return ODS_STATUS_OK;
}


/**
 * Parse family from address.
 *
 */
int
acl_parse_family(const char* a)
{
   /* see if addr is ipv6 or ipv4 -- by : and . */
   while (*a) {
       if (*a == '.') {
           return AF_INET;
       }
       if (*a == ':') {
           return AF_INET6;
       }
       ++a;
   }
   /* default to v4 */
   return AF_INET;
}


/**
 * Create ACL.
 *
 */
acl_type*
acl_create(char* address, char* port,
    char* tsig_name, tsig_type* tsig)
{
    ods_status status = ODS_STATUS_OK;
    acl_type* acl = NULL;
    char* p = NULL;
    CHECKALLOC(acl = (acl_type*) malloc(sizeof(acl_type)));
    acl->address = NULL;
    acl->next = NULL;
    acl->tsig = NULL;
    if (tsig_name) {
        acl->tsig = tsig_lookup_by_name(tsig, tsig_name);
        if (!acl->tsig) {
            ods_log_error("[%s] unable to create acl: tsig %s not found",
                acl_str, tsig_name);
            acl_cleanup(acl);
            return NULL;
        }
    }
    acl->port = 0;
    if (port) {
        acl->port = atoi((const char*) port);
    }
    memset(&acl->addr, 0, sizeof(union acl_addr_storage));
    memset(&acl->range_mask, 0, sizeof(union acl_addr_storage));
    if (address) {
        acl->family = acl_parse_family(address);
        acl->range_type = acl_parse_range_type(address, &p);
        acl->address = strdup(address);
        if (!acl->address) {
            ods_log_error("[%s] unable to create acl: allocator_strdup() "
                "failed", acl_str);
            acl_cleanup(acl);
            return NULL;
        }
        if (acl->family == AF_INET6) {
            if (inet_pton(AF_INET6, acl->address, &acl->addr.addr6) != 1) {
                ods_log_error("[%s] unable to create acl: bad ipv6 address "
                    "(%s)", acl_str, acl->address);
                acl_cleanup(acl);
                return NULL;
            }
            if (acl->range_type == ACL_RANGE_MASK ||
                acl->range_type == ACL_RANGE_MINMAX) {
                if (inet_pton(AF_INET6, p, &acl->range_mask.addr6) != 1) {
                    ods_log_error("[%s] unable to create acl: bad ipv6 address"
                        " mask (%s)", acl_str, p);
                    acl_cleanup(acl);
                    return NULL;
                }
            } else if (acl->range_type == ACL_RANGE_SUBNET) {
                status = acl_parse_range_subnet(p, &acl->range_mask.addr6, 128);
                if (status != ODS_STATUS_OK) {
                    ods_log_error("[%s] unable to create acl: %s (%s)",
                        acl_str, ods_status2str(status), p);
                    acl_cleanup(acl);
                    return NULL;
                }
            }
        } else if (acl->family == AF_INET) {
            if (inet_pton(AF_INET, acl->address, &acl->addr.addr) != 1) {
                ods_log_error("[%s] unable to create acl: bad ipv4 address "
                    "(%s)", acl_str, acl->address);
                acl_cleanup(acl);
                return NULL;
            }
            if (acl->range_type == ACL_RANGE_MASK ||
                acl->range_type == ACL_RANGE_MINMAX) {
                if (inet_pton(AF_INET, p, &acl->range_mask.addr) != 1) {
                    ods_log_error("[%s] unable to create acl: bad ipv4 address"
                        " mask (%s)", acl_str, p);
                    acl_cleanup(acl);
                    return NULL;
                }
            } else if (acl->range_type == ACL_RANGE_SUBNET) {
                status = acl_parse_range_subnet(p, &acl->range_mask.addr, 32);
                if (status != ODS_STATUS_OK) {
                    ods_log_error("[%s] unable to create acl: %s (%s)",
                        acl_str, ods_status2str(status), p);
                    acl_cleanup(acl);
                    return NULL;
                }
            }
        }
    }
    acl->ixfr_disabled = 0;
    return acl;
}


/**
 * ACL matches address mask.
 *
 */
static int
acl_addr_matches_mask(uint32_t* a, uint32_t* b, uint32_t* mask, size_t sz)
{
    size_t i = 0;
    ods_log_assert(sz % 4 == 0);
    sz /= 4;
    for (i=0; i<sz; ++i) {
        if (((*a++)&*mask) != ((*b++)&*mask)) {
            return 0;
        }
        ++mask;
    }
    return 1;
}

/**
 * ACL matches address range.
 *
 */
static int
acl_addr_matches_range(uint32_t* minval, uint32_t* x, uint32_t* maxval,
    size_t sz)
{
    size_t i = 0;
    uint8_t checkmin = 1;
    uint8_t checkmax = 1;
    ods_log_assert(sz % 4 == 0);
    /* check treats x as one huge number */
    sz /= 4;
    for (i=0; i<sz; ++i) {
        /* if outside bounds, we are done */
        if (checkmin && minval[i] > x[i]) {
            return 0;
        }
        if (checkmax && maxval[i] < x[i]) {
            return 0;
        }
        /* if x is equal to a bound, that bound needs further checks */
        if (checkmin && minval[i] != x[i]) {
            checkmin = 0;
        }
        if (checkmax && maxval[i]!=x[i]) {
            checkmax = 0;
        }
        if (!checkmin && !checkmax) {
            return 1; /* will always match */
        }
    }
    return 1;
}


/**
 * ACL matches address.
 *
 */
static int
acl_addr_matches(acl_type* acl, struct sockaddr_storage* addr)
{
    if (!acl) {
        return 0;
    }
    if (!acl->address) {
        /* all addresses match */
        return 1;
    }
    if (acl->family == AF_INET6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*) addr;
        if (addr->ss_family != AF_INET6) {
            return 0;
        }
        if (acl->port != 0 && acl->port != ntohs(addr6->sin6_port)) {
            return 0;
        }
        switch(acl->range_type) {
            case ACL_RANGE_MASK:
            case ACL_RANGE_SUBNET:
                if (!acl_addr_matches_mask((uint32_t*)&acl->addr.addr6,
                    (uint32_t*)&addr6->sin6_addr,
                    (uint32_t*)&acl->range_mask.addr6,
                    sizeof(struct in6_addr))) {
                    return 0;
                }
                break;
            case ACL_RANGE_MINMAX:
                if (!acl_addr_matches_range((uint32_t*)&acl->addr.addr6,
                    (uint32_t*)&addr6->sin6_addr,
                    (uint32_t*)&acl->range_mask.addr6,
                    sizeof(struct in6_addr))) {
                    return 0;
                }
                break;
            case ACL_RANGE_SINGLE:
            default:
                if (memcmp(&addr6->sin6_addr, &acl->addr.addr6,
                    sizeof(struct in6_addr)) != 0) {
                    return 0;
                }
                break;
        }
        return 1;
    } else {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
        if (addr4->sin_family != AF_INET) {
            return 0;
        }
        if (acl->port != 0 && acl->port != ntohs(addr4->sin_port)) {
            return 0;
        }
        switch (acl->range_type) {
            case ACL_RANGE_MASK:
            case ACL_RANGE_SUBNET:
                if (!acl_addr_matches_mask((uint32_t*)&acl->addr.addr,
                    (uint32_t*)&addr4->sin_addr,
                    (uint32_t*)&acl->range_mask.addr,
                    sizeof(struct in_addr))) {
                    return 0;
                }
                break;
            case ACL_RANGE_MINMAX:
                if (!acl_addr_matches_range((uint32_t*)&acl->addr.addr,
                    (uint32_t*)&addr4->sin_addr,
                    (uint32_t*)&acl->range_mask.addr,
                    sizeof(struct in_addr))) {
                    return 0;
                }
                break;
            case ACL_RANGE_SINGLE:
            default:
                if (memcmp(&addr4->sin_addr, &acl->addr.addr,
                    sizeof(struct in_addr)) != 0) {
                    return 0;
                }
                break;
        }
        return 1;
    }
    /* not reached */
    return 0;
}


/**
 * ACL matches TSIG.
 *
 */
static int
acl_tsig_matches(acl_type* acl, tsig_rr_type* tsig)
{
    if (!acl || !tsig) {
        ods_log_debug("[%s] no match: no acl or tsig", acl_str);
        return 0; /* missing required elements */
    }
    if (!acl->tsig) {
        if (tsig->status == TSIG_NOT_PRESENT) {
            return 1;
        }
        ods_log_debug("[%s] no match: tsig present but no config", acl_str);
        return 0; /* TSIG present but no config */
    }
    if (tsig->status != TSIG_OK) {
        ods_log_debug("[%s] no match: tsig %s", acl_str,
            tsig_status2str(tsig->status));
        return 0; /* query has no TSIG */
    }
    if (tsig->error_code != LDNS_RCODE_NOERROR) {
        ods_log_debug("[%s] no match: tsig error %d", acl_str,
            tsig->error_code);
        return 0; /* query has bork TSIG */
    }
    if (!tsig->key_name || !tsig->algo) {
        ods_log_debug("[%s] no match: missing key/algo", acl_str);
        return 0;
    }
    if (!acl->tsig->key) {
        ods_log_debug("[%s] no match: no config", acl_str);
        return 0; /* missing TSIG config */
    }
    if (ldns_dname_compare(tsig->key_name, acl->tsig->key->dname) != 0) {
        ods_log_debug("[%s] no match: key names not the same", acl_str);
        return 0; /* wrong key name */
    }
    if (ods_strlowercmp(tsig->algo->txt_name, acl->tsig->algorithm) != 0) {
        ods_log_debug("[%s] no match: algorithms not the same", acl_str);
        return 0; /* wrong algorithm name */
    }
    /* tsig matches */
    return 1;
}


/**
 * Address storage to IP string.
 *
 */
int
addr2ip(struct sockaddr_storage addr, char* ip, size_t len)
{
    if (addr.ss_family == AF_INET6) {
        if (!inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr,
            ip, len)) {
            return 0;
        }
    } else {
        if (!inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr,
            ip, len))
            return 0;
    }
    return 1;
}


/**
 * Find ACL.
 *
 */
acl_type*
acl_find(acl_type* acl, struct sockaddr_storage* addr, tsig_rr_type* trr)
{
    acl_type* find = acl;
    while (find) {
        if (acl_addr_matches(find, addr) && acl_tsig_matches(find, trr)) {
            ods_log_debug("[%s] match %s", acl_str, find->address);
            return find;
        }
        find = find->next;
    }
    return NULL;
}


/**
 * Clean up ACL.
 *
 */
void
acl_cleanup(acl_type* acl)
{
    if (!acl) {
        return;
    }
    acl_cleanup(acl->next);
    free(acl->address);
    free(acl);
}
