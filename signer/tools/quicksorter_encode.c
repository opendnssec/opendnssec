/*
 * $Id$
 *
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation).
 * All rights reserved.
 *
 * Written by Björn Stenberg <bjorn@haxx.se> for .SE
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "quicksorter_encode.h"

/* Internal binary RR format:

   cmplen   - (32-bit word) Length of data to compare (starting at 'owner')
   ttl      - (32-bit word) TTL value.
   rdlen    - (32-bit word) RDATA length
   owner    - Owner name, stored backwards (i.e. 'com.example.www').
              Each character is stored in a 16-bit word, with special values
              for end-of-segment and end-of-string
   type     - (16-bit word) RR type
   class    - (16-bit word) RR class
   rdata    - Binary RDATA in wire format

   The purpose of using this custom format instead of the exact wire format is
   to enable fast comparison. This way, RR records can be compared using a
   single memcmp() starting at the owner field.
*/

#define END_OF_SEGMENT htons(1)
#define END_OF_NAME 0

#define NUM_TYPES 101
#define NUM_CLASSES 5

static const char* typename[NUM_TYPES] = {
    NULL, "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR",
    "NULL","WKS","PTR","HINFO","MINFO","MX","TXT","RP","AFSDB","X25",
    "ISDN","RT","NSAP","NSAP-PTR","SIG","KEY","PX","GPOS","AAAA","LOC",
    "NXT","EID","NIMLOC","SRV","ATMA","NAPTR","KX","CERT","A6","DNAME",
    "SINK","OPT","APL","DS","SSHFP","IPSECKEY","RRSIG","NSEC","DNSKEY","DHCID",
    "NSEC3","NSEC3PARAM",NULL,NULL,NULL,"HIP","NINFO","RKEY",NULL,NULL,
    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,"SPF","DLV"
};

static const char* classname[NUM_CLASSES] = {
    NULL, "IN", NULL, "CH", "HS"
};

/* rdata data types, used in format_list below */
enum {
    RD_INT8,
    RD_INT16,
    RD_INT32,
    RD_NAME,   /* wire format, one string per segment */
    RD_STRING, /* wire format */
    RD_A,
    RD_AAAA,
    RD_LOC,
    RD_BASE64,
    RD_GWTYPE,  /* for IPSECKEY */
    RD_GATEWAY, /* for IPSECKEY */
    RD_APL,
    RD_CERT16,  /* for CERT */
    RD_HIP,
    RD_NSAP
};

static const char format_list[NUM_TYPES][8] = {
    /* 0 */         { 0 },
    /* 1: A  */     { 1, RD_A },
    /* 2: NS */     { 1, RD_NAME },
    /* 3: MD */     { 1, RD_NAME },
    /* 4: MF */     { 1, RD_NAME },
    /* 5: CNAME */  { 1, RD_NAME },
    /* 6: SOA */    { 7, RD_NAME, RD_NAME,
                      RD_INT32, RD_INT32, RD_INT32, RD_INT32, RD_INT32 },
    /* 7: MB */     { 1, RD_NAME },
    /* 8: MG */     { 1, RD_NAME },
    /* 9: MR */     { 1, RD_NAME },
    /* 10: NULL */  { 0 }, /* not allowed in master file */
    /* 11: WKS */   { 0 }, /* not supported by OpenDNSSEC */
    /* 12: PTR */   { 1, RD_NAME },
    /* 13: HINFO */ { 2, RD_STRING, RD_STRING },
    /* 14: MINFO */ { 2, RD_NAME, RD_NAME },
    /* 15: MX */    { 2, RD_INT16, RD_NAME },
    /* 16: TXT */   { 1, RD_STRING },
    /* 17: RP */    { 2, RD_NAME, RD_NAME },
    /* 18: AFSDB */ { 2, RD_INT16, RD_NAME },
    /* 19: X25 */   { 1, RD_STRING },
    /* 20: ISDN */  { 2, RD_STRING, RD_STRING },
    /* 21: RT */    { 2, RD_INT16, RD_STRING },
    /* 22: NSAP */  { 1, RD_NSAP },
    /* 23: NSAP-PTR */ {0}, /* obsoleted */
    /* 24: SIG */   { 0 }, /* not supported by OpenDNSSEC */
    /* 25: KEY */   { 0 }, /* not supported by OpenDNSSEC */
    /* 26: PX */    { 3, RD_INT16, RD_NAME, RD_NAME },
    /* 27: GPOS */  { 0 }, /* not supported by OpenDNSSEC */
    /* 28: AAAA */  { 1, RD_AAAA },
    /* 29: LOC */   { 1, RD_LOC },
    /* 30: NXT */   { 0 }, /* not supported by OpenDNSSEC */
    /* 31: EID */   { 0 }, /* not supported by OpenDNSSEC */
    /* 32: NIMLOC */{ 0 }, /* not supported by OpenDNSSEC */
    /* 33: SRV */   { 4, RD_INT16, RD_INT16, RD_INT16, RD_NAME },
    /* 34: ATMA */  { 0 },  /* not supported by OpenDNSSEC */
    /* 35: NAPTR */ { 6, RD_INT16, RD_INT16,
                      RD_STRING, RD_STRING, RD_STRING, RD_NAME },
    /* 36: KX */    { 2, RD_INT16, RD_NAME },
    /* 37: CERT */  { 4, RD_CERT16, RD_INT16, RD_INT8, RD_BASE64 },
    /* 38: A6 */    { 0 }, /* not supported by OpenDNSSEC */
    /* 39: DNAME */ { 1, RD_NAME },
    /* 40: SINK */  { 0 }, /* not supported by OpenDNSSEC */
    /* 41: OPT */   { 0 }, /* not allowed in master file */
    /* 42: APL */   { 1, RD_APL },
    /* 43: DS */    { 4, RD_INT16, RD_INT8, RD_INT8, RD_BASE64 },
    /* 44: SSHFP */ { 3, RD_INT8, RD_INT8, RD_BASE64 },
    /* 45: IPSECKEY */ {5, RD_INT8, RD_GWTYPE, RD_INT8, RD_GATEWAY, RD_BASE64},
    /* 46: RRSIG */ { 0 }, /* OpenDNSSEC will discard this DNSSEC RR */
    /* 47: NSEC */  { 0 }, /* OpenDNSSEC will discard this DNSSEC RR */
    /* 48: DNSKEY */{ 4, RD_INT16, RD_INT8, RD_INT8, RD_BASE64 },
    /* 49: DHCID */ { 1, RD_BASE64 },
    /* 50: NSEC3 */ { 0 }, /* OpenDNSSEC will discard this DNSSEC RR */
    /* 51: NSEC3PARAM */ { 0 }, /* OpenDNSSEC will discard this DNSSEC RR */
    /* 52: Unassigned */ { 0 },
    /* 53: Unassigned */ { 0 },
    /* 54: Unassigned */ { 0 },
    /* 55: HIP */   { 0 },
    /* 56: NINFO */ { 0 }, /* not supported by OpenDNSSEC */
    /* 57: RKEY */  { 0 }, /* not supported by OpenDNSSEC */
    /* 58: Unassigned */ { 0 },
    /* 59: Unassigned */ { 0 },
    /* 60-69: unassigned*/ {0},{0},{0},{0},{0},{0},{0},{0},{0},{0},
    /* 70-79: unassigned*/ {0},{0},{0},{0},{0},{0},{0},{0},{0},{0},
    /* 80-89: unassigned*/ {0},{0},{0},{0},{0},{0},{0},{0},{0},{0},
    /* 90-97: unassigned*/ {0},{0},{0},{0},{0},{0},{0},{0},{0},
    /* 99: SPF */   { 1, RD_STRING },
    /* 100: Used for 32769: DLV */ { 4, RD_INT16, RD_INT8, RD_INT8, RD_BASE64 }
};

static inline void encode_int32(uint32_t val, void* dest)
{
    *((uint32_t*)dest) = htonl(val);
}

static inline uint32_t decode_int32(void* src)
{
    return ntohl(*((unsigned int*)src));
}

static inline void encode_int16(uint16_t val, void* dest)
{
    *((uint16_t*)dest) = htons(val);
}

static inline uint16_t decode_int16(void* src)
{
    return ntohs(*((uint16_t*)src));
}

/* convert TTL text string to seconds */
static int parse_ttl(char* ttl)
{
    int seconds = 0;

    while (isspace(*ttl))
        ttl++;

    while (*ttl && !isspace(*ttl)) {
        int val = atoi(ttl);
        while (isdigit(*ttl))
            ttl++;
        switch (tolower(*ttl)) {
            case 'm': val *= 60; break;
            case 'h': val *= 3600; break;
            case 'd': val *= 86400; break;
            case 'w': val *= 86400*7; break;
            default:
                break;
        }
        seconds += val;
        ttl++;
    }
    return seconds;
}

static void encode_base16(char** _src, char** _dest, bool stop_on_noise)
{
    static const char hex2int[128] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0,
        0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    };
    char* src = *_src;
    char* dest = *_dest;

    while (*src && *src != '\n') {
        if (stop_on_noise && !isalnum(*src))
            break;
        while (*src && !isalnum(*src))
            src++;
        if (!*src)
            break;
        
        *dest++ = (hex2int[src[0] & 127] << 4) | hex2int[src[1] & 127];
        src += 2;
    }

    *_src = src;
    *_dest = dest;
}

static void decode_base16(char** _src, char** _dest, int bytes)
{
    static const char int2hex[16] = "0123456789ABCDEF";
    char* src = *_src;
    char* dest = *_dest;

    while (bytes--) {
        *dest++ = int2hex[*src >> 4];
        *dest++ = int2hex[*src & 15];
        src++;
    }

    *_src = src;
    *_dest = dest;
}

/* Note: "encode" in this context means transform from ascii to binary */
static int encode_base64(char** _src, char** _dest, bool stop_at_space)
{
    static const char inalphabet[256] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,1,0,0,0,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0 };
    static const char decoder[256] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,62,0,0,0,63,52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,
        0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,
        0,0,0,0,0,0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,
        45,46,47,48,49,50,51,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0 };

    char* src = *_src;
    char* dest = *_dest;

    int bits = 0;
    int char_count = 0;

    while (*src && *src != '\n') {
        if (stop_at_space && isspace(*src))
            break;
        int c = *src++;
	if (c == '=')
            break;
	if (!inalphabet[c])
            continue;
	bits += decoder[c];
	char_count++;
	if (char_count == 4) {
	    *dest++ = bits >> 16;
	    *dest++ = (bits >> 8) & 0xff;
	    *dest++ = bits & 0xff;
	    bits = 0;
	    char_count = 0;
	}
        else
	    bits <<= 6;
    }
    if (*src && *src != '\n' && !(stop_at_space && isspace(*src))) {
	switch (char_count) {
            case 1:
                fprintf(stderr, "base64 encoding incomplete: at least 2 bits missing");
                exit(-1);

            case 2:
                *dest++ = bits >> 10;
                break;

            case 3:
                *dest++ = bits >> 16;
                *dest++ = (bits >> 8) & 0xff;
                break;
	}
    }
    int len = dest - *_dest;
    *_src = src;
    *_dest = dest;

    return len;
}

/* Note: "decode" in this context means transform from binary to ascii */
static int decode_base64(char** _src, char** _dest, int bytes)
{
    static const char alphabet[64] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    char* src = *_src;
    char* dest = *_dest;
    int bits = 0;
    int char_count = 0;

    while (bytes--) {
	bits += *src++;
	char_count++;
	if (char_count == 3) {
	    *dest++ = alphabet[bits >> 18];
	    *dest++ = alphabet[(bits >> 12) & 0x3f];
	    *dest++ = alphabet[(bits >> 6) & 0x3f];
	    *dest++ = alphabet[bits & 0x3f];
	    bits = 0;
	    char_count = 0;
	}
        else
	    bits <<= 8;
    }

    if (char_count != 0) {
	bits <<= 16 - (8 * char_count);
	*dest++ = alphabet[bits >> 18];
	*dest++ = alphabet[(bits >> 12) & 0x3f];
	if (char_count == 1) {
	    *dest++ = '=';
	    *dest++ = '=';
	}
        else {
	    *dest++ = alphabet[(bits >> 6) & 0x3f];
	    *dest++ = '=';
	}
    }

    int len = dest - *_dest;
    *_src = src;
    *_dest = dest;

    return len;
}

static void encode_string(char** _src,
                          char** _dest,
                          bool domain_name,
                          char* origin)
{
    char* src = *_src;
    char* dest = *_dest;
    int len = 1; /* start at byte 1. byte 0 stores string length */
    bool quoted = false;
    bool copyorigin = false;

    if (domain_name && *src == '@') {
        if (!origin) {
            fprintf(stderr,"Error: No origin!\n");
            exit(-1);
        }
        src = origin;
    }

    while (1) {
        while (*src && (quoted || !isspace(*src))) {
            switch (*src) {
                case '\\':
                    /* parse \123 */
                    if (isdigit(src[1])) {
                        dest[len++] =
                            (src[1] - 48) * 100 +
                            (src[2] - 48) * 10 +
                            (src[3] - 48);
                        src += 3;
                    }
                    else {
                        dest[len++] = src[1];
                        src++;
                    }
                    break;

                case '.':
                    if (domain_name) {
                        /* start a new string segment */
                        dest[0] = len - 1;
                        dest += len;
                        len = 1;
                    }
                    else
                        dest[len++] = *src;
                    break;

                default:
                    if (domain_name)
                        dest[len++] = tolower(*src);
                    else {
                        dest[len++] = *src;
                        if (*src == '\"')
                            quoted = !quoted;
                    }
                    break;
            }
            src++;
        }

        if (!copyorigin)
            *_src = src;
        
        /* do we need to append origin? */
        if (domain_name && src[-1] != '.' && !copyorigin) {
            if (!origin) {
                fprintf(stderr,"Error: No origin!\n");
                exit(-1);
            }
            dest[0] = len - 1;
            dest += len;
            len = 1;
            src = origin;
            copyorigin = true;
        }
        else
            break;
    }

    dest[0] = len - 1; /* store length */
    dest += len;

    if (len > 255) {
        fprintf(stderr,"String '%s' is too long! (%d bytes)\n", src, len);
        exit(-1);
    }

    *_dest = dest;
}

static void decode_string(char** _src, char** _dest, bool domain_name)
{
    char* src = *_src;
    char* dest = *_dest;
    
    do {
        int len = *src++;
        
        for (int i=0; i<len; i++) {
            if (domain_name && (*src == '.' || *src == '\\')) {
                *dest++ = '\\';
                *dest++ = *src;
            }
            else {
                if (isgraph(*src))
                    *dest++ = *src;
                else
                    dest += sprintf(dest, "\\%03d", *src);
            }
            src++;
        }
        if (domain_name)
            *dest++ = '.';
    } while (domain_name && *src);

    if (domain_name)
        src++;

    *_src = src;
    *_dest = dest;
}

/* encodes the special 16-bit "backwards" format used for RR owner only */
static void* encode_owner(char* name,
                          void* dest,
                          char* origin)
{
    char tmpname[MAX_NAME_LEN];
    char labelpos[MAX_NAME_LEN];
    char* tmpptr = tmpname;
    encode_string(&name, &tmpptr, true, origin);

    /* iterate through string and store the position of each label */
    int count = 0;
    int pos = 0;
    do {
        labelpos[count++] = pos;
        pos += tmpname[pos] + 1;
    } while (tmpname[pos]);

    /* now store the name backwards */
    uint16_t* dptr = dest;
    for (int i=count-1; i >= 0; i--) {
        char* sptr = tmpname + labelpos[i];
        int len = *sptr++;
        while (len--) {
            *dptr++ = htons(*sptr | 0x100);
            sptr++;
        }
        *dptr++ = END_OF_SEGMENT;
    }
    dptr[-1] = END_OF_NAME;

    return dptr;
}

/* decodes the special 16-bit "backwards" format used for RR owner only */
static void decode_owner(char** _rr, char** _dest)
{
    uint16_t* rr = (uint16_t*)*_rr;
    char* dest = *_dest;

    int len = 0;
    while (rr[len] != END_OF_NAME)
        len++;

    /* reverse name */
    uint16_t* delim = rr + len;

    while (1) {
        uint16_t* end = delim;

        /* find start of name segment */
        while (delim > rr && (delim[-1] != END_OF_SEGMENT))
            delim--;

        uint16_t* p = delim;
        
        /* copy segment */
        while (p < end) {
            int c = ntohs(*p) & 0xff;
            switch (c) {
                case '.':
                    *dest++ = '\\';
                    *dest++ = '.';
                    break;

                case '\\':
                    *dest++ = '\\';
                    *dest++ = '\\';
                    break;

                default:
                    if (isgraph(c))
                        *dest++ = c;
                    else
                        dest += sprintf(dest, "\\%03d", c);
                    break;
            }
            p++;
        }
        *dest++ = '.';

        if (delim == rr)
            break;

        delim--;
    }
    *_rr += (len + 1) * sizeof(uint16_t);
    *_dest = dest;
}

static void encode_ipv4(char** src, char** dest)
{
    /* inet_pton() requires a null terminated string */
    char* end = *src;
    char oldend;
    while (isgraph(*end))
        end++;
    oldend = *end;
    *end = 0;

    if (!inet_pton(AF_INET, *src, *dest)) {
        fprintf(stderr,"Failed encoding ipv4 address: %s!\n", *src);
        exit(-1);
    }
               
    while (**src && !isspace(**src))
        (*src)++;
    *dest += 4;

    *end = oldend;
}

static void decode_ipv4(char** src, char** dest)
{
    if (!inet_ntop(AF_INET, *src, *dest, INET_ADDRSTRLEN)) {
        fprintf(stderr,"Failed encoding ipv4 address: %s!\n", *src);
        exit(-1);
    }
    while (**dest)
        (*dest)++;
    *src += 4;
}

static void encode_ipv6(char** src, char** dest)
{
    /* inet_pton() requires a null terminated string */
    char* end = *src;
    char oldend;
    while (isgraph(*end))
        end++;
    oldend = *end;
    *end = 0;

    inet_pton(AF_INET6, *src, *dest);
    while (**src && !isspace(**src))
        (*src)++;
    *dest += 16;

    *end = oldend;
}

static void decode_ipv6(char** src, char** dest)
{
    inet_ntop(AF_INET6, *src, *dest, INET6_ADDRSTRLEN);
    while (**dest)
        (*dest)++;
    *src += 16;
}

/* convert integer to power-of-ten format as used in LOC */
static int int2pow(int value)
{
    int power = 0;
    while (value > 9) {
        power++;
        value /= 10;
    }
    return value << 4 | power;
}

/* convert power-of-ten format as used in LOC to integer */
static int pow2int(int value)
{
    int power = value & 0xf;
    value >>= 4;

    while (power--)
        value *= 10;
    return value;
}

/* LOC: RFC 1876 */
static const int globe_median = 2147483648U;
static void encode_loc(char** _src, char** _dest)
{

    char* src = *_src;
    char* dest = *_dest;

    unsigned int lat = 0;
    unsigned int lon = 0;

    for (int i=0; i<2; i++) {
        unsigned int val = 0;

        /* degrees */
        val = atoi(src) * 3600000;
        while (!isspace(*src)) src++;
        while (isspace(*src)) src++;

        if (isdigit(*src)) {
            /* minutes */
            val += atoi(src) * 60000;
            while (!isspace(*src)) src++;
            while (isspace(*src)) src++;

            if (isdigit(*src)) {
                /* seconds */
                val += atof(src) * 1000;
                while (!isspace(*src)) src++;
                while (isspace(*src)) src++;
            }
        }

        switch (*src) {
            case 'N':
            case 'E':
                val = globe_median + val;
                break;

            default: /* S or W */
                val = globe_median - val;
                break;
        }
        while (!isspace(*src)) src++;
        while (isspace(*src)) src++;

        if (i==0)
            lat = val;
        else
            lon = val;
    };

    int alt = atof(src) * 100;
    while (*src && !isspace(*src)) src++;
    while (*src && isspace(*src)) src++;

    int size = int2pow(100);
    int hp = int2pow(10000);
    int vp = int2pow(10);

    /* optional parameters: */
    if (*src) {
        /* size */
        size = int2pow(atof(src) * 100);
        while (*src && !isspace(*src)) src++;
        while (*src && isspace(*src)) src++;

        if (*src) {
            /* horizontal precision */
            hp = int2pow(atof(src) * 100);
            while (*src && !isspace(*src)) src++;
            while (*src && isspace(*src)) src++;

            if (*src) {
                /* vertical precision */
                vp = int2pow(atof(src) * 100);
                while (*src && !isspace(*src)) src++;
            }
        }
    }
        
    *dest++ = 0; /* version, must be 0 */
    *dest++ = size;
    *dest++ = hp;
    *dest++ = vp;
    encode_int32(lat, dest);
    dest += 4;
    encode_int32(lon, dest);
    dest += 4;
    encode_int32(10000000 + alt, dest);
    dest += 4;

    *_src = src;
    *_dest = dest;
}

static void decode_loc(char** _src, char** _dest)
{
    char* src = *_src;
    char* dest = *_dest;

    src++; /* version */
    int size = pow2int(*src++);
    int hp = pow2int(*src++);
    int vp = pow2int(*src++);
    unsigned int lat = decode_int32(src);
    src += 4;
    unsigned int lon = decode_int32(src);
    src += 4;
    int alt = decode_int32(src) - 10000000;
    src += 4;

    for (int i=0; i<2; i++) {
        int val;
        char dir;
        if (i==0) {
            dir = (lat >= globe_median) ? 'N' : 'S';
            val = abs(lat - globe_median);
        }
        else {
            dir = (lon >= globe_median) ? 'E' : 'W';
            val = abs(lon - globe_median);
        }

        /* degrees */
        dest += sprintf(dest, "%d", val / 3600000);
        val %= 3600000;
        if (val) {
            /* minutes */
            dest += sprintf(dest, " %d", val / 60000);
            val %= 60000;
            if (val)
                /* seconds */
                dest += sprintf(dest, " %.3f", val / 1000.0);
        }

        *dest++ = ' ';
        *dest++ = dir;
        *dest++ = ' ';
    }
    dest += sprintf(dest, "%.2f", alt / 100.0);

    if (size != 100) {
        dest += sprintf(dest, " %.2f", size / 100.0);
        
        if (hp != 10000) {
            dest += sprintf(dest, " %.2f", hp / 100.0);
    
            if (vp != 10)
                dest += sprintf(dest, " %.2f", vp / 100.0);
        }
    }

    *_src = src;
    *_dest = dest;
}


/* APL: RFC 3123 */
static void encode_apl(char** _src, char** _dest)
{
    char* src = *_src;
    char* dest = *_dest;

    while (*src) {
        int negation = 0;

        if (*src == '!') {
            negation = 0x80;
            src++;
        }

        char* slash;
        int afi = atoi(src);
        int prefix;
        while (isdigit(*src))
            src++;
        src++;

        slash = strchr(src, '/');
        *slash = 0;
        prefix = atoi(slash + 1);

        encode_int16(afi, dest);
        dest += 2;
        *dest++ = prefix;
            
        switch (afi) {
            case 1: /* ipv4 */
                *dest++ = 4 | negation;
                encode_ipv4(&src, &dest);
                break;
 
            case 2: /* ipv6 */
                *dest++ = 16 | negation;
                encode_ipv6(&src, &dest);
                break;

            default:
                fprintf(stderr,"Unsupported APL address family %d\n", afi);
                exit(-1);
        }
        *slash = '/';
        src = slash + 2;
        while (*src && !isspace(*src))
            src++;
        while (*src && isspace(*src))
            src++;
    }

    *_src = src;
    *_dest = dest;
}

static void decode_apl(char** _src, char** _dest, int bytes)
{
    char* src = *_src;
    char* dest = *_dest;

    char* end = src + bytes;

    while (src < end) {
        int afi = decode_int16(src);
        src += 2;
        int prefix = *src++;
        int adflength = *src++;
        int negation = adflength & 0x80;

        if (negation)
            *dest++ = '!';
        *dest++ = afi + '0';
        *dest++ = ':';
        switch (afi) {
            case 1: decode_ipv4(&src, &dest); break;
            case 2: decode_ipv6(&src, &dest); break;
            default:
                fprintf(stderr,"Unsupported APL address family %d\n", afi);
                exit(-1);
        }
        dest += sprintf(dest, "/%d ", prefix);
    }
    *_src = src;
    *_dest = dest;
}

static void encode_int(char** src, char** dest, int type)
{
    int val = atoi(*src);
    switch (type) {
        case RD_INT8:
            **dest = val;
            (*dest)++;
            break;

        case RD_INT16:
            encode_int16(val, *dest);
            (*dest) += 2;
            break;

        case RD_INT32:
            encode_int32(val, *dest);
            (*dest) += 4;
            break;
    }

    while (**src && !isspace((unsigned)**src))
        (*src)++;
}

/* CERT: RFC 2538 */
static void encode_cert16(char** _src, char** _dest)
{
    char* src = *_src;
    char* dest = *_dest;

    int cert = 0;

    if (isdigit(*src))
        cert = atoi(src);
    else {
        /* parse mnemonic */
        switch (toupper(*src++)) {
            case 'P':
                switch (toupper(*src++)) {
                    case 'K': cert = 1; break; /* PKIX */
                    case 'G': cert = 3; break; /* PGP */
                }
                break;

            case 'S': cert = 2; break; /* SPKI */
            case 'U': cert = 253; break; /* URI */
            case 'O': cert = 254; break; /* OID */
        }
    }

    if (!cert) {
        fprintf(stderr,"Unknown certificate type: %s\n", *_src);
        exit(-1);
    }

    encode_int16(cert, dest);
    dest += 2;

    while (*src && !isspace(*src))
        src++;

    *_src = src;
    *_dest = dest;
}

/* HIP: RFC 5205 */
static void encode_hip(char** _src, char** _dest, char* origin)
{
    char* src = *_src;
    char* dest = *_dest;

    dest++; /* skip HIT length */

    *dest++ = atoi(src); /* PK algorithm */

    while (isdigit(*src))
        src++;
    while (isspace(*src))
        src++;

    dest += 2; /* skip PK length */

    /* encode HIT */
    char* tmp = dest;
    encode_base16(&src, &dest, true);
    while (isspace(*src))
        src++;
    **_dest = dest - tmp; /* HIT length */

    /* encode PK */
    tmp = dest;
    encode_base64(&src, &dest, true);
    while (*src && isspace(*src))
        src++;
    encode_int16(dest - tmp, *_dest + 2); /* PK length */

    /* encode all Rendezvous Servers */
    while (*src) {
        encode_string(&src, &dest, true, origin);
        while (*src && isspace(*src))
            src++;
    }
    
    *_src = src;
    *_dest = dest;
}

static void decode_hip(char** _src, char** _dest, int length)
{
    char* src = *_src;
    char* dest = *_dest;

    int hitlen = *src++;
    int pkalgo = *src++;
    dest += sprintf(dest, "%d ", pkalgo);

    int pklen = decode_int16(src);
    src += 2;

    decode_base16(&src, &dest, hitlen); /* HIT */

    *dest++ = ' ';
    
    decode_base64(&src, &dest, pklen); /* PK */

    while (src - *_src < length) { /* RVSs */
        *dest++ = ' ';
        decode_string(&src, &dest, true);
    }
    
    *_src = src;
    *_dest = dest;
}

/* Generic encoding: RFC 3597 */
static void encode_generic(char** _src, char** _dest)
{
    /* skip over \# token */
    *_src += 2;
    while (**_src && isspace(**_src))
        (*_src)++;

    /* skip over length */
    while (**_src && isdigit(**_src))
        (*_src)++;
    while (**_src && isspace(**_src))
        (*_src)++;

    encode_base16(_src, _dest, false);
}

static void decode_generic(char** _src, char** _dest, int bytes)
{
    *_dest += sprintf(*_dest, "\\# %d ", bytes);
    decode_base16(_src, _dest, bytes);
}

/* NSAP: RFC 1637 */
static void encode_nsap(char** _src, char** _dest)
{
    (*_src) += 2; /* step over "0x" */
    encode_base16(_src, _dest, false);
}

static void decode_nsap(char** _src, char** _dest, int bytes)
{
    *_dest += sprintf(*_dest, "0x");
    decode_base16(_src, _dest, bytes);
}

static void* encode_rdata(int type, char* rdata, char* dest, char* origin)
{
    static int tempvar = -1;
    const char* format = NULL;
    int pcount = 0;

    if (type > 0 && type < NUM_TYPES) {
        format = format_list[type];
        pcount = format[0];
    }

    if (rdata[0] == '\\' && rdata[1] == '#') {
        encode_generic(&rdata, &dest);
        pcount = 0;
    }
    else {
        if (format && !pcount) {
            fprintf(stderr,"Unsupported RR type '%s'\n", typename[type]);
            exit(-1);
        }
    }
    
    for (int i=1; i <= pcount; i++) {
        switch (format[i]) {
            case RD_NAME:
                encode_string(&rdata, &dest, true, origin);
                break;

            case RD_STRING:
                encode_string(&rdata, &dest, false, NULL);
                break;

            case RD_A:
                encode_ipv4(&rdata, &dest);
                break;

            case RD_AAAA:
                encode_ipv6(&rdata, &dest);
                break;
                
            case RD_INT8:
            case RD_INT16:
            case RD_INT32:
                encode_int(&rdata, &dest, format[i]);
                break;

            case RD_BASE64:
                encode_base64(&rdata, &dest, false);
                break;

            case RD_GWTYPE:
                tempvar = atoi(rdata);
                *dest++ = tempvar;
                while (!isspace(*rdata))
                    rdata++;
                break;

            case RD_GATEWAY:
                switch (tempvar) {
                    case 0: break;
                    case 1: encode_ipv4(&rdata, &dest); break;
                    case 2: encode_ipv6(&rdata, &dest); break;
                    case 3: encode_string(&rdata, &dest, true, origin); break;
                    default:
                        fprintf(stderr,"Error! Unsupported gwtype %d.\n", tempvar);
                        exit(-1);
                }

                if (tempvar == 1 || tempvar == 2) {
                    while (!isspace(*rdata))
                        rdata++;
                }
                break;

            case RD_LOC:
                encode_loc(&rdata, &dest);
                break;
                
            case RD_APL:
                encode_apl(&rdata, &dest);
                break;

            case RD_CERT16:
                encode_cert16(&rdata, &dest);
                break;

            case RD_HIP:
                encode_hip(&rdata, &dest, origin);
                break;
                
            case RD_NSAP:
                encode_nsap(&rdata, &dest);
                break;
                
            default:
                fprintf(stderr,"Error! Unsupported rdata parameter type %d.\n", format[i]);
                exit(-1);
                break;
        }
        while (isspace(*rdata))
            rdata++;
    }

    return dest;
}

static int decode_rdata(int type,
                        char* rdata,
                        char* dest,
                        int rdlen)
{
    static int tempvar = -1;
    const char* format = NULL;
    int pcount = 0;

    char* rstart = rdata;
    char* dstart = dest;

    if (type > 0 && type < NUM_TYPES) {
        format = format_list[type];
        pcount = format[0];
    }

    if (!format) {
        decode_generic(&rdata, &dest, rdlen);
        pcount = 0;
    }

    for (int i=1; i <= pcount; i++) {
        switch (format[i]) {
            case RD_NAME:
                decode_string(&rdata, &dest, true);
                break;

            case RD_STRING:
                decode_string(&rdata, &dest, false);
                break;

            case RD_A:
                decode_ipv4(&rdata, &dest);
                break;

            case RD_AAAA:
                decode_ipv6(&rdata, &dest);
                break;
                
            case RD_INT8:
                dest += sprintf(dest, "%d", *rdata);
                rdata++;
                break;

            case RD_INT16:
            case RD_CERT16:
                dest += sprintf(dest, "%d", decode_int16(rdata));
                rdata += 2;
                break;

            case RD_INT32:
                dest += sprintf(dest, "%d", decode_int32(rdata));
                rdata += 4;
                break;

            case RD_BASE64:
                decode_base64(&rdata, &dest, rdlen - (rdata - rstart));
                break;

            case RD_GWTYPE:
                tempvar = *rdata;
                dest += sprintf(dest, "%d", tempvar);
                rdata++;
                break;

            case RD_GATEWAY:
                switch (tempvar) {
                    case 0: break;
                    case 1: decode_ipv4(&rdata, &dest); break;
                    case 2: decode_ipv6(&rdata, &dest); break;
                    case 3: decode_string(&rdata, &dest, true); break;
                    default:
                        printf("Error! Unsupported gwtype %d.\n", tempvar);
                        exit(-1);
                }
                break;

            case RD_LOC:
                decode_loc(&rdata, &dest);
                break;
                
            case RD_APL:
                decode_apl(&rdata, &dest, rdlen - (rdata - rstart));
                break;

            case RD_HIP:
                decode_hip(&rdata, &dest, rdlen);
                break;
                
            case RD_NSAP:
                decode_nsap(&rdata, &dest, rdlen);
                break;

            default:
                fprintf(stderr,"Error! Unsupported rdata type %d for RR %d.\n",
                       format[i], type);
                exit(-1);
                break;
        }
        if (i<pcount)
            *dest++ = ' ';
    }
    *dest++ = '\n';
    *dest = 0;

    return dest - dstart;
}

int encode_rr(char* name,
              int type,
              int class,
              char* ttl,
              char* rdata,
              char* dest,
              char* origin)
{
    char* ptr = encode_owner(name, dest+12, origin);

    if (type == 32769) /* special case for DLV */
        type = 100;

    encode_int16(type, ptr);
    ptr += 2;

    encode_int16(class, ptr);
    ptr += 2;

    char* tmp = ptr;
    ptr = encode_rdata(type, rdata, ptr, origin);

    *(unsigned int*)dest = (ptr - dest - 12); /* cmplen */
    int seconds = parse_ttl(ttl);
    *(unsigned int*)(dest+4) = seconds;
    *(unsigned int*)(dest+8) = ptr - tmp; /* rdlen */

    return ptr - dest;
}

int decode_rr(char* src, char* dest)
{
    char* start = dest;
    src += 4; /* skip over cmplen */

    int ttl = *(unsigned int*)src;
    src += 4;

    int rdlen = *(unsigned int*)src;
    src += 4;
    
    decode_owner(&src, &dest);
    *dest++ = ' ';

    dest += sprintf(dest, "%d ", ttl);

    int type = decode_int16(src);
    src += 2;
    int class = decode_int16(src);
    src += 2;

    if (class > 0 && class < NUM_CLASSES)
        dest += sprintf(dest, "%s ", classname[class]);
    else
        dest += sprintf(dest, "CLASS%d ", type);

    if (type > 0 && type < NUM_TYPES)
        dest += sprintf(dest, "%s ", typename[type]);
    else
        dest += sprintf(dest, "TYPE%d ", type);
        
    dest += decode_rdata(type, src, dest, rdlen);

    return dest - start;
}
