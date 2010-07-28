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

/*
 * This tool sorts a zone file for OpenDNSSEC. It tries to be quick.
 */
  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#ifdef DEBUG
#include <sys/times.h>
#endif

#include "quicksorter_encode.h"

#ifdef DEBUG
#define DEBUGF(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUGF(...)
#endif

#define MIN(x,y) (x < y ? x : y)

struct global_data {
    int linecount;
    int listsize;
    char** lines;
};

bool inside_string(char* start, char* pos)
{
    bool inside = false;
    char* p = start;
    while (p < pos) {
        if (*p == '"') {
            if (p > start) {
                if (p[-1] != '\\')
                    inside = !inside;
            }
            else {
                fprintf(stderr,"String starter (\") found at column 1!\n");
                exit(-1);
            }
        }
        p++;
    }

    return inside;
}

int parse_rrclass(const char* s)
{
    /*
      This function is used to check which class name 's' is.
      Recognized class names: IN, CH, CS, HS, CLASSxx
    */

    switch (toupper(s[0])) {
        case 'C':
            switch (toupper(s[1])) {
                case 'H': return 3;
                case 'L': return atoi(s+5);
                case 'S': return 2;
            }
            break;

        case 'H':
            /* ensure it is not type HINFO */
            if (toupper(s[1]) == 'S')
                return 4;
            break;

        case 'I':
            if (toupper(s[1]) == 'N')
                return 1;
            break;
    }
    return 0;
}

int parse_rrtype(const char* s)
{
    /*
      Performs the minimum necessary checks to decide which RR type 's' is.
      
      The following RR types are not allowed, and hence not matched:
       NULL, OPT, TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, *
    */

    switch (toupper(s[0])) {
        case 'A':
            switch (toupper(s[1])) {
                case '6': return 38;  /* A6 */
                case 'A': return 28;  /* AAAA */
                case 'F': return 18;  /* AFSDB */
                case 'P': return 42;  /* APL */
                case 'T': return 34;  /* ATMA */
                default: return 1;   /* A */
            }
            break;
            
        case 'C':
            switch (toupper(s[1])) {
                case 'E': return 37; /* CERT*/
                case 'N': return 5;  /* CNAME */
            }
            break;

        case 'D':
            switch (toupper(s[1])) {
                case 'L': return 32769; /* DLV */
                case 'N':
                    switch (toupper(s[2])) {
                        case 'A': return 39; /* DNAME */
                        case 'S': return 48; /* DNSKEY */
                    }
                    break;
                case 'S': return 43; /* DS */
                case 'H': return 49; /* DHCID */
            }
            break;

        case 'E': return 31; /* EID */

        case 'G':
            switch (toupper(s[1])) {
                case 'I': return 102; /* GID */
                case 'P': return 27; /* GPOS */
            }
            break;
            
        case 'H':
            return 13; /* HINFO */

        case 'I':
            switch (toupper(s[1])) {
                case 'P': return 45;  /* IPSECKEY */
                case 'S': return 20;  /* ISDN */
            }
            break;

        case 'K':
            switch (toupper(s[1])) {
                case 'E': return 25; /* KEY */;
                case 'X': return 36; /* KX */
            }
            break;

        case 'L': return 29; /* LOC */

        case 'M':
            switch (toupper(s[1])) {
                case 'B': return 7;  /* MB */
                case 'D': return 3;  /* MD */
                case 'F': return 4;  /* MF */
                case 'G': return 8;  /* MG */
                case 'I': return 14; /* INFO */
                case 'R': return 9;  /* MR */
                case 'X': return 15; /* MX */
            }
            break;

        case 'N':
            switch (toupper(s[1])) {
                case 'A': return 35; /* NAPTR */

                case 'I':
                    switch (toupper(s[2])) {
                        case 'M': return 32; /* NIMLOC */
                        case 'N': return 56; /* NINFO */
                    }
                    break;
                    
                case 'S':
                    switch (toupper(s[2])) {
                        case 'A': /* NSAP* */
                            switch (s[4] == '_') {
                                case '_': return 23; /* NSAP_PTR */
                                default: return 22;  /* NSAP */
                            }
                            break;

                        case 'E':
                            switch (s[4]) {
                                case '3':
                                    switch (toupper(s[5])) {
                                        case 'P': return 51; /* NSEC3PARAM */
                                        default: return 50;  /* NSEC3 */
                                    }
                                    break;

                                default:
                                    return 47; /* NSEC */
                            }
                        default:
                            return 2;  /* NS */
                    }
                    break;

                case 'U': return 10; /* NULL */
                case 'X': return 30; /* NXT */
            }
            break;

        case 'P':
            switch (toupper(s[1])) {
                case 'T': return 12; /* PTR */
                case 'X': return 26; /* PX */
            }
            break;

        case 'R':
            switch (toupper(s[1])) {
                case 'K': return 57; /* RKEY */
                case 'P': return 17; /* RP */
                case 'R': return 46; /* RRSIG */
                case 'T': return 21; /* RT */
            }
            break;

        case 'S':
            switch (toupper(s[1])) {
                case 'I':
                    switch (toupper(s[2])) {
                        case 'G': return 24; /* SIG */
                        case 'N': return 40; /* SINK */
                    }
                    break;
                case 'O': return 6;  /* SOA */
                case 'P': return 99; /* SPF */
                case 'R': return 33; /* SRV */
                case 'S': return 44; /* SSHFP */
            }
            break;

        case 'T':
            switch (toupper(s[1])) {
                case 'A': return 32768; /* TA */;
                case 'X': return 16;  /* TXT */
                case 'Y': return atoi(s+4); /* TYPExx */
            }
            break;

        case 'U':
            switch (toupper(s[1])) {
                case 'I': 
                    switch (toupper(s[2])) {
                        case 'D': return 101; /* UID */
                        case 'N': return 100; /* UINFO */
                    }
                    break;

                case 'N': return 103; /* UNSPEC */
            }
            break;

        case 'W': return 11; /* WKS */
        case 'X': return 19; /* X25 */
    }

    return 0;
}

/* comparison function for use by qsort() */
int canonical_compare(const void* v1, const void* v2)
{
    char* s1 = *(char**)v1;
    char* s2 = *(char**)v2;

    int len1 = *(unsigned int*)s1;
    int len2 = *(unsigned int*)s2;

    int diff = memcmp(s1+12, s2+12, MIN(len1, len2));
    if (diff)
        return diff;
    return len1 - len2;
}

/* read and parse a zone file */
int read_file(char* filename,
              char* origin,
              char* default_ttl,
              char* dnskey_ttl,
              struct global_data* g)
{
    int infd = open(filename, O_RDONLY);
    if (-1 == infd) {
        perror(filename);
        return -2;
    }

    struct stat statbuf;
    if (fstat(infd, &statbuf)) {
        perror(filename);
        return -3;
    }

    void* buffer = mmap(NULL, statbuf.st_size,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE, infd, 0);
    close(infd);
    if (MAP_FAILED == buffer) {
        perror("mmap");
        return -4;
    }        

    int listlen = statbuf.st_size / 40; /* guesstimate line count */
    if (g->linecount + listlen > g->listsize) {
        /* we need to realloc the line array */
        while (g->listsize < g->linecount + listlen)
            g->listsize *= 2;

        g->lines = realloc(g->lines, g->listsize * sizeof(char*));
        if (!g->lines) {
            perror("lines realloc");
            exit(-1);
        }
        DEBUGF("Reallocated line list to %d lines\n", g->listsize);
    }

    /* skip over any leading dots */
    while (origin && *origin == '.')
        origin++;

    int currclass = 1; /* default class IN */
    char* currttl = 0;
    char* ttlmacro = 0;
    char* ptr = buffer;
    int linenumber = 1;
    char lastname[MAX_NAME_LEN];
    while (1) {
        /* terminate line */
        char* end = strchr(ptr, '\n');

        fprintf(stderr, "debug: quicksorter ptr is %s\n", ptr);
        if (!end)
            break; /* end of file */
        *end = 0;

        /* don't store comments or empty lines */
        if (*ptr == ';' || !*ptr)
            goto next_line;

        /* handle macros */
        if (*ptr == '$') {
            char* p = ptr;
            while (!isspace(*p))
                p++;
            while (isspace(*p))
                p++;

            switch (ptr[1]) {
                case 'I': {
                    if (memcmp(ptr+1,"INCLUDE",7))
                        break;
                    char* filename = p;
                    while (*p && !isspace(*p))
                        p++;
                    *p = 0; /* terminate filename */
                    p++;
                    while (*p && isspace(*p))
                        p++;

                    char* domain = NULL;
                    if (*p && *p != ';') {
                        domain = p;
                        while (*p && !isspace(*p))
                            p++;
                        *p = 0; /* terminate domain name */
                    }
                    read_file(filename, domain, default_ttl, dnskey_ttl, g);
                    goto next_line;
                }

                case 'O':
                    if (memcmp(ptr+1,"ORIGIN",6))
                        break;
                    origin = p;

                    /* skip over any leading dots */
                    while (*origin == '.')
                        origin++;
                    goto next_line;

                case 'T':
                    if (memcmp(ptr+1,"TTL",3))
                        break;
                    ttlmacro = p;
                    goto next_line;
            }
        }
        
        char* p = ptr;

        /*** join split lines ***/

        /* look for multi-line token */
        char* paren = p;
        while ((paren = strchr(paren, '('))) {
            /* was paren part of a quoted string? */
            if (!inside_string(ptr, paren))
                break;

            /* was paren in a comment? */
            char* comment = strchr(ptr, ';');
            if (comment && paren > comment) {
                /* paren was in a comment. ignore it. */
                *comment = 0;
                paren = NULL;
                break;
            }
            paren++;
        }
        if (paren) {
            *paren = ' ';
            p = paren;

            /* join lines until ')' */
            while (1) {
                /* find and remove comment */
                char* comment = strchr(p, ';');
                if (comment)
                    *comment = 0;

                /* look for closing paren */
                paren = strchr(p, ')');
                if (paren) {
                    *paren = 0;
                    break;
                }
                else {
                    /* no closing paren, connect next line */
                    if (comment)
                        memset(comment, ' ', end - comment + 1);
                    else
                        *end = ' ';
                }

                p = end + 1; /* go to next line */
                linenumber++;

                /* find end of line */
                end = strchr(p, '\n');
                if (!end) {
                    fprintf(stderr,"%s:%d: Unclosed parenthesis\n", filename, linenumber);
                    exit(-1);
                }
                *end = 0;
            }
        }
        else {
            /* strip end-of-line comment */
            char* ptr = p;
            char* comment;
            while ((comment = strchr(ptr, ';'))) {
                if (!inside_string(p, comment)) {
                    *comment = 0;
                    break;
                }
                ptr = comment + 1;
            }
        }


        /*** find ttl, class and type ***/

        char* name = lastname;
        char* ttl = NULL;
        int klass = 0;
        int rrtype = 0;

        /* check for name */
        p = ptr;
        if (!isspace(p[0])) {
            name = ptr;
            while (!isspace(*p))
                p++;
        }

        /* find out TTL and CLASS */
        while (1) {
            while(isspace(*p))
                p++;
            /* is this the ttl? */
            if (isdigit(*p))
                ttl = p;
            else  {
                /* is this the class? */
                klass = parse_rrclass(p);
                if (klass) {
                    currclass = klass;
                }
                else {
                    /* verify rr type */
                    rrtype = parse_rrtype(p);
                    switch (rrtype) {
                        case 46:
                        case 47:
                        case 50:
                        case 51:
                            /* strip this line */
                            goto next_line;

                        case 0:
                            fprintf(stderr,"%s:%d: Unknown RR: %s\n", filename, linenumber, p);
                            exit(-1);
                            break;
                    }
                    while (!isspace(*p))
                        p++;
                    while (isspace(*p))
                        p++;
                    break;
                }
            }
            /* skip past this field */
            while (!isspace(*p))
                p++;
        }

        /*** encode line to binary ***/

        /* name */
        if (name != lastname) {
            int i;
            for (i=0; name[i] && !isspace(name[i]); i++)
                lastname[i] = name[i];
            lastname[i] = 0;
        }

        /* ttl */
        if (!ttl) {
            if (currttl)
                ttl = currttl;
            else
                if (ttlmacro)
                    ttl = ttlmacro;
                else
                    ttl = default_ttl;
        }
        if (rrtype == 48 && dnskey_ttl)
            ttl = dnskey_ttl;

        if (!ttl) {
            fprintf(stderr,"%s:%d: No TTL\n", filename, linenumber);
            exit(-1);
        }

        /* class */
        if (!klass)
            klass = currclass;
        if (!klass) {
            fprintf(stderr,"%s:%d: No class\n", filename, linenumber);
            exit(-1);
        }

        unsigned int buf[MAX_LINE_LEN/sizeof(int)]; /* encourage int align */
        if (!rrtype) {
            fprintf(stderr,"No RR type!\n");
            exit(-1);
        }

        int len = encode_rr(name, rrtype, klass, ttl, p, (char*)buf, origin);
        char* rr = malloc(len);
        memcpy(rr, buf, len);

        /* add rr to array */
        g->lines[g->linecount++] = rr;
        if (g->linecount >= g->listsize) {
            g->listsize *= 2;
            g->lines = realloc(g->lines, g->listsize * sizeof(char*));
            if (!g->lines) {
                perror("lines realloc 2");
                return -8;
            }
            DEBUGF("Reallocated line list to %d lines\n", g->listsize);
        }

      next_line:
        ptr = end + 1; /* go to next line */
        linenumber++;
    }

    munmap(buffer, statbuf.st_size);
    
    return 0;
}

void init_global_data(struct global_data* g)
{
    g->linecount = 0;
    g->listsize = 1; /* will be realloc:ed by read_file() */
    g->lines = malloc(g->listsize * sizeof(char*));
    if (!g->lines) {
        perror("lines malloc");
        exit(-1);
    }
}

int main(int argc, char* argv[])
{
    const char* help =
        "usage: quicksorter -f INFILE -w OUTFILE [OPTIONS] \n"
        "options:\n"
        "-m <min>\tSOA minimum\n"
        "-t <ttl>\tDNSKEY TTL\n"
        "-o <origin>\tZone origin\n";

    char* default_ttl = NULL;
    char* dnskey_ttl = NULL;
    char* infile = NULL;
    char* outfile = NULL;
    char* origin = NULL;
    int c;
    while ((c = getopt(argc, argv, "f:w:m:o:t:")) != -1) {
        switch (c) {
            case 'f':
                infile = optarg;
                break;

            case 'w':
                outfile = optarg;
                break;

            case 'm':
                default_ttl = optarg;
                break;

            case 'o':
                origin = optarg;
                break;

            case 't':
                dnskey_ttl = optarg;
                break;
        }
    }

    if (!infile || !outfile) {
        fprintf(stderr, "%s\n", help);
        return -1;
    }

    /* check that origin ends with a dot */
    if (origin && origin[strlen(origin) - 1] != '.') {
        fprintf(stderr, "Error: The supplied origin must be an absolute name (end with a .)\n");
        exit(-1);
    }


    /* set locale to C, to avoid national quirks */
    setlocale(LC_CTYPE, "C");

    struct global_data g;
    init_global_data(&g);

    read_file(infile, origin, default_ttl, dnskey_ttl, &g);
#ifdef DEBUG
    int start = times(NULL);
    printf("Read took %d ticks\n", times(NULL) - start);
    start = times(NULL);
#endif

    qsort(g.lines, g.linecount, sizeof (char*), canonical_compare);

#ifdef DEBUG
    int ticks = times(NULL) - start;
    printf("Sort took %d ticks\n", ticks);
    start = times(NULL);
#endif

    int i;
    char buf[MAX_LINE_LEN];

    FILE* outf = fopen(outfile, "w");
    if (!outf) {
        perror(outfile);
        return -5;
    }

    for (i=0; i<g.linecount; i++) {
        int len = decode_rr(g.lines[i], buf);
        fwrite(buf, 1, len, outf);
    }
    fclose(outf);

#ifdef DEBUG
    printf("Write took %d ticks\n", times(NULL) - start);
#endif

    /* free all data */
    for (i=0; i<g.linecount; i++)
        free(g.lines[i]);
    free(g.lines);
    
    return 0;
}
