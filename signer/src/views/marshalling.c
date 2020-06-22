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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <ldns/ldns.h>
#include "proto.h"

enum marshall_mode { COPY, FREE, READ, WRITE, PRINT, COUNT };
enum marshall_func { BASIC, OBJECT, SELF };

int optionaldummy;
int* marshall_OPTIONAL = &optionaldummy;

struct marshall_struct {
    enum marshall_mode mode;
    int fd;
    FILE* fp;
    int indentincr;
    int indentlvl;
    int indentcount;
};

marshall_handle
marshallcreate(enum marshall_method method, ...)
{
    va_list ap;
    marshall_handle h, old;
    h = malloc(sizeof(struct marshall_struct));
    h->fd = -1;
    h->fp = NULL;
    va_start(ap, method);
    switch(method) {
        case marshall_INPUT:
            h->mode = READ;
            h->fd = va_arg(ap, int);
            break;
        case marshall_OUTPUT:
            h->mode = WRITE;
            h->fd = va_arg(ap, int);
            break;
        case marshall_PRINT:
            h->mode = PRINT;
            h->fp = va_arg(ap, FILE*);
            break;
        case marshall_APPEND:
            h->mode = WRITE;
            old = va_arg(ap, marshall_handle);
            h->fd = old->fd;
            h->fp = old->fp;
            old->fd = -1;
            old->fp = NULL;
            break;
        case marshall_FREE:
            h->mode = FREE;
            break;
    }
    va_end(ap);
    h->indentlvl = 0;
    h->indentincr = 2;
    h->indentcount = 0;
    return h;
}

void
marshallclose(marshall_handle h)
{
    if(!h)
        return;
    if (h->fp && h->fp != stdout && h->fp != stderr) {
        fclose(h->fp);
    }
    if (h->fd >= 0) {
        close(h->fd);
    }
    free(h);
}

int
marshallself(marshall_handle h, void* member)
{
    (void)h;
    (void)member;
    return 0;
}

int
marshallinteger(marshall_handle h, void* member)
{
    int size = 0;
    switch(h->mode) {
        case COPY:
            break;
        case FREE:
            break;
        case READ:
            size = read(h->fd, member, sizeof(int));
            assert(size==sizeof(int));
            break;
        case WRITE:
            size = write(h->fd, member, sizeof(int));
            assert(size==sizeof(int));
            break;
        case COUNT:
            abort(); // FIXME
            break;
        case PRINT:
            size = fprintf(h->fp, "%d", *(int*)member);
            break;
        default:
            abort(); // FIXME
    }
    return size;
}

int
marshallint64(marshall_handle h, void* member)
{
    int size = 0;
    switch(h->mode) {
        case COPY:
            break;
        case FREE:
            break;
        case READ:
            size = read(h->fd, member, sizeof(int64_t));
            assert(size==sizeof(int64_t));
            break;
        case WRITE:
            size = write(h->fd, member, sizeof(int64_t));
            assert(size==sizeof(int64_t));
            break;
        case COUNT:
            abort(); // FIXME
            break;
        case PRINT:
            size = fprintf(h->fp, "%ld", *(int64_t*)member);
            break;
        default:
            abort(); // FIXME
    }
    return size;
}

int
marshallbyte(marshall_handle h, void* member)
{
    int size = 0;
    switch(h->mode) {
        case COPY:
            break;
        case FREE:
            break;
        case READ:
            size = read(h->fd, member, 1);
            break;
        case WRITE:
            size = write(h->fd, member, 1);
            break;
        case COUNT:
            break;
        case PRINT:
            size = fprintf(h->fp, "%c", *(unsigned char*)member);
            break;
    }
    return size;
}

int
marshallstring(marshall_handle h, void* member)
{
    int size = 0;
    int len;
    char** str = member;
    switch(h->mode) {
        case COPY:
            *str = strdup(*str);
            size = strlen(*str);
            break;
        case FREE:
            free(*str);
            break;
        case READ:
            size = marshallinteger(h, &len);
            if(len >= 0) {
                *str = malloc(len + 1);
                read(h->fd, *str, sizeof(char)*len);
                (*str)[len] = '\0';
                size += len;
            } else {
                *str = NULL;
            }
            break;
        case WRITE:
            if(*str) {
                len = strlen(*str);
                size = marshallinteger(h, &len);
                write(h->fd, *str, sizeof(char)*len);
                size += len;
            } else {
                len = -1;
                size = marshallinteger(h, &len);
            }
            break;
        case COUNT:
            if(*str) {
                len = strlen(*str);
            } else {
                len = -1;
            }
            size = marshallinteger(h, &len);
            size += len;
            break;
        case PRINT:
            if(*str) {
                size = fprintf(h->fp, "\"%s\"", *str);
            } else {
                size = fprintf(h->fp, "NULL");
            }
            break;
        default:
            size = -1;
    }
    return size;
}

int
marshallstringarray(marshall_handle h, void* member)
{
    return marshallstring(h, (void*)member);
}

int
marshallldnsrr(marshall_handle h, void* member)
{
    ldns_rr** rr = (ldns_rr**)member;
    int size = 0;
    int len;
    char* str;
    switch(h->mode) {
        case COPY:
            *rr = ldns_rr_clone(*rr);
            break;
        case FREE:
            ldns_rr_free(*rr);
            break;
        case READ:
            size = marshallinteger(h, &len);
            if(len >= 0) {
                str = malloc(len + 1);
                read(h->fd, str, sizeof(char)*len);
                str[len] = '\0';
                size += len;
                ldns_rr_new_frm_str(rr, str, 0, NULL, NULL);
            } else {
                *rr = NULL;
            }
            break;
        case WRITE:
            if(*rr) {
                str = ldns_rr2str(*rr);
                len = strlen(str);
                size = marshallinteger(h, &len);
                write(h->fd, str, sizeof(char)*len);
                size += len;
                free(str);
            } else {
                len = -1;
                size = marshallinteger(h, &len);
            }
            break;
        case COUNT:
            if(*rr) {
                str = ldns_rr2str(*rr);
                len = strlen(str);
                free(str);
            } else {
                len = -1;
            }
            size = marshallinteger(h, &len);
            size += len;
            break;
        case PRINT:
            if(*rr) {
                str = ldns_rr2str(*rr);
                len = (int)strlen(str)-1;
                if(len > 40)
                    len = 40;
                size = fprintf(h->fp, "\"%*.*s\"", len, len, str);
                free(str);
            } else {
                size = fprintf(h->fp, "NULL");
            }
            break;
        default:
            size = -1;
    }
    return size;
}

int
marshallsigs(marshall_handle h, void* member)
{
    struct signatures_struct* signatures = (struct signatures_struct*)member;
    int i, size;
    size = marshalling(h, "sigs", &(signatures->sigs), &(signatures->nsigs), sizeof(struct signatures_struct), marshallself);
    for(i=0; i<signatures->nsigs; i++) {
        size += marshalling(h, "rr", &(signatures->sigs[i].rr), NULL, 0, marshallldnsrr);
        size += marshalling(h, "keylocator", &(signatures->sigs[i].keylocator), NULL, 0, marshallstring);
        size += marshalling(h, "keyflags", &(signatures->sigs[i].keyflags), NULL, 0, marshallinteger);
        size += marshalling(h, NULL, NULL, &(signatures->nsigs), i, marshallself);
    }
    return size;
}

enum marshall_func
marshallfunc(int (*memberfunction)(marshall_handle,void*))
{
    if(memberfunction == NULL || memberfunction == marshallself) {
        return SELF;
    } else if(memberfunction == marshallinteger || memberfunction == marshallstring || memberfunction == marshallstringarray || memberfunction == marshallldnsrr) {
        return BASIC;
    } else {
        return OBJECT;
    }
}

int
marshalling(marshall_handle h, const char* name, void* members, int *membercount, size_t membersize, int (*memberfunction)(marshall_handle,void*))
{
    char* array;
    char* dest;
    int size = 0;
    int len, i;
    int optional;
    if(membercount == marshall_OPTIONAL) {
        membercount = &optional;
        if(h->mode != READ)
            optional = (*(void**)members ? 1 : 0);
    }
    switch(h->mode) {
        case COPY:
            if(membercount) {
                size = *membercount * membersize;
                array = malloc(size);
                memcpy(array, *(char**)members, size);
                *(char**)members = array;
                if(memberfunction != NULL && memberfunction != marshallself) {
                    for(i=0; i<*membercount; i++) {
                        memberfunction(h, &(array[i*membersize]));
                    }
                }
            } else if(members) {
                size = 0;
                memberfunction(h, members);
            }
            break;
        case FREE:
            if(name != NULL) {
                if(membercount) {
                    if(memberfunction != NULL && memberfunction != marshallself) {
                        dest = *(char**) members;
                        for(i=0; i<*membercount; i++) {
                            memberfunction(h, &(dest[i*membersize]));
                        }
                    }
                    free(*(char**)members);
                } else {
                    memberfunction(h, members);
                    //free(membersize);
                }
            }
            break;
        case READ:
            if(name != NULL) {
                if(membercount) {
                    size = marshallinteger(h, membercount);
                    if(*membercount >= 0) {
                        array = malloc(*membercount * membersize);
                        *(char**)members = array;
                        dest = (char*) array;
                        if(memberfunction != NULL && memberfunction != marshallself) {
                            for(i=0; i<*membercount; i++) {
                                size += memberfunction(h, &(dest[i*membersize]));
                            }
                        }
                    } else {
                        *(char**)members = NULL;
                    }
                } else {
                    size = memberfunction(h, members);
                }
            }
            break;
        case WRITE:
        case COUNT:
            if(name != NULL) {
                if(membercount) {
                    dest = *(char**) members;
                    if(dest) {
                        size = marshallinteger(h, membercount);
                        if(memberfunction != NULL && memberfunction != marshallself) {
                            for(i=0; i<*membercount; i++) {
                                size += memberfunction(h, &(dest[i*membersize]));
                            }
                        }
                    } else {
                        len = -1;
                        size = marshallinteger(h, &len);
                    }
                } else if(members) {
                    size = memberfunction(h, members);
                }
            }
            break;
        case PRINT:
            if (name == NULL) {
                h->indentlvl -= h->indentincr;
                if (membercount != NULL) {
                    if (membersize + 1 < (size_t)*membercount) {
                        size = fprintf(h->fp, "%*.*s} , {\n", h->indentlvl, h->indentlvl, "");
                        h->indentlvl += h->indentincr;
                    } else {
                        size = fprintf(h->fp, "%*.*s} ],\n", h->indentlvl, h->indentlvl, "");
                        if(marshallfunc(memberfunction) == SELF)
                            h->indentlvl -= 2 * h->indentincr;
                        else
                            h->indentlvl -= h->indentincr;
                    }
                } else {
                    size = fprintf(h->fp, "%*.*s}\n", h->indentlvl, h->indentlvl, "");
                    h->indentlvl -= h->indentincr;
                }
            } else if (membercount && *membercount == 0) {
                if(membercount != &optional) {
                    size = fprintf(h->fp, "%*.*s%s = [ ],\n", h->indentlvl, h->indentlvl, "", name);
                }
            } else {
                dest = (char*) members;
                switch (marshallfunc(memberfunction)) {
                    case SELF:
                        if (membercount == NULL) {
                            size = fprintf(h->fp, "%*.*s%s = {\n", h->indentlvl, h->indentlvl, "", name);
                            h->indentlvl += h->indentincr * 2;
                        } else if(*membercount > 0) {
                            size = fprintf(h->fp, "%*.*s%s = [ {\n", h->indentlvl, h->indentlvl, "", name);
                            h->indentlvl += h->indentincr * 2;
                        } else {
                            size = fprintf(h->fp, "%*.*s%s = [ ],\n", h->indentlvl, h->indentlvl, "", name);
                        }
                        break;
                    case BASIC:
                        if (membercount == NULL) {
                            size = fprintf(h->fp, "%*.*s%s = ", h->indentlvl, h->indentlvl, "", name);
                            memberfunction(h, dest);
                            size += fprintf(h->fp, ",\n");
                        } else if (membercount == &optional) {
                            size = fprintf(h->fp, "%*.*s%s = ", h->indentlvl, h->indentlvl, "", name);
                            memberfunction(h, &((*(char**)dest)[0]));
                            size += fprintf(h->fp, ",\n");
                        } else {
                            size = fprintf(h->fp, "%*.*s%s = [ ", h->indentlvl, h->indentlvl, "", name);
                            for (i = 0; i<*membercount; i++) {
                                memberfunction(h, &((*(char**)dest)[i * membersize]));
                                size += fprintf(h->fp, ", ");
                            }
                            size += fprintf(h->fp, "],\n");
                        }
                        break;
                    case OBJECT:
                        if (membercount == NULL) {
                            if(dest != NULL) {
                                size = fprintf(h->fp, "%*.*s%s = {\n", h->indentlvl, h->indentlvl, "", name);
                                h->indentlvl += h->indentincr * 2;
                                memberfunction(h, dest);
                                h->indentlvl -= h->indentincr;
                                size += fprintf(h->fp, "%*.*s},\n", h->indentlvl, h->indentlvl, "");
                                h->indentlvl -= h->indentincr;
                            }
                        } else if (membercount == &optional) {
                            size = fprintf(h->fp, "%*.*s%s = {\n", h->indentlvl, h->indentlvl, "", name);
                            h->indentlvl += h->indentincr;
                            h->indentlvl += h->indentincr;
                            memberfunction(h, &((*(char**)dest)[0]));
                            h->indentlvl -= h->indentincr;
                            size = fprintf(h->fp, "%*.*s},\n", h->indentlvl, h->indentlvl, "");
                            h->indentlvl -= h->indentincr;
                        } else {
                            size = fprintf(h->fp, "%*.*s%s = [ {\n", h->indentlvl, h->indentlvl, "", name);
                            h->indentlvl += h->indentincr;
                            for (i = 0; i<*membercount; i++) {
                                h->indentlvl += h->indentincr;
                                memberfunction(h, &(dest[i * membersize]));
                                h->indentlvl -= h->indentincr;
                                if (i + 1 < *membercount) {
                                    size += fprintf(h->fp, "%*.*s}, {\n", h->indentlvl, h->indentlvl, "");
                                }
                            }
                            size = fprintf(h->fp, "%*.*s} ],\n", h->indentlvl, h->indentlvl, "");
                            h->indentlvl -= h->indentincr;
                        }
                        break;
                    default:
                        size = -1;
                }
            }
            break;
        default:
            return -1;
    }
    return size;
}
