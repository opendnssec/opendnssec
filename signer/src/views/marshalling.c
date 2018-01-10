#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "proto.h"

#pragma GCC optimize ("O0")

enum marshall_mode { marshall_COPY, marshall_READ, marshall_WRITE, marshall_PRINT, marshall_COUNT };
enum marshall_func { marshall_BASIC, marshall_OBJECT, marshall_SELF };

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

static marshall_handle
marshallcreate(enum marshall_mode mode, int fd, FILE *fp)
{
    marshall_handle h;
    h = malloc(sizeof(struct marshall_struct));
    h->mode = mode;
    h->fd = fd;
    h->fp = fp;
    h->indentlvl = 0;
    h->indentincr = 2;
    h->indentcount = 0;
    return h;
}

marshall_handle
marshallcopy(int fd)
{
    return marshallcreate(marshall_COPY, fd, NULL);
}

marshall_handle
marshallinput(int fd)
{
    return marshallcreate(marshall_READ, fd, NULL);
}

marshall_handle
marshalloutput(int fd)
{
    return marshallcreate(marshall_WRITE, fd, NULL);
}

marshall_handle
marshallprint(FILE* fp)
{
    return marshallcreate(marshall_PRINT, 0, fp);
}

void
marshallclose(marshall_handle h)
{
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
    int size;
    switch(h->mode) {
        case marshall_COPY:
        abort();
            break;
        case marshall_READ:
            size = read(h->fd, member, sizeof(int));
            assert(size==sizeof(int));
            break;
        case marshall_WRITE:
            size = write(h->fd, member, sizeof(int));
            assert(size==sizeof(int));
            break;
        case marshall_COUNT:
            abort();
            break;
        case marshall_PRINT:
            size = fprintf(h->fp, "%d", *(int*)member);
            break;
        default:
            abort();
    }
    return size;
}

int
marshallbyte(marshall_handle h, void* member)
{
    int size;
    switch(h->mode) {
        case marshall_COPY:
            break;
        case marshall_READ:
            size = read(h->fd, member, 1);
            break;
        case marshall_WRITE:
            size = write(h->fd, member, 1);
            break;
        case marshall_COUNT:
            break;
        case marshall_PRINT:
            size = fprintf(h->fp, "%c", *(unsigned char*)member);
            break;
    }
    return size;
}

int
marshallstring(marshall_handle h, void* member)
{
    int size;
    int len;
    char** str = member;
    switch(h->mode) {
        case marshall_COPY:
            *str = strdup(*str);
            size = strlen(*str);
            break;
        case marshall_READ:
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
        case marshall_WRITE:
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
        case marshall_COUNT:
            if(*str) {
                len = strlen(*str);
            } else {
                len = -1;
            }
            size = marshallinteger(h, &len);
            size += len;
            break;
        case marshall_PRINT:
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

enum marshall_func
marshallfunc(int (*memberfunction)(marshall_handle,void*))
{
    if(memberfunction == NULL || memberfunction == marshallself) {
        return marshall_SELF;
    } else if(memberfunction == marshallinteger || memberfunction == marshallstring || memberfunction == marshallstringarray) {
        return marshall_BASIC;
    } else {
        return marshall_OBJECT;
    }
}

int
marshalling(marshall_handle h, char* name, void* members, int *membercount, size_t membersize, int (*memberfunction)(marshall_handle,void*))
{
    char* array;
    char* dest;
    int len, i, size;
    int optional;
    if(membercount == marshall_OPTIONAL) {
        membercount = &optional;
        if(h->mode != marshall_READ)
            optional = (*(void**)members ? 1 : 0);
    }
    switch(h->mode) {
        case marshall_COPY:
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
        case marshall_READ:
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
        case marshall_WRITE:
        case marshall_COUNT:
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
        case marshall_PRINT:
            if (name == NULL) {
                h->indentlvl -= h->indentincr;
                if (membercount != NULL) {
                    if (membersize + 1 < (size_t)*membercount) {
                        size = fprintf(h->fp, "%*.*s} , {\n", h->indentlvl, h->indentlvl, "");
                        h->indentlvl += h->indentincr;
                    } else {
                         size = fprintf(h->fp, "%*.*s} ],\n", h->indentlvl, h->indentlvl, "");
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
                    case marshall_SELF:
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
                    case marshall_BASIC:
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
                    case marshall_OBJECT:
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
                            memberfunction(h, &(dest[0]));
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
