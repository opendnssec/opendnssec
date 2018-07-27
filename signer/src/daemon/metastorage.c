/*
 * Copyright (c) 2018 NLNet Labs. All rights reserved.
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

#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include "utilities.h"
#include "views/marshalling.h"
#include "views/proto.h"
#include "signer/zone.h"

#pragma GCC optimize ("O0")

struct definition_struct {
    const char *membercode;
    size_t membersize;
    int (*memberfunction)(marshall_handle,void*);
    const char* (*membername)(void*);
};

static int
zonemarshall(marshall_handle h, void* ptr)
{
    zone_type* d = *(zone_type**) ptr;
    int size = 0;
    size += marshalling(h, "name", &(d->name), NULL, 0, marshallstring);
    size += marshalling(h, "nextserial", &(d->nextserial), marshall_OPTIONAL, sizeof(int), marshallinteger);
    size += marshalling(h, "inboundserial", &(d->inboundserial), marshall_OPTIONAL, sizeof(int), marshallinteger);
    size += marshalling(h, "outboundserial", &(d->outboundserial), marshall_OPTIONAL, sizeof(int), marshallinteger);
    return size;
}

static const char*
zonename(void* ptr)
{
    zone_type* d = ptr;
    return d->name;
}

int
metastorage(const char* filename, int ndefs, struct definition_struct* defs, const char* name, void* item)
{
    int basefd = AT_FDCWD;
    int rdfd;
    int wrfd;
    off_t offset;
    off_t size;
    ssize_t count;
    struct definition_struct* rddef = &defs[0];
    struct definition_struct* wrdef = &defs[0];
    size_t filenamelen;
    char* tmpfilename;
    marshall_handle rdhandle = NULL;
    marshall_handle wrhandle = NULL;
    marshall_handle freehandle = NULL;
    void* ptr;
    char buffer[8];

    freehandle = marshallcreate(marshall_FREE);
    //basefd = open(directory,O_DIRECTORY,0);
    for(;;) {
        if(name!=NULL) {
            rdfd = openat(basefd,filename,O_RDONLY,0666);
        } else {
            rdfd = openat(basefd,filename,O_RDWR,0666);
        }
        if(rdfd < 0 && errno == ENOENT) {
            wrfd = openat(basefd,filename,O_WRONLY|O_CREAT|O_EXCL,0666);
            if(wrfd < 0 || errno == EEXIST) {
                continue;
            } else if(wrfd < 0) {
                abort(); // FIXME
                return -1;
            } else {
                if(lockf(wrfd,F_LOCK,0)) {
                    abort(); // FIXME
                }
                break;
            }
        } else if(rdfd < 0) {
            abort(); // FIXME
            return -1;
        } else {
            if(name==NULL) {
                if(lockf(rdfd,F_LOCK,0)) {
                    fprintf(stderr,"operation failed %s (%d) %d\n",strerror(errno),errno,rdfd);
                    //abort(); // FIXME
                    //return -1;
                }
            }
            wrfd = -1;
            break;
        }
    }
    if(rdfd >= 0) {
        size = lseek(rdfd,0,SEEK_END);
        offset = lseek(rdfd,0,SEEK_SET);
        count = read(rdfd,&buffer,sizeof(buffer));
        if(count != sizeof(buffer)) {
            abort();
        }
        if(memcmp(buffer,"\0ODS-M1\n",sizeof(buffer))) {
            abort(); // FIXME
        }
    }
    filenamelen = strlen(filename);
    tmpfilename = malloc(filenamelen+2);
    memcpy(tmpfilename,filename,filenamelen);
    tmpfilename[filenamelen+0] = '~';
    tmpfilename[filenamelen+1] = '\0';
    if(wrfd < 0 && name == NULL) {
        wrfd = openat(basefd,tmpfilename,O_WRONLY|O_CREAT|O_TRUNC,0666);
        if(wrfd < 0) {
            abort(); // FIXME
        }
    }
    if(wrfd >= 0) {
        memset(buffer,'\0',8);
        memcpy(buffer,wrdef->membercode,8);
        count = write(wrfd,buffer,8);
        if(count != 8) {
            abort(); // FIXME
        }
        wrhandle = marshallcreate(marshall_OUTPUT, wrfd);
    }

    if(rdfd >= 0) {
        rdhandle = marshallcreate(marshall_INPUT, rdfd);
        ptr = malloc(wrdef->membersize);
        do {
            offset = lseek(rdfd,0,SEEK_CUR);
            if(offset < size) {
                marshalling(rdhandle, "", &ptr, NULL, rddef->membersize, rddef->memberfunction);
                if(wrfd>=0) {
                    if(strcmp(wrdef->membername(item), rddef->membername(ptr))) {
                        marshalling(wrhandle, wrdef->membername(ptr), &ptr, NULL, wrdef->membersize, wrdef->memberfunction);
                    }
                }
                if(name != NULL && !strcmp(name, rddef->membername(ptr))) {
                    memcpy(item, ptr, wrdef->membersize); 
                } else {
                    marshalling(freehandle, "", &ptr, NULL, wrdef->membersize, wrdef->memberfunction);
                }
            }
        } while(offset < size);
        free(ptr);
    }
    if(wrfd>=0 && name==NULL) {
        marshalling(wrhandle, wrdef->membername(item), &item, NULL, wrdef->membersize, wrdef->memberfunction);
    }

    marshallclose(freehandle);
    if(rdfd >= 0)
        marshallclose(rdhandle);
    if(wrfd >= 0)
        marshallclose(wrhandle);
    if(wrfd >= 0) {
        close(wrfd);
        if(rdfd >=0) {
            renameat(basefd,tmpfilename,basefd,filename);
        }
    }
    lockf(rdfd,F_UNLCK,0);
    close(rdfd);
    return 0;
}

static int ndefs = 0;
static struct definition_struct* defs = NULL;

static void
setup(void)
{
    if(ndefs!=0)
        return;
    ndefs = 1;
    defs = malloc(sizeof(struct definition_struct)*ndefs);
    defs[0].membercode = "\0ODS-M1\n";
    defs[0].membersize = sizeof(struct zone_struct);
    defs[0].memberfunction = zonemarshall;
    defs[0].membername = zonename;
}

int
metastorageget(const char* name, void* item)
{
    setup();
    return metastorage("signer.db", ndefs, defs, name, item);
}

int
metastorageput(void* item)
{
    setup();
    return metastorage("signer.db", ndefs, defs, NULL, item);
}
