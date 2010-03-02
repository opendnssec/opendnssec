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
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "config.h"
#include "eppconfig.h"

void send(int fd, char* string)
{
    write(fd, string, strlen(string));
}


void push_keys(int argc, char** argv)
{
    char* pipename = config_value("/eppclient/pipe");
    int fd = open(pipename, O_RDWR);
    if (fd < 0) {
        perror(pipename);
        exit(-1);
    }

    send(fd, "NEWKEYS ");
    send(fd, argv[1]);
    send(fd, " ");

    for (int i=2; i<argc; i++) {
        send(fd, "\"");
        send(fd, argv[i]);
        send(fd, "\" ");
    }
    send(fd, "\n");
    close(fd);
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        printf("usage: %s [zone] [keys] ...\n", argv[0]);
        return -1;
    }

    if (argv[1][strlen(argv[1])-1] == '.') {
        printf("Zone must not end with '.'\n");
        return -1;
    }
    
    read_config();
    push_keys(argc, argv);

    return 0;
}
