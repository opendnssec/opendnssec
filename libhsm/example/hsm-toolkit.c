/*
 * $Id: hsm-toolkit.c 406 2009-04-08 13:53:37Z roy $
 *
 * Copyright (c) 2009 Nominet UK.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "libhsm.h"

int
main (int argc, char *argv[])
{
    char *pin = 0;                         // NO DEFAULT VALUE
    int slot = 0;                          // default value
    long keysize = 1024;                      // default value
    uuid_t uuid;
    int Action  = 0;
    int opt;
    char *pklib = 0;
    while ((opt = getopt (argc, argv, "GDb:l:p:s:h")) != -1) {
        switch (opt) {
            case 'G': Action = 1; break;
            case 'D': Action = 2; break;
            case 'b': keysize = atoi (optarg); break;
            case 'l': pklib = optarg; break;
            case 'p': pin = optarg; break;
            case 's': slot = atoi (optarg); break;
            case 'h': fprintf(stderr, "usage: hsm-toolkit -l pkcs11-library [-s slot] [-p pin] [-G [-b keysize]] [-D UUID-string]\n");
					  exit(2);		
		}
   	}
    if (!pklib) {
		fprintf (stderr, "Please specify a pkcs11 library.\n");
		exit(1);
	}

  PK_LinkLib(pklib);
  PK_Startup(slot, pin);
    switch (Action) {
        case 1: PK_GenerateObject(keysize); break;
        case 2: if (uuid_parse(argv[optind],uuid)) {
					fprintf (stderr, "argument %s is not a valid UUID string\n", argv[optind]);
					exit(1);
				}
				PK_RemoveObject(uuid); break;
        default:
            PK_ListObjects();
    }
    PK_Shutdown();
    PK_UnlinkLib();
    exit (0);
}
