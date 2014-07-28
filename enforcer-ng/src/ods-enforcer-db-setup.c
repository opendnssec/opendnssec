/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2014 OpenDNSSEC AB (svb)
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
 *
 */

/**
 * OpenDNSSEC enforcer database setup tool.
 */

#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "shared/log.h"
#if defined(ENFORCER_DATABASE_SQLITE3)
#include "db/db_schema_sqlite.h"
#endif
#if defined(ENFORCER_DATABASE_COUCHDB)
#include "db/db_schema_couchdb.h"
#endif

#define AUTHOR_NAME "Jerry Lundström"
#define COPYRIGHT_STR "Copyright (c) 2014 .SE (The Internet Infrastructure Foundation) OpenDNSSEC"

static void usage(FILE* out) {
    fprintf(out,
        "\nBSD licensed, see LICENSE in source package for details.\n"
        "Version %s. Report bugs to <%s>.\n",
        PACKAGE_VERSION,
        PACKAGE_BUGREPORT);
}

static void version(FILE* out) {
    fprintf(out,
        "Database setup tool for %s version %s\n"
        "Written by %s.\n\n"
        "%s.  This is free software.\n"
        "See source files for more license information\n",
        PACKAGE_NAME,
        PACKAGE_VERSION,
        AUTHOR_NAME,
        COPYRIGHT_STR);
    exit(0);
}

int main(int argc, char* argv[]) {
    int c, options_index = 0;
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        { 0, 0, 0, 0}
    };
    
    ods_log_init(NULL, 0, 0);
    
    while ((c=getopt_long(argc, argv, "hV",
        long_options, &options_index)) != -1) {
        switch (c) {
            case 'h':
                usage(stdout);
                exit(0);
            case 'V':
                version(stdout);
                exit(0);
            default:
                exit(100);
        }
    }

    return 0;
}
