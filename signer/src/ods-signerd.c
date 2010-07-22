/*
 * $Id$
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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
 * OpenDNSSEC signer engine daemon.
 *
 */

#include "config.h"
#include "daemon/engine.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * Prints usage.
 *
 */
static void
usage(FILE* out)
{
    fprintf(out, "Usage: %s [OPTIONS]\n", PACKAGE_TARNAME);
    fprintf(out, "Start the OpenDNSSEC signer engine daemon.\n\n");
    fprintf(out, "Supported options:\n");
    fprintf(out, " -c | --config <cfgfile> Read configuration from file.\n");
    fprintf(out, " -d | --no-daemon        Do not daemonize the signer "
                 "engine.\n");
    fprintf(out, " -h | --help             Show this help and exit.\n");
    fprintf(out, " -i | --info             Print configuration and exit.\n");
    fprintf(out, " -v | --verbose          Increase verbosity.\n");
    fprintf(out, "\nBSD licensed, see LICENSE in source package for "
                 "details.\n");
    fprintf(out, "Version %s. Report bugs to <%s>.\n",
        PACKAGE_VERSION, PACKAGE_BUGREPORT);
}


/**
 * Main. start engine and run it.
 *
 */
int
main(int argc, char* argv[])
{
    int c;
    int options_index = 0;
    int info = 0;
    int single_run = 0;
    int daemonize = 1;
    int cmdline_verbosity = 0;
    const char* cfgfile = ODS_SE_CFGFILE;
    static struct option long_options[] = {
        {"single-run", no_argument, 0, '1'},
        {"config", required_argument, 0, 'c'},
        {"no-daemon", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {"info", no_argument, 0, 'i'},
        {"verbose", no_argument, 0, 'v'},
        { 0, 0, 0, 0}
    };

    /* parse the commandline */
    while ((c=getopt_long(argc, argv, "1c:dhiv",
        long_options, &options_index)) != -1) {
        switch (c) {
            case '1':
                single_run = 1;
                break;
            case 'd':
                daemonize = 0;
                break;
            case 'h':
                usage(stdout);
                exit(0);
                break;
            case 'i':
                info = 1;
                break;
            case 'v':
                cmdline_verbosity++;
                break;
            /* version */
            default:
                usage(stderr);
                exit(2);
                break;
        }
    }
    argc -= optind;
    argv += optind;
    if (argc != 0) {
        usage(stderr);
        exit(2);
    }

#ifdef ENFORCER_TIMESHIFT
    fprintf(stdout, "DEBUG: timeshift mode enabled...\n");
    if (getenv("ENFORCER_TIMESHIFT")) {
        fprintf(stdout, "WARNING: timeshift %s detected, running once only\n",
            getenv("ENFORCER_TIMESHIFT"));
        single_run = 1;
    } else {
        fprintf(stdout, "DEBUG: timeshift mode not set: %s\n",
            getenv("ENFORCER_TIMESHIFT"));
    }
#endif /* ENFORCER_TIMESHIFT */


    /* main stuff */
    fprintf(stdout, "OpenDNSSEC signer engine version %s\n", PACKAGE_VERSION);
    engine_start(cfgfile, cmdline_verbosity, daemonize, info, single_run);

    /* done */
    return 0;
}
