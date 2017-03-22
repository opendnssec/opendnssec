/*
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
#include "locks.h"
#include "daemon/engine.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include "parser/confparser.h"


#define AUTHOR_NAME "Matthijs Mekking"
#define COPYRIGHT_STR "Copyright (C) 2008-2010 NLnet Labs OpenDNSSEC"

static engine_type* engine;

/**
 * Prints usage.
 *
 */
static void
usage(FILE* out)
{
    fprintf(out, "Usage: %s [OPTIONS]\n", "ods-signerd");
    fprintf(out, "Start the OpenDNSSEC signer engine daemon.\n\n");
    fprintf(out, "Supported options:\n");
    fprintf(out, " -c | --config <cfgfile> Read configuration from file.\n");
    fprintf(out, " -d | --no-daemon        Do not daemonize the signer "
                 "engine.\n");
    fprintf(out, " -1 | --single-run       Run once, then exit.\n");
    fprintf(out, " -h | --help             Show this help and exit.\n");
    fprintf(out, " -i | --info             Print configuration and exit.\n");
    fprintf(out, " -v | --verbose          Increase verbosity.\n");
    fprintf(out, " -V | --version          Show version and exit.\n");
    fprintf(out, "\nBSD licensed, see LICENSE in source package for "
                 "details.\n");
    fprintf(out, "Version %s. Report bugs to <%s>.\n",
        PACKAGE_VERSION, PACKAGE_BUGREPORT);
}


/**
 * Prints version.
 *
 */
static void
version(FILE* out)
{
    fprintf(out, "%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
    fprintf(out, "Written by %s.\n\n", AUTHOR_NAME);
    fprintf(out, "%s.  This is free software.\n", COPYRIGHT_STR);
    fprintf(out, "See source files for more license information\n");
    exit(0);
}

static void
program_setup(const char* cfgfile, int cmdline_verbosity)
{
    const char* file = NULL;
    /* open log */
    file = parse_conf_log_filename(cfgfile);
    ods_log_init("ods-signerd", parse_conf_use_syslog(cfgfile), file, cmdline_verbosity?cmdline_verbosity:parse_conf_verbosity(cfgfile));

    ods_log_verbose("[engine] starting signer");

    /* initialize */
    xmlInitGlobals();
    xmlInitParser();
    xmlInitThreads();

    tzset(); /* for portability */
    free((void*)file);
}

static void
program_teardown()
{
    xmlCleanupParser();
    xmlCleanupGlobals();
    ods_log_close();
}

/**
 * Main. start engine and run it.
 *
 */
int
main(int argc, char* argv[])
{
    char* argv0;
    int c, returncode;
    int options_index = 0;
    int daemonize = 1;
    int cmdline_verbosity = 0;
    char *time_arg = NULL;
    const char* cfgfile = ODS_SE_CFGFILE;
    int linkfd;
    ods_status status;
    static struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {"no-daemon", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"set-time", required_argument, 0, 256},
        { 0, 0, 0, 0}
    };

    if(argv[0][0] != '/') {
        char *path = getcwd(NULL,0);
        asprintf(&argv0, "%s/%s", path, argv[0]);
        free(path);
    } else {
        argv0 = strdup(argv[0]);
    }

    /* parse the commandline */
    while ((c=getopt_long(argc, argv, "c:dhvV",
        long_options, &options_index)) != -1) {
        switch (c) {
            case 'c':
                cfgfile = optarg;
                break;
            case 'd':
                daemonize = 0;
                break;
            case 'h':
                usage(stdout);
                exit(0);
                break;
            case 'v':
                cmdline_verbosity++;
                break;
            case 'V':
                version(stdout);
                exit(0);
                break;
            case 256:
                time_arg = optarg;
                break;
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

    if (time_arg) {
        if(set_time_now_str(time_arg)) {
            fprintf(stderr, "Error: Failed to interpret start time argument.  Daemon not started.\n");
            return 1;
        }
    }

    /* main stuff */
    fprintf(stdout, "OpenDNSSEC signer engine version %s\n", PACKAGE_VERSION);

    ods_janitor_initialize(argv0);
    program_setup(cfgfile, cmdline_verbosity);

    engine = engine_create();
    if((status = engine_setup_preconfig(engine, cfgfile)) != ODS_STATUS_OK ||
       (status = engine_setup_config(engine, cfgfile, cmdline_verbosity, daemonize)) != ODS_STATUS_OK ||
       (status = engine_setup_initialize(engine, &linkfd)) != ODS_STATUS_OK ||
       (status = engine_setup_signals(engine)) != ODS_STATUS_OK ||
       (status = engine_setup_workstart(engine)) != ODS_STATUS_OK ||
       (status = engine_setup_netwstart(engine)) != ODS_STATUS_OK ||
       (status = engine_setup_finish(engine, linkfd)) != ODS_STATUS_OK) {
        ods_log_error("Unable to start signer daemon: %s", ods_status2str(status));
    }
    returncode = engine_start(engine);
    engine_cleanup(engine);
    engine = NULL;
    program_teardown();

    free(argv0);
    return returncode;
}

static void *
signal_handler(sig_atomic_t sig)
{
    switch (sig) {
        case SIGHUP:
            if (engine) {
                engine->need_to_reload = 1;
                pthread_mutex_lock(&engine->signal_lock);
                pthread_cond_signal(&engine->signal_cond);
                pthread_mutex_unlock(&engine->signal_lock);
            }
            break;
        case SIGINT:
        case SIGTERM:
            if (engine) {
                engine->need_to_exit = 1;
                pthread_mutex_lock(&engine->signal_lock);
                pthread_cond_signal(&engine->signal_cond);
                pthread_mutex_unlock(&engine->signal_lock);
            }
            break;
        default:
            break;
    }
    return NULL;
}

ods_status
engine_setup_signals(engine_type* engine)
{
    struct sigaction action;
    /* catch signals */
    action.sa_handler = (void (*)(int))signal_handler;
    sigfillset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGILL, &action, NULL);
    sigaction(SIGUSR1, &action, NULL);
    sigaction(SIGALRM, &action, NULL);
    sigaction(SIGCHLD, &action, NULL);
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);
    return ODS_STATUS_OK;
}