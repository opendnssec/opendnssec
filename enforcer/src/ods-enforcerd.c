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
 * OpenDNSSEC key and signing policy enforcer daemon.
 *
 */

#include "config.h"

#include <getopt.h>
#include <libxml/parser.h>

#include "daemon/engine.h"
#include "log.h"
#include "duration.h"
#include "locks.h"
#include "enforcer/autostart_cmd.h"
#include "confparser.h"

#define AUTHOR_NAME "Matthijs Mekking, Yuri Schaeffer, René Post"
#define COPYRIGHT_STR "Copyright (C) 2010-2011 NLnet Labs OpenDNSSEC"

static const char* enforcerd_str = "engine";

/**
 * Prints usage.
 *
 */
static void
usage(FILE* out)
{
    fprintf(out, "Usage: %s [OPTIONS]\n", "ods-enforcerd");
    fprintf(out, "Start the OpenDNSSEC key and signing policy enforcer "
            "daemon.\n\n");
    fprintf(out, "Supported options:\n");
    fprintf(out, " -c | --config <cfgfile> Read configuration from file.\n");
    fprintf(out, " -d | --no-daemon        Do not daemonize the enforcer "
            "engine.\n");
    fprintf(out, " -s | --stderr           Log to standard error output.\n");
    fprintf(out, " -1 | --single-run       Run once, then exit.\n");
    fprintf(out, " -h | --help             Show this help and exit.\n");
    fprintf(out, " -i | --info             Print configuration and exit.\n");
    fprintf(out, " -v | --verbose          Increase verbosity.\n");
    fprintf(out, " -V | --version          Show version and exit.\n");
    fprintf(out, "      --set-time <time>  Start daemon at specific time. "
        "Notation \"YYYY-MM-DD-HH:MM:SS\" or seconds since Unix epoch.\n");
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
program_setup(const char* cfgfile, int cmdline_verbosity, int log_stderr)
{
    const char* file;
    int use_syslog;

    /* bypass log directives from the configuration file is stderr logging is required */
    if(log_stderr) {
        file = NULL;
        use_syslog = 0;
    } else {
        file = parse_conf_log_filename(cfgfile);
        use_syslog = parse_conf_use_syslog(cfgfile);
    }

    /* fully initialized log with parameters in conf file*/
    ods_log_init("ods-enforcerd", use_syslog, file, cmdline_verbosity?cmdline_verbosity:parse_conf_verbosity(cfgfile));
    ods_log_verbose("[%s] starting enforcer", enforcerd_str);

    /* initialize */
    xmlInitGlobals();
    xmlInitParser();
    xmlInitThreads();
    
    /* setup */
    tzset(); /* for portability */
#ifndef HAVE_ARC4RANDOM
    srand(time_now());
#endif
    free((void*)file);
}

static void
program_teardown()
{
    ods_log_close();

    xmlCleanupParser();
    xmlCleanupGlobals();
}

/**
 * Main. start engine and run it.
 *
 */
int
main(int argc, char* argv[])
{
    char* argv0;
    ods_status status;
    engine_type *engine;
    engineconfig_type* cfg;
    int returncode;
    int c;
    int options_index = 0;
    int info = 0;
    int single_run = 0;
    int daemonize = 1;
    int log_stderr = 0;
    int cmdline_verbosity = 0;
    char *time_arg = NULL;
    const char* cfgfile = ODS_SE_CFGFILE;
    static struct option long_options[] = {
        {"single-run", no_argument, 0, '1'},
        {"config", required_argument, 0, 'c'},
        {"no-daemon", no_argument, 0, 'd'},
        {"stderr", no_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {"info", no_argument, 0, 'i'},
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
    while ((c=getopt_long(argc, argv, "1c:dshivV",
        long_options, &options_index)) != -1) {
        switch (c) {
            case '1':
                single_run = 1;
                break;
            case 'c':
                cfgfile = optarg;
                break;
            case 'd':
                daemonize = 0;
                break;
            case 's':
                log_stderr = 0;
                break;
            case 'h':
                usage(stdout);
                exit(0);
            case 'i':
                info = 1;
                break;
            case 'v':
                cmdline_verbosity++;
                break;
            case 'V':
                version(stdout);
                exit(0);
            case 256:
                time_arg = optarg;
                break;
            default:
                usage(stderr);
                exit(2);
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
    fprintf(stdout, "OpenDNSSEC key and signing policy enforcer version %s\n", 
        PACKAGE_VERSION);
    
    ods_janitor_initialize(argv0);
    program_setup(cfgfile, cmdline_verbosity, log_stderr); /* setup basic logging, xml, PB */
    engine = engine_alloc(); /* Let's create an engine only once */
    if (!engine) {
        ods_log_crit("Could not start engine");
        program_teardown();
        return 1;
    }
    engine_init(engine, daemonize);
    
    returncode = 0;
    while (!engine->need_to_exit) {
        /* Parse config file */
        cfg = engine_config(cfgfile, cmdline_verbosity, engine->config);
        /* does it make sense? */
        if (engine_config_check(cfg) != ODS_STATUS_OK) {
            /* it does not, do we have a previous config loaded? */
            /* 
             * We can not recover since hsm_open tries to parse
             * this file as well, in the future we need to use 
             * hsm_open2
             * 
             * if (engine->config) {
                ods_log_error("[%s] cfgfile %s has errors, continuing"
                    " with old config", enforcerd_str, cfgfile);
            } else {*/
                ods_log_crit("[%s] cfgfile %s has errors", enforcerd_str, cfgfile);
                returncode = 2;
                engine_config_cleanup(cfg); /* antagonist of engine_config() */
                break;
            /*}*/
        } else {
            engine_config_cleanup(engine->config); /* antagonist of engine_config() */
            engine->config = cfg;
        }

        /* Print config and exit */
        if (info) {
            engine_config_print(stdout, engine->config); /* for debugging */
            break;
        }

        /* do daemon housekeeping: pid, privdrop, fork, log */
        if ((status = engine_setup()) != ODS_STATUS_OK) {
            ods_log_error("setup failed: %s", ods_status2str(status));
            if (!daemonize)
                fprintf(stderr, "setup failed: %s\n", ods_status2str(status));
            returncode = 3;
            engine->need_to_exit = 1;
        } else {
            if (engine_run(engine, autostart, single_run)) {
                returncode = 4;
                engine->need_to_exit = 1;
            }
            engine_teardown(engine); /* antagonist of engine_setup() */
        }
        if (!engine->need_to_exit) 
            ods_log_info("[%s] enforcer reloading", enforcerd_str);
    }
    engine_config_cleanup(engine->config);
    ods_log_info("[engine] enforcer shutdown"); /* needed for test */
    ods_log_info("[%s] enforcerd (pid: %lu) stopped with exitcode %d",
        enforcerd_str, (unsigned long) engine->pid, returncode);
    engine_dealloc(engine); /* antagonist of engine_alloc() */
    if (returncode && daemonize) {
        fprintf(stderr, "enforcerd stopped with exitcode %d\n",
            returncode);
    }
    program_teardown(); /* antagonist of program_setup() */
    return returncode;
}
