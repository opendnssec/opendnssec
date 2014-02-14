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
 * OpenDNSSEC key and signing policy enforcer daemon.
 *
 */

#include "config.h"
#include "daemon/engine.h"


/* Pull in the commands that have been implemented for the enforcer */
#include "enforcer/autostart_cmd.h"
#include "enforcer/setup_cmd.h"
#include "enforcer/update_repositorylist_cmd.h"
#include "enforcer/update_all_cmd.h"

#include "policy/update_kasp_cmd.h"
#include "policy/policy_resalt_cmd.h"
#include "keystate/update_keyzones_cmd.h"
#include "hsmkey/update_hsmkeys_cmd.h"

#include "policy/policy_export_cmd.h"
#include "policy/policy_import_cmd.h"
#include "policy/policy_list_cmd.h"
#include "policy/policy_purge_cmd.h"
#include "keystate/zone_list_cmd.h"
#include "keystate/zone_add_cmd.h"
#include "keystate/zone_del_cmd.h"
#include "keystate/zonelist_cmd.h"

#include "keystate/keystate_list_cmd.h"
#include "keystate/rollover_list_cmd.h"
#include "keystate/keystate_export_cmd.h"
#include "keystate/keystate_ds_submit_cmd.h"
#include "keystate/keystate_ds_seen_cmd.h"
#include "keystate/keystate_ds_retract_cmd.h"
#include "keystate/keystate_ds_gone_cmd.h"
#include "keystate/keystate_rollover_cmd.h"

#include "enforcer/enforce_cmd.h"
#include "signconf/signconf_cmd.h"

#include "hsmkey/hsmkey_gen_cmd.h"
#include "hsmkey/backup_hsmkeys_cmd.h"

/* System libraries last */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#define AUTHOR_NAME "Matthijs Mekking, Yuri Schaeffer, René Post"
#define COPYRIGHT_STR "Copyright (C) 2010-2011 NLnet Labs OpenDNSSEC"


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
#if HAVE_READ_CONFIG_FROM_EXTERNAL_FILE
    fprintf(out, " -c | --config <cfgfile> Read configuration from file.\n");
#endif
    fprintf(out, " -d | --no-daemon        Do not daemonize the enforcer "
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

/**
 * Table with command help print functions for all the enforcer
 * specific commands that are supported.
 *
 */

static help_xxxx_cmd_type enforcer_help[] = {
    help_setup_cmd,
    help_update_kasp_cmd,
    help_update_keyzones_cmd,
    help_update_repositorylist_cmd,
    help_update_all_cmd,
    
    help_policy_list_cmd,
    help_policy_export_cmd,
    help_policy_import_cmd,
    help_policy_purge_cmd,
    help_policy_resalt_cmd,

    help_zone_list_cmd,
    help_zone_add_cmd,
    help_zone_del_cmd,

    help_zonelist_export_cmd,
    help_zonelist_import_cmd,

    help_keystate_list_cmd,
    help_keystate_import_cmd,
    help_keystate_export_cmd,
    help_keystate_ds_submit_cmd,
    help_keystate_ds_seen_cmd,
    help_keystate_ds_retract_cmd,
    help_keystate_ds_gone_cmd,
    help_keystate_rollover_cmd,
    help_keystate_generate_cmd,

    help_rollover_list_cmd,

    help_backup_cmd,

    help_enforce_zones_cmd,
    help_signconf_cmd,
    
    /* ! NULL TERMINATED ! */
    NULL
};


/**
 * Table with command handler functions for all the enforcer
 * specific commands that are supported.
 *
 */
static handled_xxxx_cmd_type 
enforcer_commands[] = {
    handled_setup_cmd,
    handled_update_kasp_cmd,
    handled_update_keyzones_cmd,
    handled_update_repositorylist_cmd,
    handled_update_all_cmd,
    
    handled_policy_list_cmd,
    handled_policy_import_cmd,	
    handled_policy_export_cmd,
    handled_policy_purge_cmd,
    handled_policy_resalt_cmd,

    handled_zone_list_cmd,
    handled_zone_add_cmd,
    handled_zone_del_cmd,

    handled_zonelist_export_cmd,
    handled_zonelist_import_cmd,

    handled_keystate_list_cmd,
    handled_keystate_import_cmd,
    handled_keystate_export_cmd,
    handled_keystate_ds_submit_cmd,
    handled_keystate_ds_seen_cmd,
    handled_keystate_ds_retract_cmd,
    handled_keystate_ds_gone_cmd,
    handled_keystate_rollover_cmd,
    handled_keystate_generate_cmd,

    handled_rollover_list_cmd,

    handled_backup_cmds,

    handled_enforce_zones_cmd,
    handled_signconf_cmd,

    /* ! NULL TERMINATED ! */
    NULL
};


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
#if HAVE_READ_CONFIG_FROM_EXTERNAL_FILE
        {"config", required_argument, 0, 'c'},
#endif
        {"no-daemon", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {"info", no_argument, 0, 'i'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        { 0, 0, 0, 0}
    };

    /* parse the commandline */
    while ((c=getopt_long(argc, argv, 
#if HAVE_READ_CONFIG_FROM_EXTERNAL_FILE
                          "1c:dhivV"
#else
                          "1dhivV"
#endif
                          ,
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
            case 'V':
                version(stdout);
                exit(0);
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

#ifdef ENFORCER_TIMESHIFT
    if (getenv("ENFORCER_TIMESHIFT")) {
        fprintf(stdout, "WARNING: timeshift %s detected, this is a fixed point in time.\n",
            getenv("ENFORCER_TIMESHIFT"));
    } else {
        fprintf(stdout, "DEBUG: timeshift mode enabled, but not set.\n");
    }
#endif /* ENFORCER_TIMESHIFT */

    /* main stuff */
    fprintf(stdout, "OpenDNSSEC key and signing policy enforcer version %s\n", PACKAGE_VERSION);
    
    {
        engine_type *engine;
        if ((engine = engine_start(cfgfile, cmdline_verbosity, daemonize, info))) {
            engine_setup(engine,enforcer_commands,enforcer_help);
            /* if setup fails we need a non-zero exit code */
            if (engine->setup_error) {
                fprintf(stdout, "Setup failed. Aborting.\n");
                exit(3);
            }
            engine_runloop(engine,autostart,single_run);
            if (engine->setup_error) {
                fprintf(stdout, "Setup failed. Aborting.\n");
                exit(4);
            }
            engine_stop(engine);
        }
    }

    /* done */
    return 0;
}
