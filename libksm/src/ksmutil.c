/*
 * $Id: ksmutil.c 1170 2009-06-25 12:19:58Z jakob $
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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

#include <ksm/ksm.h>

extern char *optarg;
char *progname = "ksmutil";

void
usage_setup ()
{
    fprintf(stderr,
        "To import config into a database (deletes current contents)\n\tusage: %s [-f config] setup [path_to_kasp.xml]\n",
        progname);
}

void
usage_update ()
{
    fprintf(stderr,
        "To update database from config\n\tusage: %s [-f config] update [path_to_kasp.xml]\n",
        progname);
}

void
usage_addzone ()
{
    fprintf(stderr,
        "To add a zone to the config and database\n\tusage: %s [-f config] addzone zone [policy] [path_to_signerconf.xml] [input] [output]\n",
        progname);
}

void
usage_delzone ()
{
    fprintf(stderr,
        "To delete a zone from the config and database\n\tusage: %s [-f config] delzone zone\n",
        progname);
}

void
usage_rollzone ()
{
    fprintf(stderr,
        "To rollover a zone (may roll all zones on that policy)\n\tusage: %s [-f config] rollzone zone\n",
        progname);
}

void
usage_rollpolicy ()
{
    fprintf(stderr,
        "To rollover all zones on a policy\n\tusage: %s [-f config] rollpolicy policy\n",
        progname);
}

void
usage ()
{
    usage_setup ();
    usage_update ();
    usage_addzone ();
    usage_delzone ();
    usage_rollzone ();
    usage_rollpolicy ();
}

/* Do initial import of config files into database */
int
cmd_setup (int argc, char *argv[])
{
    printf("command not yet implemented\n");
    return 0;
}

/* Do incremental update of config files into database */
int
cmd_update (int argc, char *argv[])
{
    printf("command not yet implemented\n");
    return 0;
}

/* Add a zone to the config and database */
int
cmd_addzone (int argc, char *argv[])
{
    printf("command not yet implemented\n");
    return 0;
}

/* Delete a zone from the config and database */
int
cmd_delzone (int argc, char *argv[])
{
    printf("command not yet implemented\n");
    return 0;
}

/* To rollover a zone (or all zones on a policy if keys are shared) */
int
cmd_rollzone (int argc, char *argv[])
{
    printf("command not yet implemented\n");
    return 0;
}

/* To rollover all zones on a policy */
int
cmd_rollpolicy (int argc, char *argv[])
{
    printf("command not yet implemented\n");
    return 0;
}

int
main (int argc, char *argv[])
{
    int result;

    char *config = NULL;

    int ch;

    while ((ch = getopt(argc, argv, "f:h")) != -1) {
        switch (ch) {
        case 'f':
            config = strdup(optarg);
            break;
        case 'h':
            usage();
            exit(0);
            break;
        default:
            usage();
            exit(1);
        }
    }
    argc -= optind;
    argv += optind;

    if (!argc) {
        usage();
        exit(1);
    }

/* We may need this when we eventually import/export keys
    result = hsm_open(config, hsm_prompt_pin, NULL);
    if (result) {
        fprintf(stderr, "hsm_open() returned %d\n", result);
        exit(-1);
    } */

    if (!strcasecmp(argv[0], "setup")) {
        argc --;
        argv ++;
        result = cmd_setup(argc, argv);
    } else if (!strcasecmp(argv[0], "update")) {
        argc --;
        argv ++;
        result = cmd_update(argc, argv);
    } else if (!strcasecmp(argv[0], "addzone")) {
        argc --;
        argv ++;
        result = cmd_addzone(argc, argv);
    } else if (!strcasecmp(argv[0], "delzone")) {
        argc --;
        argv ++;
        result = cmd_delzone(argc, argv);
    } else if (!strcasecmp(argv[0], "rollzone")) {
        argc --;
        argv ++;
        result = cmd_rollzone(argc, argv);
    } else if (!strcasecmp(argv[0], "rollpolicy")) {
        argc --;
        argv ++;
        result = cmd_rollpolicy(argc, argv);
    } else {
        printf("Unknown command: %s\n", argv[0]);
        usage();
        result = -1;
    }

    /*(void) hsm_close();*/
    if (config) free(config);

    exit(result);
}
