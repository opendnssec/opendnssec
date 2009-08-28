/*
 * $Id$
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
#include <errno.h>
#include <fcntl.h>

#include "config.h"

#include <ksm/ksmutil.h>
#include <ksm/ksm.h>
#include <ksm/database.h>
#include "ksm/database_statement.h"
#include "ksm/db_fields.h"
#include <ksm/datetime.h>
#include <ksm/string_util.h>
#include <ksm/string_util2.h>
#include "ksm/kmemsg.h"
#include "ksm/kmedef.h"
#include "ksm/dbsmsg.h"
#include "ksm/dbsdef.h"
#include "ksm/message.h"

#include <libhsm.h>
#include <libhsmdns.h>
#include <ldns/ldns.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlsave.h>

/* Some value type flags */
#define INT_TYPE 0
#define DURATION_TYPE 1
#define BOOL_TYPE 2
#define REPO_TYPE 3
#define SERIAL_TYPE 4

extern char *optarg;
extern int optind;
const char *progname = "ksmutil";
char *config = (char *) CONFIG_FILE;

    void
usage_setup ()
{
    fprintf(stderr,
            "usage: %s [-f config] setup\n"
            "\tImport config into a database (deletes current contents)\n",
            progname);
}

    void
usage_update ()
{
    fprintf(stderr,
            "usage: %s [-f config] update\n"
            "\tUpdate database from config\n",
            progname);
}

    void
usage_addzone ()
{
    fprintf(stderr,
            "usage: %s [-f config] addzone zone [policy] [path_to_signerconf.xml] [input] [output]\n"
            "\tAdd a zone to the config and database\n",
            progname);
}

    void
usage_delzone ()
{
    fprintf(stderr,
            "usage: %s [-f config] [-a] delzone zone\n"
            "\tDelete a zone from the config and database\n"
            "\t-a will delete all zones from the config and database\n",
            progname);
}

    void
usage_listzone ()
{
    fprintf(stderr,
            "usage: %s [-f config] listzone\n"
            "\tList zones from the zonelist.xml in config\n",
            progname);
}

   void
usage_export ()
{
    fprintf(stderr,
            "usage: %s [-f config] [-a] export policy [policy_name]\n"
            "   or: %s [-f config] [-a] export [keys|ds] [zone_name] [state] [keytype]\n"
            "\tpolicy: export all policies [or named policy] to xml\n"
            "\t\t-a: export all policies; omit policy_name\n"
            "\tkeys: export dnskey RRs for named zone [KSK unless ZSK specified]\n"
            "\tds: export ds RRs for named zone [KSK unless ZSK specified]\n"
            "\t\t-a: export all keys or ds records; omit zone_name\n"
            "\t\t[state] can be one of GENERATED, PUBLISHED, READY, ACTIVE or RETIRED (default = ACTIVE)\n"
            ,progname, progname);
}

    void
usage_rollzone ()
{
    fprintf(stderr,
            "usage: %s [-f config] rollzone zone [KSK|ZSK]\n"
            "\tRollover a zone (may roll all zones on that policy)\n",
            progname);
}

    void
usage_rollpolicy ()
{
    fprintf(stderr,
            "usage: %s [-f config] rollpolicy policy [KSK|ZSK]\n"
            "\tRollover all zones on a policy\n",
            progname);
}

    void
usage_backup ()
{
    fprintf(stderr,
            "usage: %s [-f config] backup [done|list] [repository]\n"
            "\tIndicate that a key backup has been performed or list dates when backups were made\n",
            progname);
}

    void
usage_list ()
{
    fprintf(stderr,
            "usage: %s [-f config] [-l] list [repositories|policies|keys|rollovers|backups] [qualifier]\n"
            "\tList specified aspect of the current configuration\n"
            "\t-l returns more information on keys\n",
            progname);
}

    void
usage_import ()
{
    fprintf(stderr,
            "usage: %s [-f config] import key <CKA_ID> <HSM> <ZONE> <KEYTYPE> <SIZE> <ALGORITHM> <STATE> <TIME> [RETIRE_TIME]\n"
            "\tImport a key into ksm\n"
            "\t\t<KEYTYPE> can be one of KSK or ZSK\n"
            "\t\t<SIZE> size of key in bits\n", progname);

    fprintf(stderr,
            "\t\t<ALGORITHM> can be one of RSASHA1 or RSASHA1-NSEC3-SHA1 (5 or 7)\n"
            "\t\t<STATE> can be one of GENERATED, PUBLISHED, READY, ACTIVE or RETIRED\n"
            "\t\t<TIME> is the date when it entered the state given\n"
            "\t\t[RETIRE TIME] is the date when it should retire (if entered as active)\n"
            "\t\t\t(possible time format YYYY[MM[DD[HH[MM[SS]]]]] use ksmutil -h for full list\n");
}

    void
usage ()
{
    usage_setup ();
    usage_update ();
    usage_addzone ();
    usage_delzone ();
    usage_listzone ();
    usage_export ();
    usage_rollzone ();
    usage_rollpolicy ();
    usage_backup ();
    usage_list ();
    usage_import ();
}

    void
date_help()
{
    fprintf(stderr,
        "\n\tAllowed date/time strings are of the form:\n"
 
        "\tYYYYMMDD[HH[MM[SS]]]                (all numeric)\n"
        "\n" 
        "\tor  D-MMM-YYYY[:| ]HH[:MM[:SS]]     (alphabetic  month)\n"
        "\tor  DD-MMM-YYYY[:| ]HH[:MM[:SS]]    (alphabetic  month)\n"
        "\tor  YYYY-MMM-DD[:| ]HH[:MM[:SS]]    (alphabetic month)\n"
        "\n" 
        "\tD-MM-YYYY[:| ]HH[:MM[:SS]]          (numeric month)\n"
        "\tDD-MM-YYYY[:| ]HH[:MM[:SS]]         (numeric month)\n"
        "\tor  YYYY-MM-DD[:| ]HH[:MM[:SS]]     (numeric month)\n"
        "\n" 
        "\t... and the distinction between them is given by the location of the\n"
        "\thyphens.\n");
}
/* 
 * Do initial import of config files into database
 */
    int
cmd_setup (int argc, char *argv[])
{
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */
    char* lock_filename;    /* name for the lock file (so we can close it) */
    char* zone_list_filename;   /* Extracted from conf.xml */
    char* kasp_filename;    /* Extracted from conf.xml */
    int status = 0;

    /* Database connection details */
    char *dbschema = NULL;
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *password = NULL;

    char* backup_filename = NULL;
    char* setup_command = NULL;

    int user_certain;
    printf("*WARNING* This will erase all data in the database; are you sure? [y/N] ");

    user_certain = getchar();
    if (user_certain != 'y' && user_certain != 'Y') {
        printf("Okay, quitting...\n");
        exit(0);
    }

    /* Right then, they asked for it */

    /* Read the database details out of conf.xml */
    status = get_db_details(&dbschema, &host, &port, &user, &password);
    if (status != 0) {
        StrFree(host);
        StrFree(port);
        StrFree(dbschema);
        StrFree(user);
        StrFree(password);
        return(status);
    }

    /* If we are in sqlite mode then take a lock out on a file to
       prevent multiple access (not sure that we can be sure that sqlite is
       safe for multiple processes to access). */
    if (DbFlavour() == SQLITE_DB) {

        /* set up lock filename (it may have changed?) */
        lock_filename = NULL;
        StrAppend(&lock_filename, dbschema);
        StrAppend(&lock_filename, ".our_lock");

        lock_fd = fopen(lock_filename, "w");
        status = get_lite_lock(lock_filename, lock_fd);
        if (status != 0) {
            printf("Error getting db lock\n");
            if (lock_fd != NULL) {
                fclose(lock_fd);
            }
            StrFree(dbschema);
            StrFree(lock_filename);
            return(1);
        }
        StrFree(lock_filename);

        /* Make a backup of the sqlite DB */
        StrAppend(&backup_filename, dbschema);
        StrAppend(&backup_filename, ".backup");

        status = backup_file(dbschema, backup_filename);

        StrFree(backup_filename);

        if (status != 0) {
            fclose(lock_fd);
            StrFree(host);
            StrFree(port);
            StrFree(dbschema);
            StrFree(user);
            StrFree(password);
            return(status);
        }

        /* Run the setup script */
        /* will look like: <SQL_BIN> <DBSCHEMA> < <SQL_SETUP> */
        StrAppend(&setup_command, SQL_BIN);
        StrAppend(&setup_command, " ");
        StrAppend(&setup_command, dbschema);
        StrAppend(&setup_command, " < ");
        StrAppend(&setup_command, SQL_SETUP);

        if (system(setup_command) != 0)
        {
            printf("Could not call db setup command:\n\t%s\n", setup_command);
            fclose(lock_fd);
            StrFree(host);
            StrFree(port);
            StrFree(dbschema);
            StrFree(user);
            StrFree(password);
            StrFree(setup_command);
            return(1);
        }
        StrFree(setup_command);
    }
    else {
        /* MySQL setup */
        /* will look like: <SQL_BIN> -u <USER> -h <HOST> -p<PASSWORD> <DBSCHEMA> < <SQL_SETUP> */
        StrAppend(&setup_command, SQL_BIN);
        StrAppend(&setup_command, " -u ");
        StrAppend(&setup_command, user);
        StrAppend(&setup_command, " -h ");
        StrAppend(&setup_command, host);
        if (password != NULL) {
            StrAppend(&setup_command, " -p");
            StrAppend(&setup_command, password);
        }
        StrAppend(&setup_command, " ");
        StrAppend(&setup_command, dbschema);
        StrAppend(&setup_command, " < ");
        StrAppend(&setup_command, SQL_SETUP);

        if (system(setup_command) != 0)
        {
            printf("Could not call db setup command:\n\t%s\n", setup_command);
            fclose(lock_fd);
            StrFree(host);
            StrFree(port);
            StrFree(dbschema);
            StrFree(user);
            StrFree(password);
            StrFree(setup_command);
            return(1);
        }
        StrFree(setup_command);
    }


    /* try to connect to the database */
    status = DbConnect(&dbhandle, dbschema, host, password, user);

    /* Free these up early */
    StrFree(host);
    StrFree(port);
    StrFree(dbschema);
    StrFree(user);
    StrFree(password);

    if (status != 0) {
        printf("Failed to connect to database\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(1);
    }

    /* 
     *  Now we will read the conf.xml file again, but this time we will not validate.
     *  Instead we just extract the RepositoryList into the database and also learn
     *  the location of the zonelist and kasp.
     */
    status = update_repositories(&zone_list_filename, &kasp_filename);
    if (status != 0) {
        printf("Failed to update repositories\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(1);
    }

    /*
     * Now read the kasp.xml which should be in the same directory.
     * This lists all of the policies.
     */
    status = update_policies(kasp_filename);
    if (status != 0) {
        printf("Failed to update policies\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(1);
    }

    StrFree(kasp_filename);

    /*
     * Take the zonelist we learnt above and read it, updating or inserting zone
     * records in the database as we go.
     */
    status = update_zones(zone_list_filename);
    if (status != 0) {
        printf("Failed to update zones\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(1);
    }

    StrFree(zone_list_filename);

    /* Release sqlite lock file (if we have it) */
    if (DbFlavour() == SQLITE_DB) {
        status = release_lite_lock(lock_fd);
        if (status != 0) {
            printf("Error releasing db lock: %s", strerror(errno));
            fclose(lock_fd);
            return(1);
        }
        fclose(lock_fd);
    }

    DbDisconnect(dbhandle);

    return 0;
}

/*
 * Do incremental update of config files into database
 *
 * returns 0 on success
 *         1 on error (and will have sent a message to stdout)
 */
    int
cmd_update (int argc, char *argv[])
{
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */
    char* lock_filename;    /* name for the lock file (so we can close it) */
    char* zone_list_filename;   /* Extracted from conf.xml */
    char* kasp_filename;   /* Extracted from conf.xml */
    int status = 0;

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, &lock_filename);
    if (status != 0) {
        printf("Failed to connect to database\n");
        return(1);
    }
    StrFree(lock_filename);

    /* 
     *  Now we will read the conf.xml file again, but this time we will not validate.
     *  Instead we just extract the RepositoryList into the database and also learn
     *  the location of the zonelist.
     */
    status = update_repositories(&zone_list_filename, &kasp_filename);
    if (status != 0) {
        printf("Failed to update repositories\n");
        fclose(lock_fd);
        return(1);
    }

    /*
     * Now read the kasp.xml which should be in the same directory.
     * This lists all of the policies.
     */
    status = update_policies(kasp_filename);
    if (status != 0) {
        printf("Failed to update policies\n");
        fclose(lock_fd);
        return(1);
    }

    /*
     * Take the zonelist we learnt above and read it, updating or inserting zone
     * records in the database as we go.
     */
    status = update_zones(zone_list_filename);
    if (status != 0) {
        printf("Failed to update zones\n");
        fclose(lock_fd);
        return(1);
    }
    StrFree(zone_list_filename);

    /* Release sqlite lock file (if we have it) */
    if (DbFlavour() == SQLITE_DB) {
        status = release_lite_lock(lock_fd);
        if (status != 0) {
            printf("Error releasing db lock");
            fclose(lock_fd);
            return(1);
        }
        fclose(lock_fd);
    }

    DbDisconnect(dbhandle);

    return 0;
}

/* 
 * Add a zone to the config and database.
 *
 * Use XMLwriter to update the zonelist.xml found in conf.xml.
 * Then call update_zones to push these changes into the database.
 * zonelist.xml will be backed up, as will the DB file if we are using sqlite
 *
 */
    int
cmd_addzone (int argc, char *argv[])
{
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */
    char* lock_filename;    /* name for the lock file (so we can close it) */

    char* zonelist_filename = NULL;
    char* backup_filename = NULL;
    char* db_backup_filename = NULL;
    /* The settings that we need for the zone */
    char* zone_name = NULL;
    char* policy_name = NULL;
    char* sig_conf_name = NULL;
    char* input_name = NULL;
    char* output_name = NULL;
    int policy_id = 0;

    /* Database connection details */
    char *dbschema = NULL;
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *password = NULL;

    xmlDocPtr doc = NULL;

    int status = 0;

    char *path = getenv("PWD");

    /* See what arguments we were passed (if any) otherwise set the defaults */
    if (argc != 1 && argc != 5) {
        usage_addzone();
        return -1;
    }
    StrAppend(&zone_name, argv[0]);
    if (argc == 5) {
        StrAppend(&policy_name, argv[1]);

        /*
         * Turn any relative paths into absolute (sort of, not the neatest output)
         */
        if (*argv[2] != '/') {
            StrAppend(&sig_conf_name, path);
            StrAppend(&sig_conf_name, "/");
        }
        StrAppend(&sig_conf_name, argv[2]);

        if (*argv[3] != '/') {
            StrAppend(&input_name, path);
            StrAppend(&input_name, "/");
        }
        StrAppend(&input_name, argv[3]);

        if (*argv[4] != '/') {
            StrAppend(&output_name, path);
            StrAppend(&output_name, "/");
        }
        StrAppend(&output_name, argv[4]);

    }
    else {
        StrAppend(&policy_name, "default");

        StrAppend(&sig_conf_name, LOCALSTATE_DIR);
        StrAppend(&sig_conf_name, "/signconf/");
        StrAppend(&sig_conf_name, zone_name);
        StrAppend(&sig_conf_name, ".xml");

        StrAppend(&input_name, LOCALSTATE_DIR);
        StrAppend(&input_name, "/unsigned/");
        StrAppend(&input_name, zone_name);

        StrAppend(&output_name, LOCALSTATE_DIR);
        StrAppend(&output_name, "/signed/");
        StrAppend(&output_name, zone_name);
    }

    /* Set zonelist from the conf.xml that we have got */
    status = read_zonelist_filename(&zonelist_filename);
    if (status != 0) {
        printf("couldn't read zonelist\n");
        return(1);
    }

    /* Read the file and add our new node in memory */
    /* TODO don't add if it already exists */
    xmlKeepBlanksDefault(0);
    xmlTreeIndentString = "\t";
    doc = add_zone_node(zonelist_filename, zone_name, policy_name, sig_conf_name, input_name, output_name);
    if (doc == NULL) {
        return(1);
    }

    /* Backup the current zonelist */
    StrAppend(&backup_filename, zonelist_filename);
    StrAppend(&backup_filename, ".backup");
    status = backup_file(zonelist_filename, backup_filename);
    StrFree(backup_filename);
    if (status != 0) {
        StrFree(zonelist_filename);
        StrFree(zone_name);
        StrFree(policy_name);
        StrFree(sig_conf_name);
        StrFree(input_name);
        StrFree(output_name);
        return(status);
    }

    /* Save our new one over, TODO should we validate it first? */
    status = xmlSaveFormatFile(zonelist_filename, doc, 1);
    xmlFreeDoc(doc);
    if (status == -1) {
        printf("couldn't save zonelist\n");
        StrFree(zonelist_filename);
        StrFree(zone_name);
        StrFree(policy_name);
        StrFree(sig_conf_name);
        StrFree(input_name);
        StrFree(output_name);
        return(1);
    }

    /*
     * Push this new zonelist into the database
     */

    /* Read the database details out of conf.xml */
    status = get_db_details(&dbschema, &host, &port, &user, &password);
    if (status != 0) {
        StrFree(host);
        StrFree(port);
        StrFree(dbschema);
        StrFree(user);
        StrFree(password);
        return(status);
    }

    /* If we are in sqlite mode then take a lock out on a file to
       prevent multiple access (not sure that we can be sure that sqlite is
       safe for multiple processes to access). */
    if (DbFlavour() == SQLITE_DB) {

        /* set up lock filename (it may have changed?) */
        lock_filename = NULL;
        StrAppend(&lock_filename, dbschema);
        StrAppend(&lock_filename, ".our_lock");

        lock_fd = fopen(lock_filename, "w");
        status = get_lite_lock(lock_filename, lock_fd);
        if (status != 0) {
            printf("Error getting db lock\n");
            if (lock_fd != NULL) {
                fclose(lock_fd);
            }
            StrFree(dbschema);
            return(1);
        }

        /* Make a backup of the sqlite DB */
        StrAppend(&db_backup_filename, dbschema);
        StrAppend(&db_backup_filename, ".backup");

        status = backup_file(dbschema, db_backup_filename);

        StrFree(db_backup_filename);

        if (status != 0) {
            fclose(lock_fd);
            StrFree(host);
            StrFree(port);
            StrFree(dbschema);
            StrFree(user);
            StrFree(password);
            return(status);
        }
    }

    /* try to connect to the database */
    status = DbConnect(&dbhandle, dbschema, host, password, user);

    /* Free these up early */
    StrFree(host);
    StrFree(port);
    StrFree(dbschema);
    StrFree(user);
    StrFree(password);

    if (status != 0) {
        printf("Failed to connect to database\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(1);
    }

    /* Now stick this zone into the database */
    status = KsmPolicyIdFromName(policy_name, &policy_id);
    if (status != 0) {
        printf("Error, can't find policy : %s\n", policy_name);
        printf("Failed to update zones\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(1);
    }
    status = KsmImportZone(zone_name, policy_id);
    if (status != 0) {
        printf("Failed to Import zone\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(1);
    }

    /* If need be (keys shared on policy) link existing keys to zone */
    status = KsmLinkKeys(zone_name, policy_id);
    if (status != 0) {
        printf("Failed to Link Keys to zone\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(1);
    }

    /* Release sqlite lock file (if we have it) */
    if (DbFlavour() == SQLITE_DB) {
        status = release_lite_lock(lock_fd);
        if (status != 0) {
            printf("Error releasing db lock");
            fclose(lock_fd);
            return(1);
        }
        fclose(lock_fd);
    }

    printf("Imported zone: %s\n", zone_name);

    DbDisconnect(dbhandle);

    return 0;
}

/*
 * Delete a zone from the config 
 */
    int
cmd_delzone (int argc, char *argv[], int do_all)
{

    char* zonelist_filename = NULL;
    char* backup_filename = NULL;
    /* The settings that we need for the zone */
    char* zone_name = NULL;
    int zone_id = -1;

    xmlDocPtr doc = NULL;

    int status = 0;
    int user_certain;           /* Continue ? */

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */
    char* lock_filename;    /* name for the lock file (so we can close it) */
    char *dbschema = NULL;
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *password = NULL;

    /* See what arguments we were passed (if any) otherwise set the defaults */
    if (argc != 0 && do_all == 1) {
        usage_delzone();
        return -1;
    }
    else if (argc != 1 && do_all == 0) {
        usage_delzone();
        return -1;
    }
    StrAppend(&zone_name, argv[0]);

    /* Warn and confirm if they have asked to delete all zones */
    if (do_all == 1) {
        printf("*WARNING* This will remove all zones from OpenDNSSEC; are you sure? [y/N] ");

        user_certain = getchar();
        if (user_certain != 'y' && user_certain != 'Y') {
            printf("Okay, quitting...\n");
            exit(0);
        }
    }

    /* Read the database details out of conf.xml */
    status = get_db_details(&dbschema, &host, &port, &user, &password);
    if (status != 0) {
        StrFree(host);
        StrFree(port);
        StrFree(dbschema);
        StrFree(user);
        StrFree(password);
        return(status);
    }

    /* If we are in sqlite mode then take a lock out on a file to
       prevent multiple access (not sure that we can be sure that sqlite is
       safe for multiple processes to access). */
    if (DbFlavour() == SQLITE_DB) {

        /* set up lock filename (it may have changed?) */
        lock_filename = NULL;
        StrAppend(&lock_filename, dbschema);
        StrAppend(&lock_filename, ".our_lock");

        lock_fd = fopen(lock_filename, "w");
        status = get_lite_lock(lock_filename, lock_fd);
        if (status != 0) {
            printf("Error getting db lock\n");
            if (lock_fd != NULL) {
                fclose(lock_fd);
            }
            StrFree(dbschema);
            return(1);
        }

        if (status != 0) {
            fclose(lock_fd);
            StrFree(host);
            StrFree(port);
            StrFree(dbschema);
            StrFree(user);
            StrFree(password);
            return(status);
        }
    }

    /* try to connect to the database */
    status = DbConnect(&dbhandle, dbschema, host, password, user);

    /* Free these up early */
    StrFree(host);
    StrFree(port);
    StrFree(dbschema);
    StrFree(user);
    StrFree(password);

    if (status != 0) {
        printf("Failed to connect to database\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(1);
    }

    /*
     * DO XML STUFF FIRST
     */

    /* Set zonelist from the conf.xml that we have got */
    status = read_zonelist_filename(&zonelist_filename);
    if (status != 0) {
        printf("couldn't read zonelist\n");
        return(1);
    }

    /* Read the file and delete our zone node(s) in memory */
    doc = del_zone_node(zonelist_filename, zone_name, do_all);
    if (doc == NULL) {
        return(1);
    }

    /* Backup the current zonelist */
    StrAppend(&backup_filename, zonelist_filename);
    StrAppend(&backup_filename, ".backup");
    status = backup_file(zonelist_filename, backup_filename);
    StrFree(backup_filename);
    if (status != 0) {
        StrFree(zonelist_filename);
        StrFree(zone_name);
        return(status);
    }

    /* Save our new one over, TODO should we validate it first? */
    status = xmlSaveFormatFile(zonelist_filename, doc, 1);
    xmlFreeDoc(doc);
    if (status == -1) {
        printf("Could not save %s\n", zonelist_filename);
        return(1);
    }

    /*
     * NOW SORT OUT THE DATABASE (zone_id will still be -1 if we are deleting all)
     */

    /* See if the zone exists and get its ID, assuming we are not deleting all */
    if (do_all == 0) {
        status = KsmZoneIdFromName(zone_name, &zone_id);
        if (status != 0) {
            printf("Couldn't find zone %s\n", zone_name);
            return(1);
        }
    }

    status = KsmDeleteZone(zone_id);

    if (status != 0) {
        printf("Error: failed to remove zone%s from database\n", (do_all == 1) ? "s" : "");
        return status;
    }
    
    /* Call the signer_engine_cli to tell it that the zonelist has changed */
    /* TODO Should we do this when we remove a zone? */
    if (do_all == 0) {
        if (system(SIGNER_CLI_COMMAND) != 0)
        {
            printf("Could not call signer_engine\n");
        }
    }

    return 0;
}

/*
 * List a zone 
 */
    int
cmd_listzone (int argc, char *argv[])
{

    char* zonelist_filename = NULL;

    int status = 0;

    /* See what arguments we were passed (if any) otherwise set the defaults */
    if (argc != 0) {
        usage_listzone();
        return -1;
    }

    /* Set zonelist from the conf.xml that we have got */
    status = read_zonelist_filename(&zonelist_filename);
    if (status != 0) {
        printf("couldn't read zonelist\n");
        return(1);
    }

    /* Read the file and list the zones as we go */
    list_zone_node(zonelist_filename);

    return 0;
}

/*
 * To export: 
 *          policies (all, unless one is named) to xml
 *          keys|ds for zone
 */
    int
cmd_export (int argc, char *argv[], int do_all)
{
    int status = 0;
    /* Database connection details */
    DB_HANDLE	dbhandle;
    char *dbschema = NULL;
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *password = NULL;

    xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");
    xmlNodePtr root;
    KSM_POLICY *policy;

    char* subcommand = NULL;
    char* qualifier = NULL;
    char* qual2 = NULL;
    char* qual3 = NULL;
    char* zone_name = NULL;

    char* case_subcommand = NULL;   /* POLICY, KEYS or DS */
    char* case_qual2 = NULL;        /* GENERATED, PUBLISHED, READY, ACTIVE or RETIRED */
    char* case_qual3 = NULL;        /* KSK or ZSK */

    int zone_id = -1;
    int state_id = KSM_STATE_ACTIVE;
    int keytype_id = KSM_TYPE_KSK;

    /* Key information */
    hsm_key_t *key = NULL;
    ldns_rr *dnskey_rr = NULL;
    ldns_rr *ds_sha1_rr = NULL;
    ldns_rr *ds_sha256_rr = NULL;
    hsm_sign_params_t *sign_params;

    char* sql = NULL;
    KSM_KEYDATA data;       /* Data for each key */
    DB_RESULT	result;     /* Result set from query */

    /* 
       Command should look like:
       ksmutil export policy [policy_name]
       call it       subcommand qualifier
       OR
       ksmutil export [keys|ds] [zone_name] [state] [keytype]
       call it        subcommand qualifier   qual2    qual3

       if do_all == 1 then zone_name should be null
     */  

    /* See what arguments we were passed (if any) otherwise set the defaults */
    if (argc == 0 || argc >= 5) {
        usage_export();
        return -1;
    }
    StrAppend(&subcommand, argv[0]);

    /* Check the subcommand */
    case_subcommand = StrStrdup(subcommand);
    (void) StrToUpper(case_subcommand);
    if (strncmp(case_subcommand, "POLICY", 6) != 0 && 
            strncmp(case_subcommand, "KEYS", 4) != 0 && 
            strncmp(case_subcommand, "DS", 2)) {
        printf("Error: Unrecognised command \"export %s\"\n", subcommand);
        StrFree(case_subcommand);
        return(1);
    }

    if (argc >= 2 && do_all == 0) {
        /* argv[1] should be policy name or zone name */
        StrAppend(&qualifier, argv[1]);
    } 

    if (argc >= 2 && do_all == 1) {
        /* argv[1] should be state or keytype */
        StrAppend(&qual2, argv[1]);
        if (strncmp(case_subcommand, "POLICY", 6) == 0) {
            printf("Error: command \"export polcy\" requires no policy_name with -a flag\n");
            StrFree(case_subcommand);
            return(1);
        }
    }
    if (argc >= 3 && do_all == 0) {
        /* argv[2] should be state or keytype */
        StrAppend(&qual2, argv[2]);

        if (strncmp(case_subcommand, "POLICY", 6) == 0) {
            printf("Error: command \"export polcy\" requires one policy name at a time\n");
            StrFree(case_subcommand);
            return(1);
        }
    }
    if (argc >= 3 && do_all == 1) {
        /* argv[2] should be keytype */
        StrAppend(&qual3, argv[2]);
    }
    if (argc == 4) {
        /* argv[3] should be keytype */
        StrAppend(&qual3, argv[3]);
    }

    /* Check qual2, can be state or keytype */
    if (qual2 != NULL) {
        case_qual2 = StrStrdup(qual2);
        (void) StrToUpper(case_qual2);
        if (strncmp(case_qual2, "KSK", 3) == 0 || strncmp(qual2, "257", 3) == 0) {
            keytype_id = KSM_TYPE_KSK;
        }
        else if (strncmp(case_qual2, "ZSK", 3) == 0 || strncmp(qual2, "256", 3) == 0) {
            keytype_id = KSM_TYPE_ZSK;
        }
        else if (strncmp(case_qual2, "GENERATE", 8) == 0 || strncmp(qual2, "1", 1) == 0) {
            state_id = KSM_STATE_GENERATE;
        }
        else if (strncmp(case_qual2, "PUBLISH", 7) == 0 || strncmp(qual2, "2", 1) == 0) {
            state_id =  KSM_STATE_PUBLISH;
        }
        else if (strncmp(case_qual2, "READY", 5) == 0 || strncmp(qual2, "3", 1) == 0) {
            state_id =  KSM_STATE_READY;
        }
        else if (strncmp(case_qual2, "ACTIVE", 6) == 0 || strncmp(qual2, "4", 1) == 0) {
            state_id =  KSM_STATE_ACTIVE;
        }
        else if (strncmp(case_qual2, "RETIRE", 6) == 0 || strncmp(qual2, "5", 1) == 0) {
            state_id =  KSM_STATE_DEAD;
        }
        else {
            printf("Error: Unrecognised state %s; should be one of GENERATED, PUBLISHED, READY, ACTIVE or RETIRED\n", qual2);

            StrFree(case_qual2);
            return(1);
        }
        StrFree(case_qual2);
    }

    /* Check qual3, can be keytype */
    if (qual3 != NULL) {
        case_qual3 = StrStrdup(qual3);
        (void) StrToUpper(case_qual3);
        if (strncmp(case_qual3, "KSK", 3) == 0 || strncmp(qual3, "257", 3) == 0) {
            keytype_id = KSM_TYPE_KSK;
        }
        else if (strncmp(case_qual3, "ZSK", 3) == 0 || strncmp(qual3, "256", 3) == 0) {
            keytype_id = KSM_TYPE_ZSK;
        }
        else {
            printf("Error: Unrecognised keytype %s; should be one of KSK or ZSK\n", qual3);

            StrFree(case_qual3);
            return(1);
        }
        StrFree(case_qual3);
    }

    /* Read the database details out of conf.xml */
    status = get_db_details(&dbschema, &host, &port, &user, &password);
    if (status != 0) {
        StrFree(host);
        StrFree(port);
        StrFree(dbschema);
        StrFree(user);
        StrFree(password);
        return(status);
    }
    /* try to connect to the database */
    status = DbConnect(&dbhandle, dbschema, host, password, user);

    /* Free these up early */
    StrFree(host);
    StrFree(port);
    StrFree(dbschema);
    StrFree(user);
    StrFree(password);
  
    if (strncmp(case_subcommand, "POLICY", 6) == 0) {
        /* Make some space for the policy */ 
        policy = (KSM_POLICY *)malloc(sizeof(KSM_POLICY));
        policy->signer = (KSM_SIGNER_POLICY *)malloc(sizeof(KSM_SIGNER_POLICY));
        policy->signature = (KSM_SIGNATURE_POLICY *)malloc(sizeof(KSM_SIGNATURE_POLICY));
        policy->zone = (KSM_ZONE_POLICY *)malloc(sizeof(KSM_ZONE_POLICY));
        policy->parent = (KSM_PARENT_POLICY *)malloc(sizeof(KSM_PARENT_POLICY));
        policy->keys = (KSM_COMMON_KEY_POLICY *)malloc(sizeof(KSM_COMMON_KEY_POLICY));
        policy->ksk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
        policy->zsk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
        policy->denial = (KSM_DENIAL_POLICY *)malloc(sizeof(KSM_DENIAL_POLICY));
        policy->enforcer = (KSM_ENFORCER_POLICY *)malloc(sizeof(KSM_ENFORCER_POLICY));
        /*    policy->audit = (KSM_AUDIT_POLICY *)malloc(sizeof(KSM_AUDIT_POLICY)); */
        policy->audit = (char *)calloc(KSM_POLICY_AUDIT_LENGTH, sizeof(char));
        policy->name = (char *)calloc(KSM_NAME_LENGTH, sizeof(char));
        policy->description = (char *)calloc(KSM_POLICY_DESC_LENGTH, sizeof(char));
        if (policy->signer == NULL || policy->signature == NULL || 
                policy->zone == NULL || policy->parent == NULL ||
                policy->keys == NULL ||
                policy->ksk == NULL || policy->zsk == NULL || 
                policy->denial == NULL || policy->enforcer == NULL) {
            fprintf(stderr, "Malloc for policy struct failed\n");
            exit(1);
        }

        /* Setup doc with a root node of <KASP> */
        xmlKeepBlanksDefault(0);
        xmlTreeIndentString = "    ";
        root = xmlNewDocNode(doc, NULL, (const xmlChar *)"KASP", NULL);
        (void) xmlDocSetRootElement(doc, root);

        /* Read policies (all if policy_name == NULL; else named policy only) */
        status = KsmPolicyInit(&result, qualifier);
        if (status == 0) {
            /* get the first policy */
            status = KsmPolicy(result, policy);
            KsmPolicyRead(policy);

            while (status == 0) {
                append_policy(doc, policy);

                /* get next policy */
                status = KsmPolicy(result, policy);
                KsmPolicyRead(policy);

            }
        }

        xmlSaveFormatFile("-", doc, 1);

        xmlFreeDoc(doc);
        KsmPolicyFree(policy);
    }
    else {
        /* ASKED TO EXPORT KEY OR DS RECORD */

        /* check that the zone name is valid and use it to get some ids */
        if (qualifier != NULL) {
            status = KsmZoneIdFromName(qualifier, &zone_id);
            if (status != 0) {
                printf("Error: unable to find a zone named \"%s\" in database\n", qualifier);
                return(status);
            }
        }

        status = hsm_open(config, hsm_prompt_pin, NULL);
        if (status) {
            hsm_print_error(NULL);
            exit(-1);
        }

        sql = DqsSpecifyInit("KEYDATA_VIEW", DB_KEYDATA_FIELDS);
        DqsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, state_id, 0);
        DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype_id, 1);
        if (zone_id != -1) {
            DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, 2);
        }
        DqsEnd(&sql);

        status = KsmKeyInitSql(&result, sql);
        if (status == 0) {
            status = KsmKey(result, &data);
            while (status == 0) {

                /* Code to output the DNSKEY record  (stolen from hsmutil) */
                key = hsm_find_key_by_id(NULL, data.location);

                if (!key) {
                    printf("Key %s in DB but not repository\n", data.location);
                    return -1;
                }

                sign_params = hsm_sign_params_new();
                /* If zone_id == -1 then we need to work out the zone name from data.zone_id */
                if (zone_id == -1) {
                    status = KsmZoneNameFromId(data.zone_id, &zone_name);
                    if (status != 0) {
                        printf("Error: unable to find zone name for id %d\n", zone_id);
                        return(status);
                    }
                    sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, zone_name);
                    StrFree(zone_name);
                }
                else {
                    sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, qualifier);
                }

                sign_params->algorithm = data.algorithm;
                sign_params->flags = LDNS_KEY_ZONE_KEY;
                if (keytype_id == KSM_TYPE_KSK) {
                    sign_params->flags += LDNS_KEY_SEP_KEY;
                }
                dnskey_rr = hsm_get_dnskey(NULL, key, sign_params);
                sign_params->keytag = ldns_calc_keytag(dnskey_rr);

                if (strncmp(case_subcommand, "KEYS", 4) == 0) {
                    printf("\n%s %s DNSKEY record:\n\n", KsmKeywordStateValueToName(state_id), (keytype_id == KSM_TYPE_KSK ? "KSK" : "ZSK"));
                    ldns_rr_print(stdout, dnskey_rr);
                }
                else {

                    printf("\n%s %s DS record (SHA1):\n\n", KsmKeywordStateValueToName(state_id), (keytype_id == KSM_TYPE_KSK ? "KSK" : "ZSK"));
                    ds_sha1_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA1);
                    ldns_rr_print(stdout, ds_sha1_rr);

                    printf("\n%s %s DS record (SHA256):\n\n", KsmKeywordStateValueToName(state_id), (keytype_id == KSM_TYPE_KSK ? "KSK" : "ZSK"));
                    ds_sha256_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA256);
                    ldns_rr_print(stdout, ds_sha256_rr);
                }

                status = KsmKey(result, &data);

            }
            /* Convert EOF status to success */
            if (status == -1) {
                status = 0;
            }

            KsmKeyEnd(result);
        }

        /* TODO when the above is working then replicate it twice for the case where keytype == -1 */

        hsm_sign_params_free(sign_params);
        if (dnskey_rr != NULL) {
            ldns_rr_free(dnskey_rr);
        }
        if (ds_sha1_rr != NULL) {
            ldns_rr_free(ds_sha1_rr);
        }
        if (ds_sha256_rr != NULL) {
            ldns_rr_free(ds_sha256_rr);
        }
        hsm_key_free(key);

    }

    StrFree(case_subcommand);
    DbDisconnect(dbhandle);

    return 0;
}

/*
 * To rollover a zone (or all zones on a policy if keys are shared)
 */
    int
cmd_rollzone (int argc, char *argv[])
{
    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */
    char* lock_filename;    /* name for the lock file (so we can close it) */

    char *dbschema = NULL;
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *password = NULL;
    char* db_backup_filename = NULL;
    DB_RESULT	result;         /* Result of parameter query */
    KSM_PARAMETER data;         /* Parameter information */
    
    char* zone_name = NULL;
    int key_type = 0;
    int zone_id = 0;
    int policy_id = 0;

    int status = 0;
    int user_certain;

    char*   datetime = DtParseDateTimeString("now");

    if (argc > 2 || argc == 0) {
        usage_rollzone();
        return -1;
    }

    /* See what arguments we were passed */
    StrAppend(&zone_name, argv[0]);
    if (argc == 2) {
        StrToLower(argv[1]);
        key_type = KsmKeywordTypeNameToValue(argv[1]);
    }

    /* Read the database details out of conf.xml */
    status = get_db_details(&dbschema, &host, &port, &user, &password);
    if (status != 0) {
        StrFree(host);
        StrFree(port);
        StrFree(dbschema);
        StrFree(user);
        StrFree(password);
        return(status);
    }

    /* If we are in sqlite mode then take a lock out on a file to
       prevent multiple access (not sure that we can be sure that sqlite is
       safe for multiple processes to access). */
    if (DbFlavour() == SQLITE_DB) {

        /* set up lock filename (it may have changed?) */
        lock_filename = NULL;
        StrAppend(&lock_filename, dbschema);
        StrAppend(&lock_filename, ".our_lock");

        lock_fd = fopen(lock_filename, "w");
        status = get_lite_lock(lock_filename, lock_fd);
        if (status != 0) {
            printf("Error getting db lock\n");
            if (lock_fd != NULL) {
                fclose(lock_fd);
            }
            StrFree(dbschema);
            return(1);
        }

        /* Make a backup of the sqlite DB */
        StrAppend(&db_backup_filename, dbschema);
        StrAppend(&db_backup_filename, ".backup");

        status = backup_file(dbschema, db_backup_filename);

        StrFree(db_backup_filename);

        if (status != 0) {
            fclose(lock_fd);
            StrFree(host);
            StrFree(port);
            StrFree(dbschema);
            StrFree(user);
            StrFree(password);
            return(status);
        }
    }

    /* try to connect to the database */
    status = DbConnect(&dbhandle, dbschema, host, password, user);
    /* Free these up early */
    StrFree(host);
    StrFree(port);
    StrFree(dbschema);
    StrFree(user);
    StrFree(password);
    if (status != 0) {
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }

    status = KsmZoneIdAndPolicyFromName(zone_name, &policy_id, &zone_id);
    if (status != 0) {
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }

    /* Get the shared_keys parameter */
    status = KsmParameterInit(&result, "zones_share_keys", "keys", policy_id);
    if (status != 0) {
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }
    status = KsmParameter(result, &data);
    if (status != 0) {
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }
    KsmParameterEnd(result);
    
    /* Warn and confirm if this will roll more than one zone */
    if (data.value == 1) {
        printf("*WARNING* This zone shares keys with others, they will all be rolled; are you sure? [y/N] ");

        user_certain = getchar();
        if (user_certain != 'y' && user_certain != 'Y') {
            printf("Okay, quitting...\n");
            if (DbFlavour() == SQLITE_DB) {
                fclose(lock_fd);
            }
            exit(0);
        }
    }

    /* retire the active key(s) */
    if (key_type == 0) {
        /*status = KsmRequestSetActiveExpectedRetire(KSM_TYPE_ZSK, datetime, zone_id);*/
        KsmRequestKeys(KSM_TYPE_ZSK, 1, datetime, printKey, datetime, policy_id, zone_id, 0);
        /*if (status != 0) {
            return(status);
        }*/
        /*status = KsmRequestSetActiveExpectedRetire(KSM_TYPE_KSK, datetime, zone_id);*/
        KsmRequestKeys(KSM_TYPE_KSK, 1, datetime, printKey, datetime, policy_id, zone_id, 0);
        /*if (status != 0) {
            return(status);
        }*/
    }
    else {
        /*status = KsmRequestSetActiveExpectedRetire(key_type, datetime, zone_id);*/
        KsmRequestKeys(key_type, 1, datetime, printKey, datetime, policy_id, zone_id, 0);
        /*if (status != 0) {
            return(status);
        }*/
    }

    /* Release sqlite lock file (if we have it) */
    if (DbFlavour() == SQLITE_DB) {
        status = release_lite_lock(lock_fd);
        if (status != 0) {
            printf("Error releasing db lock");
            fclose(lock_fd);
            return(1);
        }
        fclose(lock_fd);
    }

    /* Need to poke the communicator to wake it up */
    if (system("killall -HUP communicated") != 0)
    {
        fprintf(stderr, "Could not HUP communicated\n");
    }

    DbDisconnect(dbhandle);

    return 0;
}

/*
 * To rollover all zones on a policy
 */
    int
cmd_rollpolicy (int argc, char *argv[])
{
    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */
    char* lock_filename;    /* name for the lock file (so we can close it) */

    char *dbschema = NULL;
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *password = NULL;
    char* db_backup_filename = NULL;

    DB_RESULT   result;     /* To see if the policy shares keys or not */
    KSM_PARAMETER data;     /* Parameter information */
    DB_RESULT   result2;    /* For looping over the zones on the policy */
	KSM_ZONE*   zone;
    
    char* policy_name = NULL;
    int key_type = 0;
    int policy_id = 0;

    int status = 0;
    int user_certain;

    char*   datetime = DtParseDateTimeString("now");

    if (argc > 2 || argc == 0) {
        usage_rollpolicy();
        return -1;
    }

    /* See what arguments we were passed */
    StrAppend(&policy_name, argv[0]);
    if (argc == 2) {
        StrToLower(argv[1]);
        key_type = KsmKeywordTypeNameToValue(argv[1]);
    }

    /* Read the database details out of conf.xml */
    status = get_db_details(&dbschema, &host, &port, &user, &password);
    if (status != 0) {
        StrFree(host);
        StrFree(port);
        StrFree(dbschema);
        StrFree(user);
        StrFree(password);
        return(status);
    }

    /* If we are in sqlite mode then take a lock out on a file to
       prevent multiple access (not sure that we can be sure that sqlite is
       safe for multiple processes to access). */
    if (DbFlavour() == SQLITE_DB) {

        /* set up lock filename (it may have changed?) */
        lock_filename = NULL;
        StrAppend(&lock_filename, dbschema);
        StrAppend(&lock_filename, ".our_lock");

        lock_fd = fopen(lock_filename, "w");
        status = get_lite_lock(lock_filename, lock_fd);
        if (status != 0) {
            printf("Error getting db lock\n");
            if (lock_fd != NULL) {
                fclose(lock_fd);
            }
            StrFree(dbschema);
            return(1);
        }

        /* Make a backup of the sqlite DB */
        StrAppend(&db_backup_filename, dbschema);
        StrAppend(&db_backup_filename, ".backup");

        status = backup_file(dbschema, db_backup_filename);

        StrFree(db_backup_filename);

        if (status != 0) {
            fclose(lock_fd);
            StrFree(host);
            StrFree(port);
            StrFree(dbschema);
            StrFree(user);
            StrFree(password);
            return(status);
        }
    }

    /* try to connect to the database */
    status = DbConnect(&dbhandle, dbschema, host, password, user);
    /* Free these up early */
    StrFree(host);
    StrFree(port);
    StrFree(dbschema);
    StrFree(user);
    StrFree(password);
    if (status != 0) {
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }

    status = KsmPolicyIdFromName(policy_name, &policy_id);
    if (status != 0) {
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }

    /* Warn and confirm */
    printf("*WARNING* This will roll all keys on the policy; are you sure? [y/N] ");

    user_certain = getchar();
    if (user_certain != 'y' && user_certain != 'Y') {
        printf("Okay, quitting...\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        exit(0);
    }

    /* Find out if this policy shares keys, (we only need to do one zone if this is the case) */
    status = KsmParameterInit(&result, "zones_share_keys", "keys", policy_id);
    if (status != 0) {
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }
    status = KsmParameter(result, &data);
    if (status != 0) {
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }
    KsmParameterEnd(result);
    
    status = KsmZoneInit(&result2, policy_id);
    if (status == 0) {
        
        zone = (KSM_ZONE *)malloc(sizeof(KSM_ZONE));
        zone->name = (char *)calloc(KSM_ZONE_NAME_LENGTH, sizeof(char));

        status = KsmZone(result2, zone);

        while (status == 0) {

            /* retire the active key(s) */
            if (key_type == 0) {
                KsmRequestKeys(KSM_TYPE_ZSK, 1, datetime, printKey, datetime, policy_id, zone->id, 0);
                KsmRequestKeys(KSM_TYPE_KSK, 1, datetime, printKey, datetime, policy_id, zone->id, 0);
            }
            else {
                KsmRequestKeys(key_type, 1, datetime, printKey, datetime, policy_id, zone->id, 0);
            }

            /* We can leave now if the policy shares keys */
            if (data.value == 1) {
                break;
            }

            status = KsmZone(result2, zone);
        }

        free(zone->name);
        free(zone);

    } 
    else {
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }

    /* Release sqlite lock file (if we have it) */
    if (DbFlavour() == SQLITE_DB) {
        status = release_lite_lock(lock_fd);
        if (status != 0) {
            printf("Error releasing db lock");
            fclose(lock_fd);
            return(1);
        }
        fclose(lock_fd);
    }

    /* Need to poke the communicator to wake it up */
    if (system("killall -HUP communicated") != 0)
    {
        fprintf(stderr, "Could not HUP communicated\n");
    }

    DbDisconnect(dbhandle);

    return 0;
}

/*
 * note that fact that a backup has been performed
 */
    int
cmd_backup (int argc, char *argv[])
{
    int status = 0;

    char* subcommand = NULL;
    char* case_subcommand = NULL;   /* Upper case copy of subcommand */
    char* repository = NULL;
    int repo_id = -1;

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */
    char* lock_filename;    /* name for the lock file (so we can close it) */
    char *dbschema = NULL;
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *password = NULL;
    char* db_backup_filename = NULL;

    char* datetime = DtParseDateTimeString("now");

    /* See what arguments we were passed (if any) otherwise set the defaults */
    if (argc != 1 && argc != 2) {
        usage_backup();
        return -1;
    }

    StrAppend(&subcommand, argv[0]);
    if (argc == 2) {
        StrAppend(&repository, argv[1]);
    }

    /* Read the database details out of conf.xml */
    status = get_db_details(&dbschema, &host, &port, &user, &password);
    if (status != 0) {
        StrFree(host);
        StrFree(port);
        StrFree(dbschema);
        StrFree(user);
        StrFree(password);
        return(status);
    }

    /* If we are in sqlite mode then take a lock out on a file to
       prevent multiple access (not sure that we can be sure that sqlite is
       safe for multiple processes to access). */
    if (DbFlavour() == SQLITE_DB) {

        /* set up lock filename (it may have changed?) */
        lock_filename = NULL;
        StrAppend(&lock_filename, dbschema);
        StrAppend(&lock_filename, ".our_lock");

        lock_fd = fopen(lock_filename, "w");
        status = get_lite_lock(lock_filename, lock_fd);
        if (status != 0) {
            printf("Error getting db lock\n");
            if (lock_fd != NULL) {
                fclose(lock_fd);
            }
            StrFree(dbschema);
            return(1);
        }

        /* Make a backup of the sqlite DB */
        /* TODO skip this if we are only doing a list */
        StrAppend(&db_backup_filename, dbschema);
        StrAppend(&db_backup_filename, ".backup");

        status = backup_file(dbschema, db_backup_filename);

        StrFree(db_backup_filename);

        if (status != 0) {
            fclose(lock_fd);
            StrFree(host);
            StrFree(port);
            StrFree(dbschema);
            StrFree(user);
            StrFree(password);
            return(status);
        }
    }

    /* try to connect to the database */
    status = DbConnect(&dbhandle, dbschema, host, password, user);

    /* Free these up early */
    StrFree(host);
    StrFree(port);
    StrFree(dbschema);
    StrFree(user);
    StrFree(password);

    if (status != 0) {
        printf("Failed to connect to database\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(1);
    }

    /* Turn repo name into an id (if provided) */
    if (repository != NULL) {
        status = KsmSmIdFromName(repository, &repo_id);
        if (status != 0) {
            printf("Error: unable to find a repository named \"%s\" in database\n", repository);
            return status;
        }
    }

    case_subcommand = StrStrdup(subcommand);
    (void) StrToUpper(case_subcommand);
    if (!strncmp(case_subcommand, "DONE", 4)) {

        status = KsmMarkBackup(repo_id, datetime);
        if (status != 0) {
            printf("Error: failed to mark backup as done\n");
            StrFree(case_subcommand);
            return status;
        }

        if (repository != NULL) {
            printf("Marked repository %s as backed up at %s\n", repository, datetime);
        } else {
            printf("Marked all repositories as backed up at %s\n", datetime);
        }
    }
    else if (!strncmp(case_subcommand, "LIST", 4)) {
        status = KsmListBackups(repo_id);

        if (status != 0) {
            printf("Error: failed to list backups\n");
            StrFree(case_subcommand);
            return status;
        }
    }
    else {
        printf("Unknown command \"backup %s\"\n", subcommand);
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        StrFree(case_subcommand);
        return(1);
    }
    StrFree(case_subcommand);

    /* Release sqlite lock file (if we have it) */
    if (DbFlavour() == SQLITE_DB) {
        status = release_lite_lock(lock_fd);
        if (status != 0) {
            printf("Error releasing db lock");
            fclose(lock_fd);
            return(1);
        }
        fclose(lock_fd);
    }

    DbDisconnect(dbhandle);
    return 0;
}

/*
 * List whatever was asked of us
 */
    int
cmd_list (int argc, char *argv[], int long_list)
{
    int status = 0;
    int done_something = 0;

    char* subcommand = NULL;    /* What to list */
    char* case_subcommand = NULL;    /* Upper case copy of subcommand */
    char* qualifier = NULL;     /* Any further specification */
    int qualifier_id = -1;      /* ID of qualifer (if given) */

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */
    char* lock_filename;    /* name for the lock file (so we can close it) */
    char *dbschema = NULL;
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *password = NULL;

    /* See what arguments we were passed (if any) otherwise we will list everything */
    if (argc != 0 && argc != 1 && argc != 2) {
        usage_list();
        return -1;
    }

    if (argc == 1) {
        StrAppend(&subcommand, argv[0]);
    } else if (argc == 2) {
        StrAppend(&subcommand, argv[0]);
        StrAppend(&qualifier, argv[1]);
    } else {
        StrAppend(&subcommand, "all");
    }

    /* Read the database details out of conf.xml */
    status = get_db_details(&dbschema, &host, &port, &user, &password);
    if (status != 0) {
        StrFree(host);
        StrFree(port);
        StrFree(dbschema);
        StrFree(user);
        StrFree(password);
        return(status);
    }

    /* If we are in sqlite mode then take a lock out on a file to
       prevent multiple access (not sure that we can be sure that sqlite is
       safe for multiple processes to access). */
    if (DbFlavour() == SQLITE_DB) {

        /* set up lock filename (it may have changed?) */
        lock_filename = NULL;
        StrAppend(&lock_filename, dbschema);
        StrAppend(&lock_filename, ".our_lock");

        lock_fd = fopen(lock_filename, "w");
        status = get_lite_lock(lock_filename, lock_fd);
        if (status != 0) {
            printf("Error getting db lock\n");
            if (lock_fd != NULL) {
                fclose(lock_fd);
            }
            StrFree(dbschema);
            return(1);
        }

        if (status != 0) {
            fclose(lock_fd);
            StrFree(host);
            StrFree(port);
            StrFree(dbschema);
            StrFree(user);
            StrFree(password);
            return(status);
        }
    }

    /* try to connect to the database */
    status = DbConnect(&dbhandle, dbschema, host, password, user);

    /* Free these up early */
    StrFree(host);
    StrFree(port);
    StrFree(dbschema);
    StrFree(user);
    StrFree(password);

    if (status != 0) {
        printf("Failed to connect to database\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(1);
    }

    /* Start the work here */
    case_subcommand = StrStrdup(subcommand);
    (void) StrToUpper(case_subcommand);

    /* REPOSITORIES */
    if (!strncmp(case_subcommand, "REP", 3) || !strncmp(case_subcommand, "ALL", 3)) {
        done_something = 1;
        printf("Repositories:\n");

        status = KsmListRepos();

        if (status != 0) {
            printf("Error: failed to list repositories\n");
            StrFree(case_subcommand);
            return status;
        }

        printf("\n");
    }
    /* POLICIES */
    if (!strncmp(case_subcommand, "POL", 3) || !strncmp(case_subcommand, "ALL", 3)) {
        done_something = 1;
        printf("Policies:\n");

        status = KsmListPolicies();

        if (status != 0) {
            printf("Error: failed to list policies\n");
            StrFree(case_subcommand);
            return status;
        }

        printf("\n");
    }
    /* KEYS */
    if (!strncmp(case_subcommand, "KEY", 3) || !strncmp(case_subcommand, "ALL", 3)) {
        done_something = 1;

        /* Turn zone name into an id (if provided) */
        if (qualifier != NULL) {
            status = KsmZoneIdFromName(qualifier, &qualifier_id);
            if (status != 0) {
                printf("Error: unable to find a zone named \"%s\" in database\n", qualifier);
                StrFree(case_subcommand);
                return status;
            }
        }

        printf("Keys:\n");

        status = KsmListKeys(qualifier_id, long_list);

        if (status != 0) {
            printf("Error: failed to list keys\n");
            StrFree(case_subcommand);
            return status;
        }

        printf("\n");
    }
    /* ROLLOVERS */
    if (!strncmp(case_subcommand, "ROL", 3) || !strncmp(case_subcommand, "ALL", 3)) {
        done_something = 1;

        /* Turn zone name into an id (if provided) */
        if (qualifier != NULL) {
            status = KsmZoneIdFromName(qualifier, &qualifier_id);
            if (status != 0) {
                printf("Error: unable to find a zone named \"%s\" in database\n", qualifier);
                StrFree(case_subcommand);
                return status;
            }
        }

        printf("Rollovers:\n");

        status = KsmListRollovers(qualifier_id);

        if (status != 0) {
            printf("Error: failed to list rollovers\n");
            StrFree(case_subcommand);
            return status;
        }

        printf("\n");
    }
    /* BACKUPS */
    if (!strncmp(case_subcommand, "BAC", 3) || !strncmp(case_subcommand, "ALL", 3)) {
        done_something = 1;

        /* Turn repo name into an id (if provided) */
        if (qualifier != NULL) {
            status = KsmSmIdFromName(qualifier, &qualifier_id);
            if (status != 0) {
                printf("Error: unable to find a repository named \"%s\" in database\n", qualifier);
                StrFree(case_subcommand);
                return status;
            }
        }

        printf("Backups:\n");
        status = KsmListBackups(qualifier_id);

        if (status != 0) {
            printf("Error: failed to list backups\n");
            StrFree(case_subcommand);
            return status;
        }
        printf("\n");
    }
    StrFree(case_subcommand);

    /* If done_something is still 0 then we did not recognise the option provided */
    if (done_something == 0) {
        printf("Unknown command \"list %s\"\n", subcommand);
    }

    /* Release sqlite lock file (if we have it) */
    if (DbFlavour() == SQLITE_DB) {
        status = release_lite_lock(lock_fd);
        if (status != 0) {
            printf("Error releasing db lock");
            fclose(lock_fd);
            return(1);
        }
        fclose(lock_fd);
    }

    DbDisconnect(dbhandle);
    return 0;
}

/*
 * import a key into the ksm and set its values as specified
 */
    int
cmd_import (int argc, char *argv[])
{
    int status = 0;

    char* subcommand = NULL; /* has to be "key" at the moment */
    char* cka_id = NULL;     /* will become location */
    char* hsm = NULL;        /* name of repo this key is in */
    char* zone = NULL;       /* name of zone this key is on */
    char* keytype = NULL;    /* KSK or ZSK */
    char* size = NULL;       /* Size of key in bits */
    char* algorithm = NULL;  /* RSASHA1 or RSASHA1-NSEC3-SHA1 (5 or 7) */
    char* state = NULL;      /* GENERATED, PUBLISHED, READY, ACTIVE or RETIRED */
    char* time = NULL;       /* time at which it entered the above state */
    char* opt_time = NULL;   /* time at which it should retire (maybe provided) */

    /* some strings to hold upper case versions of arguments */
    char* case_keytype = NULL;    /* KSK or ZSK */
    char* case_algorithm = NULL;  /* RSASHA1 or RSASHA1-NSEC3-SHA1 (5 or 7) */
    char* case_state = NULL;      /* GENERATED, PUBLISHED, READY, ACTIVE or RETIRED */

    int repo_id = -1;
    int zone_id = -1;
    int policy_id = -1;
    int cka_id_exists = -1; /* do we already have this id in the HSM */
    int keytype_id = -1;
    int size_int = -1;
    int algo_id = -1;
    int state_id = -1;
    char form_time[KSM_TIME_LENGTH]; /* YYYY-MM-DD HH:MM:SS + NULL Time after we reformat it */
    char form_opt_time[KSM_TIME_LENGTH]; /* Opt_time after we reformat it */

    DB_ID   keypair_id = 0;    /* This will be set when we enter the keypair */
    DB_ID   ignore = 0;        /* This will be set when we enter the dnsseckey */

    struct tm   datetime;       /* Used for getting the date/time */

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */
    char* lock_filename;    /* name for the lock file (so we can close it) */
    char *dbschema = NULL;
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *password = NULL;
    char* db_backup_filename = NULL;

    DB_RESULT	result;         /* Result of parameter query */
    KSM_PARAMETER data;         /* Parameter information */

    int user_certain;           /* Continue ? */
    
    /* See what arguments we were passed (if any) otherwise set the defaults */
    if (argc != 9 && argc != 10) {
        usage_import();
        return -1;
    }

    StrAppend(&subcommand, argv[0]);
    StrAppend(&cka_id, argv[1]);
    StrAppend(&hsm, argv[2]);
    StrAppend(&zone, argv[3]);
    StrAppend(&keytype, argv[4]);
    StrAppend(&size, argv[5]);
    StrAppend(&algorithm, argv[6]);
    StrAppend(&state, argv[7]);
    StrAppend(&time, argv[8]);
    if (argc == 10) {
        StrAppend(&opt_time, argv[9]);
    }

    if (strncmp(subcommand, "key", 3) != 0) {
        printf("Error: Unrecognised command \"import %s\"\n", subcommand);
        return(1);
    }
        

    /* Read the database details out of conf.xml */
    status = get_db_details(&dbschema, &host, &port, &user, &password);
    if (status != 0) {
        StrFree(host);
        StrFree(port);
        StrFree(dbschema);
        StrFree(user);
        StrFree(password);
        return(status);
    }

    /* If we are in sqlite mode then take a lock out on a file to
       prevent multiple access (not sure that we can be sure that sqlite is
       safe for multiple processes to access). */
    if (DbFlavour() == SQLITE_DB) {

        /* set up lock filename (it may have changed?) */
        lock_filename = NULL;
        StrAppend(&lock_filename, dbschema);
        StrAppend(&lock_filename, ".our_lock");

        lock_fd = fopen(lock_filename, "w");
        status = get_lite_lock(lock_filename, lock_fd);
        if (status != 0) {
            printf("Error getting db lock\n");
            if (lock_fd != NULL) {
                fclose(lock_fd);
            }
            StrFree(dbschema);
            return(1);
        }

        /* Make a backup of the sqlite DB */
        StrAppend(&db_backup_filename, dbschema);
        StrAppend(&db_backup_filename, ".backup");

        status = backup_file(dbschema, db_backup_filename);

        StrFree(db_backup_filename);

        if (status != 0) {
            fclose(lock_fd);
            StrFree(host);
            StrFree(port);
            StrFree(dbschema);
            StrFree(user);
            StrFree(password);
            return(status);
        }
    }

    /* try to connect to the database */
    status = DbConnect(&dbhandle, dbschema, host, password, user);

    /* Free these up early */
    StrFree(host);
    StrFree(port);
    StrFree(dbschema);
    StrFree(user);
    StrFree(password);

    if (status != 0) {
        printf("Failed to connect to database\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(1);
    }

    /* check that the repository specified exists */
    status = KsmSmIdFromName(hsm, &repo_id);
    if (status != 0) {
        printf("Error: unable to find a repository named \"%s\" in database\n", hsm);
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return status;
    }

    /* check that the zone name is valid and use it to get some ids */
    status = KsmZoneIdAndPolicyFromName(zone, &policy_id, &zone_id);
    if (status != 0) {
        printf("Error: unable to find a zone named \"%s\" in database\n", zone);
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }

    /* Check that the cka_id does not exist (in the specified HSM) */
    status = (KsmCheckHSMkeyID(repo_id, cka_id, &cka_id_exists));
    if (status != 0) {
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }
    if (cka_id_exists == 1) {
        printf("Error: key with cka_id \"%s\" already exists in database\n", cka_id);
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(1);
    }

    /* Check the Keytype */
    case_keytype = StrStrdup(keytype);
    (void) StrToUpper(case_keytype);
    if (strncmp(case_keytype, "KSK", 3) == 0 || strncmp(keytype, "257", 3) == 0) {
        keytype_id = 257;
    }
    else if (strncmp(case_keytype, "ZSK", 3) == 0 || strncmp(keytype, "256", 3) == 0) {
        keytype_id = 256;
    }
    else {
        printf("Error: Unrecognised keytype %s; should be one of KSK or ZSK\n", keytype);

        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        StrFree(case_keytype);
        return(1);
    }
    StrFree(case_keytype);
        
    /* Check the size is numeric */
    if (StrIsDigits(size)) {
        status = StrStrtoi(size, &size_int);
        if (status != 0) {
            printf("Error: Unable to convert size \"%s\"; to an integer\n", size);
            if (DbFlavour() == SQLITE_DB) {
                fclose(lock_fd);
            }
            return(status);
        }
    }
    else {
        printf("Error: Size \"%s\"; should be numeric only\n", size);
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }
        
    /* Check the algorithm */
    case_algorithm = StrStrdup(algorithm);
    (void) StrToUpper(case_algorithm);
    if (strncmp(case_algorithm, "RSASHA1", 7) == 0 || strncmp(algorithm, "5", 1) == 0) {
        algo_id = 5;
    }
    else if (strncmp(case_algorithm, "RSASHA1-NSEC3-SHA1", 18) == 0 || strncmp(algorithm, "7", 1) == 0) {
        algo_id = 7;
    }
    else {
        printf("Error: Unrecognised algorithm %s; should be one of RSASHA1 or RSASHA1-NSEC3-SHA1\n", algorithm);

        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        StrFree(case_algorithm);
        return(1);
    }
    StrFree(case_algorithm);

    /* Check the state */
    case_state = StrStrdup(state);
    (void) StrToUpper(case_state);
    if (strncmp(case_state, "GENERATE", 8) == 0 || strncmp(state, "1", 1) == 0) {
        state_id = 1;
    }
    else if (strncmp(case_state, "PUBLISH", 7) == 0 || strncmp(state, "2", 1) == 0) {
        state_id = 2;
    }
    else if (strncmp(case_state, "READY", 5) == 0 || strncmp(state, "3", 1) == 0) {
        state_id = 3;
    }
    else if (strncmp(case_state, "ACTIVE", 6) == 0 || strncmp(state, "4", 1) == 0) {
        state_id = 4;
    }
    else if (strncmp(case_state, "RETIRE", 6) == 0 || strncmp(state, "5", 1) == 0) {
        state_id = 5;
    }
    else {
        printf("Error: Unrecognised state %s; should be one of GENERATED, PUBLISHED, READY, ACTIVE or RETIRED\n", state);

        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        StrFree(case_state);
        return(1);
    }
    StrFree(case_state);

    /* Check, and convert, the time(s) */
    status = DtGeneral(time, &datetime);
    if (status != 0) {
        printf("Error: unable to convert \"%s\" into a date\n", time);
        date_help();

        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }
    else {
        snprintf(form_time, KSM_TIME_LENGTH, "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
            datetime.tm_year + 1900, datetime.tm_mon + 1, datetime.tm_mday,
            datetime.tm_hour, datetime.tm_min, datetime.tm_sec);
    }

    if (opt_time != NULL) {
        /* can only specify a retire time if the key is being inserted in the active state */
        if (state_id != KSM_STATE_ACTIVE) {
            printf("Error: unable to specify retire time for a key in state \"%s\"\n", state);
            if (DbFlavour() == SQLITE_DB) {
                fclose(lock_fd);
            }
            return(status);
        }

        status = DtGeneral(opt_time, &datetime);
        if (status != 0) {
            printf("Error: unable to convert retire time \"%s\" into a date\n", opt_time);
            date_help();

            if (DbFlavour() == SQLITE_DB) {
                fclose(lock_fd);
            }
            return(status);
        }
        else {
            snprintf(form_opt_time, KSM_TIME_LENGTH, "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
                    datetime.tm_year + 1900, datetime.tm_mon + 1, datetime.tm_mday,
                    datetime.tm_hour, datetime.tm_min, datetime.tm_sec);
        }
    }

    /* Find out if this zone has any others on a "shared keys" policy and warn */
    status = KsmParameterInit(&result, "zones_share_keys", "keys", policy_id);
    if (status != 0) {
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }
    status = KsmParameter(result, &data);
    if (status != 0) {
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }
    KsmParameterEnd(result);
    
    /* Warn and confirm if this will roll more than one zone */
    if (data.value == 1) {
        printf("*WARNING* This zone shares keys with others, the key will be added to all; are you sure? [y/N] ");

        user_certain = getchar();
        if (user_certain != 'y' && user_certain != 'Y') {
            printf("Okay, quitting...\n");
            if (DbFlavour() == SQLITE_DB) {
                fclose(lock_fd);
            }
            exit(0);
        }
    }

    /* create basic keypair */
    status = KsmImportKeyPair(policy_id, cka_id, repo_id, size_int, algo_id, state_id, form_time, form_opt_time, &keypair_id);
    if (status != 0) {
        printf("Error: couldn't import key\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }

    /* allocate key to zone(s) */
    if (data.value == 1) {
        status = KsmDnssecKeyCreateOnPolicy(policy_id, (int) keypair_id, keytype_id);
    } else {
        status = KsmDnssecKeyCreate(zone_id, (int) keypair_id, keytype_id, &ignore);
    }

    if (status != 0) {
        printf("Error: couldn't allocate key to zone(s)\n");
        if (DbFlavour() == SQLITE_DB) {
            fclose(lock_fd);
        }
        return(status);
    }

    printf("Key imported into zone(s)\n");

    /* Release sqlite lock file (if we have it) */
    if (DbFlavour() == SQLITE_DB) {
        status = release_lite_lock(lock_fd);
        if (status != 0) {
            printf("Error releasing db lock");
            fclose(lock_fd);
            return(1);
        }
        fclose(lock_fd);
    }

    DbDisconnect(dbhandle);
    return 0;
}

/* 
 * Fairly basic main, just pass most things through to their handlers
 */
    int
main (int argc, char *argv[])
{
    int result;
    int ch;
    int long_list = 0;
    int do_all = 0;
    char* case_command = NULL;

    while ((ch = getopt(argc, argv, "af:hl")) != -1) {
        switch (ch) {
            case 'a':
                do_all = 1;
                break;
            case 'f':
                config = strdup(optarg);
                break;
            case 'h':
                usage();
                date_help();
                exit(0);
                break;
            case 'l':
                long_list = 1;
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

    /*(void) KsmInit();*/
    MsgInit();
    MsgRegister(KME_MIN_VALUE, KME_MAX_VALUE, m_messages, ksm_log_msg);
    MsgRegister(DBS_MIN_VALUE, DBS_MAX_VALUE, d_messages, ksm_log_msg);

    /* We may need this when we eventually import/export keys
       result = hsm_open(config, hsm_prompt_pin, NULL);
       if (result) {
       fprintf(stderr, "hsm_open() returned %d\n", result);
       exit(-1);
       } */

    case_command = StrStrdup(argv[0]);
    (void) StrToUpper(case_command);

    if (!strncmp(case_command, "SETUP", 5)) {
        argc --;
        argv ++;
        result = cmd_setup(argc, argv);
    } else if (!strncmp(case_command, "UPDATE", 6)) {
        argc --;
        argv ++;
        result = cmd_update(argc, argv);
    } else if (!strncmp(case_command, "ADDZONE", 7)) {
        argc --;
        argv ++;
        result = cmd_addzone(argc, argv);
    } else if (!strncmp(case_command, "DELZONE", 7)) {
        argc --;
        argv ++;
        result = cmd_delzone(argc, argv, do_all);
    } else if (!strncmp(case_command, "LISTZONE", 8)) {
        argc --;
        argv ++;
        result = cmd_listzone(argc, argv);
    } else if (!strncmp(case_command, "EXPORT", 6)) {
        argc --;
        argv ++;
        result = cmd_export(argc, argv, do_all);
    } else if (!strncmp(case_command, "ROLLZONE", 8)) {
        argc --;
        argv ++;
        result = cmd_rollzone(argc, argv);
    } else if (!strncmp(case_command, "ROLLPOLICY", 10)) {
        argc --;
        argv ++;
        result = cmd_rollpolicy(argc, argv);
    } else if (!strncmp(case_command, "BACKUP", 6)) {
        argc --;
        argv ++;
        result = cmd_backup(argc, argv);
    } else if (!strncmp(case_command, "LIST", 4)) {
        argc --;
        argv ++;
        result = cmd_list(argc, argv, long_list);
    } else if (!strncmp(case_command, "IMPORT", 6)) {
        argc --;
        argv ++;
        result = cmd_import(argc, argv);
    } else {
        printf("Unknown command: %s\n", argv[0]);
        usage();
        result = -1;
    }

    StrFree(case_command);

    /*(void) hsm_close();*/
    /*if (config) free(config);*/

    exit(result);
}


/* 
 * Given a conf.xml location connect to the database contained within it
 *
 * A lock will be taken out on the DB if it is SQLite; so it is important to release it
 * in the calling Fn when we are done with it.
 *
 * Returns 0 if a connection was made.
 *         1 if a connection could not be made.
 *        -1 if any of the config files could not be read/parsed
 *
 */
    int
db_connect(DB_HANDLE *dbhandle, FILE** lock_fd, char** lock_filename)
{
    /* what we will read from the file */
    char *dbschema = NULL;
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *password = NULL;

    int status;

    char* backup_filename = NULL;

    /* Read the database details out of conf.xml */
    status = get_db_details(&dbschema, &host, &port, &user, &password);
    if (status != 0) {
        StrFree(host);
        StrFree(port);
        StrFree(dbschema);
        StrFree(user);
        StrFree(password);
        return(status);
    }

    /* If we are in sqlite mode then take a lock out on a file to
       prevent multiple access (not sure that we can be sure that sqlite is
       safe for multiple processes to access). */
    if (DbFlavour() == SQLITE_DB) {

        /* set up lock filename (it may have changed?) */
        *lock_filename = NULL;
        StrAppend(lock_filename, dbschema);
        StrAppend(lock_filename, ".our_lock");

        *lock_fd = fopen(*lock_filename, "w");
        status = get_lite_lock(*lock_filename, *lock_fd);
        if (status != 0) {
            printf("Error getting db lock\n");
            if (lock_fd != NULL) {
                fclose(*lock_fd);
            }
            StrFree(dbschema);
            return(1);
        }

        /* Make a backup of the sqlite DB */
        StrAppend(&backup_filename, dbschema);
        StrAppend(&backup_filename, ".backup");

        status = backup_file(dbschema, backup_filename);

        StrFree(backup_filename);

        if (status != 0) {
            fclose(*lock_fd);
            StrFree(host);
            StrFree(port);
            StrFree(dbschema);
            StrFree(user);
            StrFree(password);
            return(status);
        }

    }

    /* Finally we can do what we came here to do, connect to the database */
    status = DbConnect(dbhandle, dbschema, host, password, user);

    /* Cleanup */
    StrFree(host);
    StrFree(port);
    StrFree(dbschema);
    StrFree(user);
    StrFree(password);

    return(status);
}

/* To overcome the potential differences in sqlite compile flags assume that it is not
   happy with multiple connections.

   The following 2 functions take out a lock and release it
 */

int get_lite_lock(char *lock_filename, FILE* lock_fd)
{
    struct flock fl;
    struct timeval tv;

    if (lock_fd == NULL) {
        printf("%s could not be opened\n", lock_filename);
        return 1;
    }

    memset(&fl, 0, sizeof(struct flock));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_pid = getpid();

    while (fcntl(fileno(lock_fd), F_SETLK, &fl) == -1) {
        if (errno == EACCES || errno == EAGAIN) {
            printf("%s already locked, sleep\n", lock_filename);

            /* sleep for 10 seconds TODO make this configurable? */
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            select(0, NULL, NULL, NULL, &tv);

        } else {
            printf("couldn't get lock on %s; %s\n", lock_filename, strerror(errno));
            return 1;
        }
    }

    return 0;

}

int release_lite_lock(FILE* lock_fd)
{
    struct flock fl;

    if (lock_fd == NULL) {
        return 1;
    }

    memset(&fl, 0, sizeof(struct flock));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fileno(lock_fd), F_SETLK, &fl) == -1) {
        return 1;
    }

    return 0;
}

/* 
 *  Read the conf.xml file, we will not validate as that was done as we read the database.
 *  Instead we just extract the RepositoryList into the database and also learn the 
 *  location of the zonelist.
 */
int update_repositories(char** zone_list_filename, char** kasp_filename)
{
    int status = 0;
    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    int ret = 0; /* status of the XML parsing */
    char* filename = NULL;
    char* repo_name = NULL;
    char* repo_capacity = NULL;
    int require_backup = 0;
    char* tag_name = NULL;
    char* temp_char = NULL;

    xmlChar *name_expr = (unsigned char*) "name";
    xmlChar *capacity_expr = (unsigned char*) "//Repository/Capacity";
    xmlChar *backup_expr = (unsigned char*) "//Repository/RequireBackup";
    xmlChar *zonelist_expr = (unsigned char*) "//Common/ZoneListFile";
    xmlChar *kaspfile_expr = (unsigned char*) "//Common/PolicyFile";

    /* Start reading the file; we will be looking for "Repository" tags */ 
    reader = xmlNewTextReaderFilename(config);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            tag_name = (char*) xmlTextReaderLocalName(reader);
            /* Found <Repository> */
            if (strncmp(tag_name, "Repository", 10) == 0 
                    && strncmp(tag_name, "RepositoryList", 14) != 0
                    && xmlTextReaderNodeType(reader) == 1) {
                /* Get the repository name */
                repo_name = NULL;
                temp_char = (char*) xmlTextReaderGetAttribute(reader, name_expr);
                StrAppend(&repo_name, temp_char);
                StrFree(temp_char);
                /* Make sure that we got something */
                if (repo_name == NULL) {
                    /* error */
                    printf("Error extracting repository name from %s\n", config);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                printf("Repository %s found\n", repo_name);

                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                doc = xmlTextReaderCurrentDoc(reader);
                if (doc == NULL) {
                    printf("Error: can not read repository \"%s\"; skipping\n", repo_name);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                xpathCtx = xmlXPathNewContext(doc);
                if(xpathCtx == NULL) {
                    printf("Error: can not create XPath context for \"%s\"; skipping repository\n", repo_name);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* Evaluate xpath expression for capacity */
                xpathObj = xmlXPathEvalExpression(capacity_expr, xpathCtx);

                if(xpathObj == NULL) {
                    printf("Error: unable to evaluate xpath expression: %s; skipping repository\n", capacity_expr);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                repo_capacity = NULL;
                temp_char = (char*) xmlXPathCastToString(xpathObj);
                StrAppend(&repo_capacity, temp_char);
                StrFree(temp_char);
                if (strlen(repo_capacity) == 0) {
                    printf("No Maximum Capacity set.\n");
                } else {
                    printf("Capacity set to %s.\n", repo_capacity);
                }

                xmlXPathFreeObject(xpathObj);

                /* See if we were gven a "RequireBackup" tag or not */
                xpathObj = xmlXPathEvalExpression(backup_expr, xpathCtx);
                xmlXPathFreeContext(xpathCtx);

                if(xpathObj == NULL) {
                    printf("Error: unable to evaluate xpath expression: %s; skipping repository\n", backup_expr);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if (xpathObj->nodesetval->nodeNr > 0) {
                    /*
                     * tag present
                     */
                    require_backup = 1;
                    printf("RequireBackup set.\n");
                } else {
                    require_backup = 0;
                    printf("RequireBackup NOT set; please make sure that you know the potential problems of using keys which are not recoverable\n");
                }

                xmlXPathFreeObject(xpathObj);
                
                /*
                 * Now we have all the information update/insert this repository
                 */
                status = KsmImportRepository(repo_name, repo_capacity, require_backup);
                if (status != 0) {
                    printf("Error Importing Repository %s", repo_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                StrFree(repo_name);
                StrFree(repo_capacity);
            }
            /* Found <Common> */
            else if (strncmp(tag_name, "Common", 6) == 0 
                    && xmlTextReaderNodeType(reader) == 1) {

                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                doc = xmlTextReaderCurrentDoc(reader);
                if (doc == NULL) {
                    printf("Error: can not read Common section\n");
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                xpathCtx = xmlXPathNewContext(doc);
                if(xpathCtx == NULL) {
                    printf("Error: can not create XPath context for Common section\n");
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* Evaluate xpath expression for ZoneListFile */
                xpathObj = xmlXPathEvalExpression(zonelist_expr, xpathCtx);
                if(xpathObj == NULL) {
                    printf("Error: unable to evaluate xpath expression: %s\n", zonelist_expr);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                *zone_list_filename = NULL;
                temp_char = (char*) xmlXPathCastToString(xpathObj);
                StrAppend(zone_list_filename, temp_char);
                StrFree(temp_char);
                xmlXPathFreeObject(xpathObj);
                printf("zonelist filename set to %s.\n", *zone_list_filename);

                /* Evaluate xpath expression for KaspFile */
                xpathObj = xmlXPathEvalExpression(kaspfile_expr, xpathCtx);
                xmlXPathFreeContext(xpathCtx);
                if(xpathObj == NULL) {
                    printf("Error: unable to evaluate xpath expression: %s\n", kaspfile_expr);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                *kasp_filename = NULL;
                if (xpathObj->nodesetval->nodeNr > 0) {
                    /*
                     * Found Something, set it
                     */
                    temp_char = (char*) xmlXPathCastToString(xpathObj);
                    StrAppend(kasp_filename, temp_char);
                    StrFree(temp_char);
                } else {
                    /*
                     * Set a default
                     */
                    /* XXX this should be parse from the the main config */
                    StrAppend(kasp_filename, CONFIG_DIR);
                    StrAppend(kasp_filename, "/kasp.xml");
                }
                printf("kasp filename set to %s.\n", *kasp_filename);

                xmlXPathFreeObject(xpathObj);
            }
            /* Read the next line */
            ret = xmlTextReaderRead(reader);

            StrFree(tag_name);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            printf("%s : failed to parse\n", filename);
        }
    } else {
        printf("Unable to open %s\n", filename);
    }
    if (doc) {
        xmlFreeDoc(doc);
    }

    StrFree(filename);

    return 0;
}

/* Read kasp.xml, validate it and grab each policy in it as we go. */
int update_policies(char* kasp_filename)
{
    int status;

    /* what we will read from the file */
    char *policy_name;
    char *policy_description;
    char *audit_contents;
    char *temp_char;
    char *tag_name;
    char *tag_name2;

    /* All of the XML stuff */
    int ret = 0; /* status of the XML parsing */
    int ret2 = 0; /* status of the XML parsing */
    xmlDocPtr doc = NULL;
    xmlDocPtr pol_doc = NULL;
    xmlDocPtr rngdoc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlRelaxNGParserCtxtPtr rngpctx = NULL;
    xmlRelaxNGValidCtxtPtr rngctx = NULL;
    xmlRelaxNGPtr schema = NULL;
    xmlTextReaderPtr reader = NULL;
    xmlTextReaderPtr reader2 = NULL;

    xmlChar *name_expr = (unsigned char*) "name";
    xmlChar *desc_expr = (unsigned char*) "//Policy/Description";

    xmlChar *sig_res_expr = (unsigned char*) "//Policy/Signatures/Resign";
    xmlChar *sig_ref_expr = (unsigned char*) "//Policy/Signatures/Refresh";
    xmlChar *val_def_expr = (unsigned char*) "//Policy/Signatures/Validity/Default";
    xmlChar *val_den_expr = (unsigned char*) "//Policy/Signatures/Validity/Denial";
    xmlChar *sig_jit_expr = (unsigned char*) "//Policy/Signatures/Jitter";
    xmlChar *sig_off_expr = (unsigned char*) "//Policy/Signatures/InceptionOffset";

    xmlChar *den_nsec3_expr = (unsigned char*) "//Policy/Denial/NSEC3";

    xmlChar *den_opt_expr = (unsigned char*) "//Policy/Denial/NSEC3/OptOut";
    xmlChar *den_resalt_expr = (unsigned char*) "//Policy/Denial/NSEC3/Resalt";
    xmlChar *den_alg_expr = (unsigned char*) "//Policy/Denial/NSEC3/Hash/Algorithm";
    xmlChar *den_iter_expr = (unsigned char*) "//Policy/Denial/NSEC3/Hash/Iterations";
    xmlChar *den_salt_expr = (unsigned char*) "//Policy/Denial/NSEC3/Hash/Salt/@length";

    xmlChar *keys_ttl_expr = (unsigned char*) "//Policy/Keys/TTL";
    xmlChar *keys_ret_expr = (unsigned char*) "//Policy/Keys/RetireSafety";
    xmlChar *keys_pub_expr = (unsigned char*) "//Policy/Keys/PublishSafety";
    xmlChar *keys_share_expr = (unsigned char*) "//Policy/Keys/ShareKeys";

    xmlChar *ksk_alg_expr = (unsigned char*) "//Policy/Keys/KSK/Algorithm";
    xmlChar *ksk_alg_len_expr = (unsigned char*) "//Policy/Keys/KSK/Algorithm/@length";
    xmlChar *ksk_life_expr = (unsigned char*) "//Policy/Keys/KSK/Lifetime";
    xmlChar *ksk_repo_expr = (unsigned char*) "//Policy/Keys/KSK/Repository";
    xmlChar *ksk_emer_expr = (unsigned char*) "//Policy/Keys/KSK/Emergency";
    xmlChar *ksk_5011_expr = (unsigned char*) "//Policy/Keys/KSK/RFC5011";

    xmlChar *zsk_alg_expr = (unsigned char*) "//Policy/Keys/ZSK/Algorithm";
    xmlChar *zsk_alg_len_expr = (unsigned char*) "//Policy/Keys/ZSK/Algorithm/@length";
    xmlChar *zsk_life_expr = (unsigned char*) "//Policy/Keys/ZSK/Lifetime";
    xmlChar *zsk_repo_expr = (unsigned char*) "//Policy/Keys/ZSK/Repository";
    xmlChar *zsk_emer_expr = (unsigned char*) "//Policy/Keys/ZSK/Emergency";

    xmlChar *zone_prop_expr = (unsigned char*) "//Policy/Zone/PropagationDelay";
    xmlChar *zone_soa_ttl_expr = (unsigned char*) "//Policy/Zone/SOA/TTL";
    xmlChar *zone_min_expr = (unsigned char*) "//Policy/Zone/SOA/Minimum";
    xmlChar *zone_serial_expr = (unsigned char*) "//Policy/Zone/SOA/Serial";

    xmlChar *parent_prop_expr = (unsigned char*) "//Policy/Parent/PropagationDelay";
    xmlChar *parent_ds_ttl_expr = (unsigned char*) "//Policy/Parent/DS/TTL";
    xmlChar *parent_soa_ttl_expr = (unsigned char*) "//Policy/Parent/SOA/TTL";
    xmlChar *parent_min_expr = (unsigned char*) "//Policy/Parent/SOA/Minimum";

/*    xmlChar *audit_expr = (unsigned char*) "//Policy/Audit"; */
    int audit_found = 0;    /* flag to say whether an Audit flag was found or not */

    KSM_POLICY *policy;

    /* Some files, the xml and rng */
    const char* rngfilename = SCHEMA_DIR "/kasp.rng";

    /* Load XML document */
    doc = xmlParseFile(kasp_filename);
    if (doc == NULL) {
        printf("Error: unable to parse file \"%s\"\n", kasp_filename);
        return(-1);
    }

    /* Load rng document: TODO make the rng stuff optional? */
    rngdoc = xmlParseFile(rngfilename);
    if (rngdoc == NULL) {
        printf("Error: unable to parse file \"%s\"\n", rngfilename);
        return(-1);
    }

    /* Create an XML RelaxNGs parser context for the relax-ng document. */
    rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);
    if (rngpctx == NULL) {
        printf("Error: unable to create XML RelaxNGs parser context\n");
        return(-1);
    }

    /* parse a schema definition resource and build an internal XML Shema struture which can be used to validate instances. */
    schema = xmlRelaxNGParse(rngpctx);
    if (schema == NULL) {
        printf("Error: unable to parse a schema definition resource\n");
        return(-1);
    }

    /* Create an XML RelaxNGs validation context based on the given schema */
    rngctx = xmlRelaxNGNewValidCtxt(schema);
    if (rngctx == NULL) {
        printf("Error: unable to create RelaxNGs validation context based on the schema\n");
        return(-1);
    }

    /* Validate a document tree in memory. */
    status = xmlRelaxNGValidateDoc(rngctx,doc);
    if (status != 0) {
        printf("Error validating file \"%s\"\n", kasp_filename);
        return(-1);
    }

    /* Allocate some space for our policy */
    policy = (KSM_POLICY *)malloc(sizeof(KSM_POLICY));
    policy->signer = (KSM_SIGNER_POLICY *)malloc(sizeof(KSM_SIGNER_POLICY));
    policy->signature = (KSM_SIGNATURE_POLICY *)malloc(sizeof(KSM_SIGNATURE_POLICY));
    policy->zone = (KSM_ZONE_POLICY *)malloc(sizeof(KSM_ZONE_POLICY));
    policy->parent = (KSM_PARENT_POLICY *)malloc(sizeof(KSM_PARENT_POLICY));
    policy->keys = (KSM_COMMON_KEY_POLICY *)malloc(sizeof(KSM_COMMON_KEY_POLICY));
    policy->ksk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
    policy->zsk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
    policy->denial = (KSM_DENIAL_POLICY *)malloc(sizeof(KSM_DENIAL_POLICY));
    policy->enforcer = (KSM_ENFORCER_POLICY *)malloc(sizeof(KSM_ENFORCER_POLICY));
/*    policy->audit = (KSM_AUDIT_POLICY *)malloc(sizeof(KSM_AUDIT_POLICY)); */
    policy->audit = (char *)calloc(KSM_POLICY_AUDIT_LENGTH, sizeof(char));
    policy->description = (char *)calloc(KSM_POLICY_DESC_LENGTH, sizeof(char));
    /* Let's check all of those mallocs, or should we use MemMalloc ? */
    if (policy->signer == NULL || policy->signature == NULL || policy->keys == NULL ||
            policy->zone == NULL || policy->parent == NULL || 
            policy->ksk == NULL || policy->zsk == NULL || 
            policy->denial == NULL || policy->enforcer == NULL) {
        printf("Malloc for policy struct failed\n");
        exit(1);
    }

    /* Switch to the XmlTextReader API so that we can consider each policy separately */
    reader = xmlNewTextReaderFilename(kasp_filename);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            tag_name = (char*) xmlTextReaderLocalName(reader);
            /* Found <Policy> */
            if (strncmp(tag_name, "Policy", 6) == 0 
                    && xmlTextReaderNodeType(reader) == 1) {
                /* Get the policy name */
                policy_name = NULL;
                temp_char = (char*) xmlTextReaderGetAttribute(reader, name_expr);
                StrAppend(&policy_name, temp_char);
                StrFree(temp_char);
                /* Make sure that we got something */
                if (policy_name == NULL) {
                    /* error */
                    printf("Error extracting policy name from %s\n", kasp_filename);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                printf("Policy %s found\n", policy_name);

                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                pol_doc = xmlTextReaderCurrentDoc(reader);
                if (pol_doc == NULL) {
                    printf("Error: can not read policy \"%s\"; skipping\n", policy_name);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                xpathCtx = xmlXPathNewContext(pol_doc);

                if(xpathCtx == NULL) {
                    printf("Error: can not create XPath context for \"%s\"; skipping policy\n", policy_name);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* Evaluate xpath expression for Description */
                xpathObj = xmlXPathEvalExpression(desc_expr, xpathCtx);
                if(xpathObj == NULL) {
                    printf("Error: unable to evaluate xpath expression: %s; skipping policy\n", desc_expr);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                policy_description = NULL;
                temp_char = (char *)xmlXPathCastToString(xpathObj);
                StrAppend(&policy_description, temp_char);
                StrFree(temp_char);
                xmlXPathFreeObject(xpathObj);

                /* Insert or update this policy with the description found,
                   we will need the policy_id too */
                SetPolicyDefaults(policy, policy_name);
                status = KsmPolicyExists(policy_name);
                if (status == 0) {
                    /* Policy exists; we will be updating it */
                    status = KsmPolicyRead(policy);
                    if(status != 0) {
                        printf("Error: unable to read policy %s; skipping\n", policy_name);
                        /* Don't return? try to parse the rest of the file? */
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }
                    /* TODO Set description here ? */
                }
                else {
                    /* New policy, insert it and get the new policy_id */
                    status = KsmImportPolicy(policy_name, policy_description);
                    if(status != 0) {
                        printf("Error: unable to insert policy %s; skipping\n", policy_name);
                        /* Don't return? try to parse the rest of the file? */
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }
                    status = KsmPolicySetIdFromName(policy);

                    if (status != 0) {
                        printf("Error: unable to get policy id for %s; skipping\n", policy_name);
                        /* Don't return? try to parse the rest of the file? */
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }

                }

                /* Free up some stuff that we don't need any more */
                StrFree(policy_name);
                StrFree(policy_description);

                /* Now churn through each parameter as we find it */
                /* SIGNATURES */
                if ( SetParamOnPolicy(xpathCtx, sig_res_expr, "resign", "signature", policy->signature->resign, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, sig_ref_expr, "refresh", "signature", policy->signer->refresh, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, val_def_expr, "valdefault", "signature", policy->signature->valdefault, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, val_den_expr, "valdenial", "signature", policy->signature->valdenial, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, sig_jit_expr, "jitter", "signature", policy->signer->jitter, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, sig_off_expr, "clockskew", "signature", policy->signature->clockskew, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* DENIAL */
                /* Need to decide here if we have NSEC or NSEC3 */
                xpathObj = xmlXPathEvalExpression(den_nsec3_expr, xpathCtx);
                if(xpathObj == NULL) {
                    printf("Error: unable to evaluate xpath expression: %s\n", den_nsec3_expr);
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                /* TODO is this right? */
                if (xpathObj->nodesetval->nodeNr > 0) {
                    /* Found something, NSEC3 */
                    status = KsmParameterSet("version", "denial", 3, policy->id);
                    if (status != 0) {
                        printf("Error: unable to insert/update %s for policy\n", "Denial version");
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }

                    if ( SetParamOnPolicy(xpathCtx, den_opt_expr, "optout", "denial", policy->denial->optout, policy->id, BOOL_TYPE) != 0) {
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }
                    if ( SetParamOnPolicy(xpathCtx, den_resalt_expr, "resalt", "denial", policy->denial->resalt, policy->id, DURATION_TYPE) != 0) {
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }
                    if ( SetParamOnPolicy(xpathCtx, den_alg_expr, "algorithm", "denial", policy->denial->algorithm, policy->id, INT_TYPE) != 0) {
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }
                    if ( SetParamOnPolicy(xpathCtx, den_iter_expr, "iterations", "denial", policy->denial->iteration, policy->id, INT_TYPE) != 0) {
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }
                    if ( SetParamOnPolicy(xpathCtx, den_salt_expr, "saltlength", "denial", policy->denial->saltlength, policy->id, INT_TYPE) != 0) {
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }

                } else {
                    /* Must be NSEC */
                    status = KsmParameterSet("version", "denial", 1, policy->id);
                    if (status != 0) {
                        printf("Error: unable to insert/update %s for policy\n", "Denial version");
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }
                }
                xmlXPathFreeObject(xpathObj);

                /* KEYS */
                if ( SetParamOnPolicy(xpathCtx, keys_ttl_expr, "ttl", "keys", policy->keys->ttl, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, keys_ret_expr, "retiresafety", "keys", policy->keys->retire_safety, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, keys_pub_expr, "publishsafety", "keys", policy->keys->publish_safety, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, keys_share_expr, "zones_share_keys", "keys", policy->keys->share_keys, policy->id, BOOL_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                /* KSK */
                if ( SetParamOnPolicy(xpathCtx, ksk_alg_expr, "algorithm", "ksk", policy->ksk->algorithm, policy->id, INT_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, ksk_alg_len_expr, "bits", "ksk", policy->ksk->bits, policy->id, INT_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, ksk_life_expr, "lifetime", "ksk", policy->ksk->lifetime, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, ksk_repo_expr, "repository", "ksk", policy->ksk->sm, policy->id, REPO_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, ksk_emer_expr, "emergency", "ksk", policy->ksk->emergency_keys, policy->id, INT_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, ksk_5011_expr, "rfc5011", "ksk", policy->ksk->rfc5011, policy->id, BOOL_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                /* ZSK */
                if ( SetParamOnPolicy(xpathCtx, zsk_alg_expr, "algorithm", "zsk", policy->zsk->algorithm, policy->id, INT_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, zsk_alg_len_expr, "bits", "zsk", policy->zsk->bits, policy->id, INT_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, zsk_life_expr, "lifetime", "zsk", policy->zsk->lifetime, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, zsk_repo_expr, "repository", "zsk", policy->zsk->sm, policy->id, REPO_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, zsk_emer_expr, "emergency", "zsk", policy->zsk->emergency_keys, policy->id, INT_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* ZONE */
                if ( SetParamOnPolicy(xpathCtx, zone_prop_expr, "propagationdelay", "zone", policy->zone->propdelay, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, zone_soa_ttl_expr, "ttl", "zone", policy->zone->soa_ttl, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, zone_min_expr, "min", "zone", policy->zone->soa_min, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, zone_serial_expr, "serial", "zone", policy->zone->serial, policy->id, SERIAL_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* PARENT */
                if ( SetParamOnPolicy(xpathCtx, parent_prop_expr, "propagationdelay", "parent", policy->parent->propdelay, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, parent_ds_ttl_expr, "ttlds", "parent", policy->parent->ds_ttl, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, parent_soa_ttl_expr, "ttl", "parent", policy->parent->soa_ttl, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                if ( SetParamOnPolicy(xpathCtx, parent_min_expr, "min", "parent", policy->parent->soa_min, policy->id, DURATION_TYPE) != 0) {
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* AUDIT */
                /* Make Reader from pol_doc */
                reader2 = xmlReaderWalker(pol_doc);
                if (reader2 != NULL) {
                    ret2 = xmlTextReaderRead(reader2);
                    while (ret2 == 1) {
                        tag_name2 = (char*) xmlTextReaderLocalName(reader2);
                        /* Found <Audit> */
                        if (strncmp(tag_name2, "Audit", 5) == 0 
                                && xmlTextReaderNodeType(reader2) == 1) {
                            audit_contents = (char *)xmlTextReaderReadInnerXml(reader2);

                            /* Stick the audit information into the database */
                            status = KsmImportAudit(policy->id, audit_contents);
                            audit_found = 1;
                            if(status != 0) {
                                printf("Error: unable to insert Audit info for policy %s\n", policy->name);
                                /* Don't return? try to parse the rest of the file? */
                                ret2 = xmlTextReaderRead(reader2);
                                continue;
                            }
                            StrFree(audit_contents);
                        } /* End of <Audit> */
                        StrFree(tag_name2);
                        ret2 = xmlTextReaderRead(reader2);
                    }

                    /* Indicate in the database if we didn't find an audit tag */
                    if (audit_found == 0) {
                        status = KsmImportAudit(policy->id, "NULL");
                    }

                    xmlFreeTextReader(reader2);
                }
                
            } /* End of <Policy> */
            /* Read the next line */
            ret = xmlTextReaderRead(reader);
            StrFree(tag_name);
        }
        xmlFreeTextReader(reader);
        xmlFreeDoc(pol_doc);
        if (ret != 0) {
            printf("%s : failed to parse\n", kasp_filename);
        }
    }

    /* Cleanup */
    /* TODO: some other frees are needed */
    xmlXPathFreeContext(xpathCtx);
    xmlRelaxNGFree(schema);
    xmlRelaxNGFreeValidCtxt(rngctx);
    xmlRelaxNGFreeParserCtxt(rngpctx);
    xmlFreeDoc(doc);
    xmlFreeDoc(rngdoc);
    KsmPolicyFree(policy);

    return(status);
}

/* Read zonelist (as passed in) and insert/update any zones seen */
int update_zones(char* zone_list_filename)
{
    int status = 0;
    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    int ret = 0; /* status of the XML parsing */
    char* zone_name = NULL;
    char* policy_name = NULL;
    char* temp_char = NULL;
    char* tag_name = NULL;
    int policy_id = 0;

    xmlChar *name_expr = (unsigned char*) "name";
    xmlChar *policy_expr = (unsigned char*) "//Zone/Policy";

    /* TODO validate the file ? */

    /* Start reading the file; we will be looking for "Repository" tags */ 
    reader = xmlNewTextReaderFilename(zone_list_filename);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            tag_name = (char*) xmlTextReaderLocalName(reader);
            /* Found <Zone> */
            if (strncmp(tag_name, "Zone", 4) == 0 
                    && strncmp(tag_name, "ZoneList", 8) != 0
                    && xmlTextReaderNodeType(reader) == 1) {
                /* Get the repository name */
                zone_name = NULL;
                temp_char = (char*) xmlTextReaderGetAttribute(reader, name_expr);
                StrAppend(&zone_name, temp_char);
                StrFree(temp_char);
                /* Make sure that we got something */
                if (zone_name == NULL) {
                    /* error */
                    printf("Error extracting zone name from %s\n", zone_list_filename);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                printf("Zone %s found\n", zone_name);

                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                doc = xmlTextReaderCurrentDoc(reader);
                if (doc == NULL) {
                    printf("Error: can not read zone \"%s\"; skipping\n", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                xpathCtx = xmlXPathNewContext(doc);
                if(xpathCtx == NULL) {
                    printf("Error: can not create XPath context for \"%s\"; skipping zone\n", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* Extract the Policy name for this zone */
                /* Evaluate xpath expression for policy */
                xpathObj = xmlXPathEvalExpression(policy_expr, xpathCtx);
                xmlXPathFreeContext(xpathCtx);
                if(xpathObj == NULL) {
                    printf("Error: unable to evaluate xpath expression: %s; skipping zone\n", policy_expr);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                policy_name = NULL;
                temp_char = (char *)xmlXPathCastToString(xpathObj);
                StrAppend(&policy_name, temp_char);
                StrFree(temp_char);
                printf("Policy set to %s.\n", policy_name);
                xmlXPathFreeObject(xpathObj);

                status = KsmPolicyIdFromName(policy_name, &policy_id);
                if (status != 0) {
                    printf("Error, can't find policy : %s\n", policy_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /*
                 * Now we have all the information update/insert this repository
                 */
                status = KsmImportZone(zone_name, policy_id);
                if (status != 0) {
                    printf("Error Importing Zone %s\n", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                StrFree(zone_name);
                StrFree(policy_name);

            }
            /* Read the next line */
            ret = xmlTextReaderRead(reader);
            StrFree(tag_name);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            printf("%s : failed to parse\n", zone_list_filename);
        }
    } else {
        printf("Unable to open %s\n", zone_list_filename);
    }
    if (doc) {
        xmlFreeDoc(doc);
    }

    return 0;
}

/* 
 * This encapsulates all of the steps needed to insert/update a parameter value
 * evaluate the xpath expression and try to update the policy value, if it has changed
 * TODO possible bug where parmeters which have a value of 0 are not written (because we 
 * only write what looks like it has changed
 */
int SetParamOnPolicy(xmlXPathContextPtr xpathCtx, const xmlChar* xpath_expr, const char* name, const char* category, int current_value, int policy_id, int value_type)
{
    int status = 0;
    int value = 0;
    char* temp_char;
    xmlXPathObjectPtr xpathObj = NULL;

    /* Evaluate xpath expression */
    xpathObj = xmlXPathEvalExpression(xpath_expr, xpathCtx);
    if(xpathObj == NULL) {
        printf("Error: unable to evaluate xpath expression: %s; skipping policy\n", xpath_expr);
        return -1;
    }

    /* extract the value into an int */
    if (value_type == DURATION_TYPE) {
        temp_char = (char *)xmlXPathCastToString(xpathObj);
        status = DtXMLIntervalSeconds(temp_char, &value);
        if (status > 0) {
            printf("Error: unable to convert interval %s to seconds, error: %i\n", temp_char, status);
            StrFree(temp_char);
            return status;
        }
        else if (status == -1) {
            printf("Warning: converting %s to seconds may not give what you expect\n", temp_char);
        }
        StrFree(temp_char);
    }
    else if (value_type == BOOL_TYPE) {
        /* Do we have an empty tag or no tag? */
        if (xpathObj->nodesetval->nodeNr > 0) {
            value = 1;
        } else {
            value = 0;
        }
    }
    else if (value_type == REPO_TYPE) {
        /* We need to convert the repository name into an id */
        temp_char = (char *)xmlXPathCastToString(xpathObj);
        status = KsmSmIdFromName(temp_char, &value);
        if (status != 0) {
            printf("Error: unable to find repository %s\n", temp_char);
            StrFree(temp_char);
            return status;
        }
        StrFree(temp_char);
    }
    else if (value_type == SERIAL_TYPE) {
        /* We need to convert the serial name into an id */
        temp_char = (char *)xmlXPathCastToString(xpathObj);
        status = KsmSerialIdFromName(temp_char, &value);
        if (status != 0) {
            printf("Error: unable to find serial type %s\n", temp_char);
            StrFree(temp_char);
            return status;
        }
        StrFree(temp_char);
    }
    else {
        temp_char = (char *)xmlXPathCastToString(xpathObj);
        status = StrStrtoi(temp_char, &value);
        if (status != 0) {
            printf("Error: unable to convert %s to int\n", temp_char);
            StrFree(temp_char);
            return status;
        }
        StrFree(temp_char);
    }

    /* Now update the policy with what we found, if it is different */
    if (value != current_value || current_value == 0) {
        status = KsmParameterSet(name, category, value, policy_id);
        if (status != 0) {
            printf("Error: unable to insert/update %s for policy\n", name);
            return status;
        }
    }

    xmlXPathFreeObject(xpathObj);

    return 0;
}

void SetPolicyDefaults(KSM_POLICY *policy, char *name)
{
    if (policy == NULL) {
        printf("Error, no policy provided");
        return;
    }

    if(name) policy->name = StrStrdup(name);

    policy->signer->refresh = 0;
    policy->signer->jitter = 0;
    policy->signer->propdelay = 0;
    policy->signer->soamin = 0;
    policy->signer->soattl = 0;
    policy->signer->serial = 0;

    policy->signature->clockskew = 0;
    policy->signature->resign = 0;
    policy->signature->valdefault = 0;
    policy->signature->valdenial = 0;

    policy->denial->version = 0;
    policy->denial->resalt = 0;
    policy->denial->algorithm = 0;
    policy->denial->iteration = 0;
    policy->denial->optout = 0;
    policy->denial->ttl = 0;
    policy->denial->saltlength = 0;

    policy->keys->ttl = 0;
    policy->keys->retire_safety = 0;
    policy->keys->publish_safety = 0;
    policy->keys->share_keys = 0;

    policy->ksk->algorithm = 0;
    policy->ksk->bits = 0;
    policy->ksk->lifetime = 0;
    policy->ksk->sm = 0;
    policy->ksk->overlap = 0;
    policy->ksk->ttl = 0;
    policy->ksk->rfc5011 = 0;
    policy->ksk->type = KSM_TYPE_KSK;
    policy->ksk->emergency_keys = 0;

    policy->zsk->algorithm = 0;
    policy->zsk->bits = 0;
    policy->zsk->lifetime = 0;
    policy->zsk->sm = 0;
    policy->zsk->overlap = 0;
    policy->zsk->ttl = 0;
    policy->zsk->rfc5011 = 0;
    policy->zsk->type = KSM_TYPE_ZSK;
    policy->zsk->emergency_keys = 0;

    policy->enforcer->keycreate = 0;
    policy->enforcer->backup_interval = 0;
    policy->enforcer->keygeninterval = 0;

    policy->zone->propdelay = 0;
    policy->zone->soa_ttl = 0;
    policy->zone->soa_min = 0;
    policy->zone->serial = 0;

    policy->parent->propdelay = 0;
    policy->parent->ds_ttl = 0;
    policy->parent->soa_ttl = 0;
    policy->parent->soa_min = 0;

}

/* make a backup of a file
 * Returns 0 on success
 *         1 on error
 *        -1 if it could read the original but not open the backup
 */
int backup_file(const char* orig_file, const char* backup_file)
{
    FILE *from, *to;
    int ch;

    errno = 0;
    /* open source file */
    if((from = fopen( orig_file, "rb"))==NULL) {
        if (errno == ENOENT) {
            printf("File %s does not exist, nothing to backup\n", orig_file);
            return(0);
        }
        else {
            printf("Cannot open source file.\n");
            return(1); /* No point in trying to connect */
        }
    }

    /* open destination file */
    if((to = fopen(backup_file, "wb"))==NULL) {
        printf("Cannot open destination file, will not make backup.\n");
        fclose(from);
        return(-1);
    }
    else {
        /* copy the file */
        while(!feof(from)) {
            ch = fgetc(from);
            if(ferror(from)) {
                printf("Error reading source file.\n");
                fclose(from);
                fclose(to);
                return(1);
            }
            if(!feof(from)) fputc(ch, to);
            if(ferror(to)) {
                printf("Error writing destination file.\n");
                fclose(from);
                fclose(to);
                return(1);
            }
        }

        if(fclose(from)==EOF) {
            printf("Error closing source file.\n");
            fclose(to);
            return(1);
        }

        if(fclose(to)==EOF) {
            printf("Error closing destination file.\n");
            return(1);
        }
    }
    return(0);
}

/* 
 * Given a conf.xml location extract the database details contained within it
 *
 * The caller will need to StrFree the char**s passed in
 *
 * Returns 0 if a full set of details was found
 *         1 if something didn't look right
 *        -1 if any of the config files could not be read/parsed
 *
 */
    int
get_db_details(char** dbschema, char** host, char** port, char** user, char** password)
{
    /* All of the XML stuff */
    xmlDocPtr doc;
    xmlDocPtr rngdoc;
    xmlXPathContextPtr xpathCtx;
    xmlXPathObjectPtr xpathObj;
    xmlRelaxNGParserCtxtPtr rngpctx;
    xmlRelaxNGValidCtxtPtr rngctx;
    xmlRelaxNGPtr schema;
    xmlChar *litexpr = (unsigned char*) "//Configuration/Enforcer/Datastore/SQLite";
    xmlChar *mysql_host = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Host";
    xmlChar *mysql_port = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Host/@port";
    xmlChar *mysql_db = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Database";
    xmlChar *mysql_user = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Username";
    xmlChar *mysql_pass = (unsigned char*) "//Configuration/Enforcer/Datastore/MySQL/Password";

    int status;
    int db_found = 0;
    char* temp_char = NULL;

    /* Some files, the xml and rng */
    const char* rngfilename = SCHEMA_DIR "/conf.rng";

    /* Load XML document */
    doc = xmlParseFile(config);
    if (doc == NULL) {
        printf("Error: unable to parse file \"%s\"\n", config);
        return(-1);
    }

    /* Load rng document: TODO make the rng stuff optional? */
    rngdoc = xmlParseFile(rngfilename);
    if (rngdoc == NULL) {
        printf("Error: unable to parse file \"%s\"\n", rngfilename);
        return(-1);
    }

    /* Create an XML RelaxNGs parser context for the relax-ng document. */
    rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);
    if (rngpctx == NULL) {
        printf("Error: unable to create XML RelaxNGs parser context\n");
        return(-1);
    }

    /* parse a schema definition resource and build an internal XML Schema structure which can be used to validate instances. */
    schema = xmlRelaxNGParse(rngpctx);
    if (schema == NULL) {
        printf("Error: unable to parse a schema definition resource\n");
        return(-1);
    }

    /* Create an XML RelaxNGs validation context based on the given schema */
    rngctx = xmlRelaxNGNewValidCtxt(schema);
    if (rngctx == NULL) {
        printf("Error: unable to create RelaxNGs validation context based on the schema\n");
        return(-1);
    }

    /* Validate a document tree in memory. */
    status = xmlRelaxNGValidateDoc(rngctx,doc);
    if (status != 0) {
        printf("Error validating file \"%s\"\n", config);
        return(-1);
    }

    /* Now parse a value out of the conf */
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        printf("Error: unable to create new XPath context\n");
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Evaluate xpath expression for SQLite file location */
    xpathObj = xmlXPathEvalExpression(litexpr, xpathCtx);
    if(xpathObj == NULL) {
        printf("Error: unable to evaluate xpath expression: %s\n", litexpr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    if(xpathObj->nodesetval->nodeNr > 0) {
        db_found = SQLITE_DB;
        temp_char = (char *)xmlXPathCastToString(xpathObj);
        StrAppend(dbschema, temp_char);
        StrFree(temp_char);
        fprintf(stderr, "SQLite database set to: %s\n", *dbschema);
    }

    if (db_found == 0) {
        /* Get all of the MySQL stuff read in too */
        /* HOST */
        xpathObj = xmlXPathEvalExpression(mysql_host, xpathCtx);
        if(xpathObj == NULL) {
            printf("Error: unable to evaluate xpath expression: %s\n", mysql_host);
            xmlXPathFreeContext(xpathCtx);
            xmlFreeDoc(doc);
            return(-1);
        }
        if(xpathObj->nodesetval->nodeNr > 0) {
            db_found = MYSQL_DB;
        }
        temp_char = (char *)xmlXPathCastToString(xpathObj);
        StrAppend(host, temp_char);
        StrFree(temp_char);
        printf("MySQL database host set to: %s\n", *host);

        /* PORT */
        xpathObj = xmlXPathEvalExpression(mysql_port, xpathCtx);
        if(xpathObj == NULL) {
            printf("Error: unable to evaluate xpath expression: %s\n", mysql_port);
            xmlXPathFreeContext(xpathCtx);
            xmlFreeDoc(doc);
            return(-1);
        }
        if(xpathObj->nodesetval->nodeNr > 0) {
            db_found = 0;
        }
        temp_char = (char *)xmlXPathCastToString(xpathObj);
        StrAppend(port, temp_char);
        StrFree(temp_char);
        printf("MySQL database port set to: %s\n", *port);

        /* SCHEMA */
        xpathObj = xmlXPathEvalExpression(mysql_db, xpathCtx);
        if(xpathObj == NULL) {
            printf("Error: unable to evaluate xpath expression: %s\n", mysql_db);
            xmlXPathFreeContext(xpathCtx);
            xmlFreeDoc(doc);
            return(-1);
        }
        if(xpathObj->nodesetval->nodeNr > 0) {
            db_found = 0;
        }
        temp_char = (char *)xmlXPathCastToString(xpathObj);
        StrAppend(dbschema, temp_char);
        StrFree(temp_char);
        printf("MySQL database schema set to: %s\n", *dbschema);

        /* DB USER */
        xpathObj = xmlXPathEvalExpression(mysql_user, xpathCtx);
        if(xpathObj == NULL) {
            printf("Error: unable to evaluate xpath expression: %s\n", mysql_user);
            xmlXPathFreeContext(xpathCtx);
            xmlFreeDoc(doc);
            return(-1);
        }
        if(xpathObj->nodesetval->nodeNr > 0) {
            db_found = 0;
        }
        temp_char = (char *)xmlXPathCastToString(xpathObj);
        StrAppend(user, temp_char);
        StrFree(temp_char);
        printf("MySQL database user set to: %s\n", *user);

        /* DB PASSWORD */
        xpathObj = xmlXPathEvalExpression(mysql_pass, xpathCtx);
        if(xpathObj == NULL) {
            printf("Error: unable to evaluate xpath expression: %s\n", mysql_pass);
            xmlXPathFreeContext(xpathCtx);
            xmlFreeDoc(doc);
            return(-1);
        }
        /* password may be blank */
        temp_char = (char *)xmlXPathCastToString(xpathObj);
        StrAppend(password, temp_char);
        StrFree(temp_char);

        printf("MySQL database password set\n");

    }

    /* Check that we found one or the other database */
    if(db_found == 0) {
        printf("Error: unable to find complete database connection expression\n");
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Check that we found the right database type */
    if (db_found != DbFlavour()) {
        printf("Error: database in config file does not match libksm\n");
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Cleanup */
    /* TODO: some other frees are needed */
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);
    xmlRelaxNGFree(schema);
    xmlRelaxNGFreeValidCtxt(rngctx);
    xmlRelaxNGFreeParserCtxt(rngpctx);
    xmlFreeDoc(rngdoc);

    StrFree(temp_char);

    return(status);
}

/* 
 *  Read the conf.xml file, we will not validate as that was done as we read the database.
 *  Instead we just extract the RepositoryList into the database and also learn the 
 *  location of the zonelist.
 */
int read_zonelist_filename(char** zone_list_filename)
{
    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    int ret = 0; /* status of the XML parsing */
    char* temp_char = NULL;
    char* tag_name = NULL;

    xmlChar *zonelist_expr = (unsigned char*) "//Common/ZoneListFile";

    /* Start reading the file; we will be looking for "Common" tags */ 
    reader = xmlNewTextReaderFilename(config);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            tag_name = (char*) xmlTextReaderLocalName(reader);
            /* Found <Common> */
            if (strncmp(tag_name, "Common", 6) == 0 
                    && xmlTextReaderNodeType(reader) == 1) {

                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                doc = xmlTextReaderCurrentDoc(reader);
                if (doc == NULL) {
                    printf("Error: can not read Common section\n");
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                xpathCtx = xmlXPathNewContext(doc);
                if(xpathCtx == NULL) {
                    printf("Error: can not create XPath context for Common section\n");
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* Evaluate xpath expression for ZoneListFile */
                xpathObj = xmlXPathEvalExpression(zonelist_expr, xpathCtx);
                if(xpathObj == NULL) {
                    printf("Error: unable to evaluate xpath expression: %s\n", zonelist_expr);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                *zone_list_filename = NULL;
                temp_char = (char *)xmlXPathCastToString(xpathObj);
                StrAppend(zone_list_filename, temp_char);
                StrFree(temp_char);
                printf("zonelist filename set to %s.\n", *zone_list_filename);
            }
            /* Read the next line */
            ret = xmlTextReaderRead(reader);
            StrFree(tag_name);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            printf("%s : failed to parse\n", config);
            return(1);
        }
    } else {
        printf("Unable to open %s\n", config);
        return(1);
    }
    if (xpathCtx) {
        xmlXPathFreeContext(xpathCtx);
    }
    if (doc) {
        xmlFreeDoc(doc);
    }

    return 0;
}

xmlDocPtr add_zone_node(const char *docname,
                        const char *zone_name, 
                        const char *policy_name, 
                        const char *sig_conf_name, 
                        const char *input_name, 
                        const char *output_name)
{
    xmlDocPtr doc;
    xmlNodePtr cur;
    xmlNodePtr newzonenode;
    xmlNodePtr newadaptnode;
    xmlNodePtr newinputnode;
    xmlNodePtr newoutputnode;
    doc = xmlParseFile(docname);
    if (doc == NULL ) {
        fprintf(stderr,"Document not parsed successfully. \n");
        return (NULL);
    }
    cur = xmlDocGetRootElement(doc);
    if (cur == NULL) {
        fprintf(stderr,"empty document\n");
        xmlFreeDoc(doc);
        return (NULL);
    }
    if (xmlStrcmp(cur->name, (const xmlChar *) "ZoneList")) {
        fprintf(stderr,"document of the wrong type, root node != %s", "ZoneList");
        xmlFreeDoc(doc);
        return (NULL);
    }
    newzonenode = xmlNewTextChild(cur, NULL, (const xmlChar *)"Zone", NULL);
    (void) xmlNewProp(newzonenode, (const xmlChar *)"name", (const xmlChar *)zone_name);

    (void) xmlNewTextChild (newzonenode, NULL, (const xmlChar *)"Policy", (const xmlChar *)policy_name);

    (void) xmlNewTextChild (newzonenode, NULL, (const xmlChar *)"SignerConfiguration", (const xmlChar *)sig_conf_name);

    newadaptnode = xmlNewChild (newzonenode, NULL, (const xmlChar *)"Adapters", NULL);

    newinputnode = xmlNewChild (newadaptnode, NULL, (const xmlChar *)"Input", NULL);

    (void) xmlNewTextChild (newinputnode, NULL, (const xmlChar *)"File", (const xmlChar *)input_name);

    newoutputnode = xmlNewChild (newadaptnode, NULL, (const xmlChar *)"Output", NULL);

    (void) xmlNewTextChild (newoutputnode, NULL, (const xmlChar *)"File", (const xmlChar *)output_name);

    return(doc);
}

xmlDocPtr del_zone_node(const char *docname,
                        const char *zone_name,
                        int do_all)
{
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr cur;

    doc = xmlParseFile(docname);
    if (doc == NULL ) {
        fprintf(stderr,"Document not parsed successfully. \n");
        return (NULL);
    }
    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        fprintf(stderr,"empty document\n");
        xmlFreeDoc(doc);
        return (NULL);
    }
    if (xmlStrcmp(root->name, (const xmlChar *) "ZoneList")) {
        fprintf(stderr,"document of the wrong type, root node != %s", "ZoneList");
        xmlFreeDoc(doc);
        return (NULL);
    }

    /* If we are removing all zones then just replace the root node with an empty one */
    if (do_all == 1) {
        cur = root->children;
        while (cur != NULL)
        {
            xmlUnlinkNode(cur);
            xmlFreeNode(cur);

            cur = root->children;
        }
    }
    else {

    /* Zone nodes are children of the root */
        for(cur = root->children; cur != NULL; cur = cur->next)
        {
            /* is this the zone we are looking for? */
            if (xmlStrcmp( xmlGetProp(cur, (xmlChar *) "name"), (const xmlChar *) zone_name) == 0)
            {
                xmlUnlinkNode(cur);

                cur = root->children; /* May pass through multiple times, but will remove all instances of the zone */
            }
        }
        xmlFreeNode(cur);
    }

    return(doc);
}

void list_zone_node(const char *docname)
{
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr cur;
    xmlNodePtr pol;

    doc = xmlParseFile(docname);
    if (doc == NULL ) {
        fprintf(stderr,"Document not parsed successfully. \n");
        return;
    }
    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        fprintf(stderr,"empty document\n");
        xmlFreeDoc(doc);
        return;
    }
    if (xmlStrcmp(root->name, (const xmlChar *) "ZoneList")) {
        fprintf(stderr,"document of the wrong type, root node != %s", "ZoneList");
        xmlFreeDoc(doc);
        return;
    }

    /* Zone nodes are children of the root */
    for(cur = root->children; cur != NULL; cur = cur->next)
    {
        if (xmlStrcmp( cur->name, (const xmlChar *)"Zone") == 0) {
            printf("Found Zone: %s; ", xmlGetProp(cur, (xmlChar *) "name"));
            for(pol = cur->children; pol != NULL; pol = pol->next)
            {
                if (xmlStrcmp( pol->name, (const xmlChar *)"Policy") == 0)
                {
                    printf("on policy %s\n", xmlNodeGetContent(pol));
                }
            }
        }
    }

    xmlFreeDoc(doc);

    return;
}

/*
 * Given a doc that has the start of the kasp-like xml and a policy structure
 * create the policy tag and contents in that doc
 */
int append_policy(xmlDocPtr doc, KSM_POLICY *policy)
{
    xmlNodePtr root;
    xmlNodePtr policy_node;
    xmlNodePtr signatures_node;
    xmlNodePtr validity_node;
    xmlNodePtr denial_node;
    xmlNodePtr nsec_node;
    xmlNodePtr hash_node;
    xmlNodePtr salt_node;
    xmlNodePtr keys_node;
    xmlNodePtr ksk_node;
    xmlNodePtr ksk_alg_node;
    xmlNodePtr zsk_node;
    xmlNodePtr zsk_alg_node;
    xmlNodePtr zone_node;
    xmlNodePtr zone_soa_node;
    xmlNodePtr parent_node;
    xmlNodePtr parent_ds_node;
    xmlNodePtr parent_soa_node;

    xmlNodePtr audit_node;
    xmlNodePtr encNode;
    int ret = 0; /* status of the XML parsing */

    char temp_time[32];
   
    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        fprintf(stderr,"empty document\n");
        return(1);
    }
    if (xmlStrcmp(root->name, (const xmlChar *) "KASP")) {
        fprintf(stderr,"document of the wrong type, root node != %s", "KASP");
        return(1);
    }

    policy_node = xmlNewTextChild(root, NULL, (const xmlChar *)"Policy", NULL);
    (void) xmlNewProp(policy_node, (const xmlChar *)"name", (const xmlChar *)policy->name);
    (void) xmlNewTextChild(policy_node, NULL, (const xmlChar *)"Description", (const xmlChar *)policy->description);

    /* SIGNATURES */
    signatures_node = xmlNewTextChild(policy_node, NULL, (const xmlChar *)"Signatures", NULL);
    snprintf(temp_time, 32, "PT%dS", policy->signature->resign);
    (void) xmlNewTextChild(signatures_node, NULL, (const xmlChar *)"Resign", (const xmlChar *)temp_time);
    snprintf(temp_time, 32, "PT%dS", policy->signer->refresh);
    (void) xmlNewTextChild(signatures_node, NULL, (const xmlChar *)"Refresh", (const xmlChar *)temp_time);
    validity_node = xmlNewTextChild(signatures_node, NULL, (const xmlChar *)"Validity", NULL);
    snprintf(temp_time, 32, "PT%dS", policy->signature->valdefault);
    (void) xmlNewTextChild(validity_node, NULL, (const xmlChar *)"Default", (const xmlChar *)temp_time);
    snprintf(temp_time, 32, "PT%dS", policy->signature->valdenial);
    (void) xmlNewTextChild(validity_node, NULL, (const xmlChar *)"Denial", (const xmlChar *)temp_time);
    snprintf(temp_time, 32, "PT%dS", policy->signer->jitter);
    (void) xmlNewTextChild(signatures_node, NULL, (const xmlChar *)"Jitter", (const xmlChar *)temp_time);
    snprintf(temp_time, 32, "PT%dS", policy->signature->clockskew);
    (void) xmlNewTextChild(signatures_node, NULL, (const xmlChar *)"InceptionOffset", (const xmlChar *)temp_time);

    /* DENIAL */
    denial_node = xmlNewTextChild(policy_node, NULL, (const xmlChar *)"Denial", NULL);
    if (policy->denial->version == 1) /* NSEC */
    {
        (void) xmlNewTextChild(denial_node, NULL, (const xmlChar *)"NSEC", NULL);
    }
    else    /* NSEC3 */
    {
        nsec_node = xmlNewTextChild(denial_node, NULL, (const xmlChar *)"NSEC3", NULL);
        if (policy->denial->optout == 1)
        {
            (void) xmlNewTextChild(nsec_node, NULL, (const xmlChar *)"OptOut", NULL);
        }
        snprintf(temp_time, 32, "PT%dS", policy->denial->resalt);
        (void) xmlNewTextChild(nsec_node, NULL, (const xmlChar *)"Resalt", (const xmlChar *)temp_time);
        hash_node = xmlNewTextChild(nsec_node, NULL, (const xmlChar *)"Hash", NULL);
        snprintf(temp_time, 32, "%d", policy->denial->algorithm);
        (void) xmlNewTextChild(hash_node, NULL, (const xmlChar *)"Algorithm", (const xmlChar *)temp_time);
        snprintf(temp_time, 32, "%d", policy->denial->iteration);
        (void) xmlNewTextChild(hash_node, NULL, (const xmlChar *)"Iteration", (const xmlChar *)temp_time);
        snprintf(temp_time, 32, "%d", policy->denial->saltlength);
        salt_node = xmlNewTextChild(hash_node, NULL, (const xmlChar *)"Salt", NULL);
        (void) xmlNewProp(salt_node, (const xmlChar *)"length", (const xmlChar *)temp_time);
    }

    /* KEYS */
    keys_node = xmlNewTextChild(policy_node, NULL, (const xmlChar *)"Keys", NULL);
    snprintf(temp_time, 32, "PT%dS", policy->keys->ttl);
    (void) xmlNewTextChild(keys_node, NULL, (const xmlChar *)"TTL", (const xmlChar *)temp_time);
    snprintf(temp_time, 32, "PT%dS", policy->keys->retire_safety);
    (void) xmlNewTextChild(keys_node, NULL, (const xmlChar *)"RetireSafety", (const xmlChar *)temp_time);
    snprintf(temp_time, 32, "PT%dS", policy->keys->publish_safety);
    (void) xmlNewTextChild(keys_node, NULL, (const xmlChar *)"PublishSafety", (const xmlChar *)temp_time);
    if (policy->keys->share_keys == 1)
    {
            (void) xmlNewTextChild(keys_node, NULL, (const xmlChar *)"SharedKeys", NULL);
    }
    /*(void) xmlNewDocComment(doc, (const xmlChar *)"Parameters that are different for zsks and ksks");*/
    /* KSK */
    ksk_node = xmlNewTextChild(keys_node, NULL, (const xmlChar *)"KSK", NULL);
    snprintf(temp_time, 32, "%d", policy->ksk->algorithm);
    ksk_alg_node = xmlNewTextChild(ksk_node, NULL, (const xmlChar *)"Algorithm", (const xmlChar *)temp_time);
    snprintf(temp_time, 32, "%d", policy->ksk->bits);
    (void) xmlNewProp(ksk_alg_node, (const xmlChar *)"length", (const xmlChar *)temp_time);
    snprintf(temp_time, 32, "PT%dS", policy->ksk->lifetime);
    (void) xmlNewTextChild(ksk_node, NULL, (const xmlChar *)"Lifetime", (const xmlChar *)temp_time);
    (void) xmlNewTextChild(ksk_node, NULL, (const xmlChar *)"Repository", (const xmlChar *)policy->ksk->sm_name);
    snprintf(temp_time, 32, "%d", policy->ksk->emergency_keys);
    (void) xmlNewTextChild(ksk_node, NULL, (const xmlChar *)"Emergency", (const xmlChar *)temp_time);
    if (policy->ksk->rfc5011 == 1)
    {
        (void) xmlNewTextChild(ksk_node, NULL, (const xmlChar *)"RFC5011", NULL);
    }

    /* ZSK */
    zsk_node = xmlNewTextChild(keys_node, NULL, (const xmlChar *)"ZSK", NULL);
    snprintf(temp_time, 32, "%d", policy->zsk->algorithm);
    zsk_alg_node = xmlNewTextChild(zsk_node, NULL, (const xmlChar *)"Algorithm", (const xmlChar *)temp_time);
    snprintf(temp_time, 32, "%d", policy->zsk->bits);
    (void) xmlNewProp(zsk_alg_node, (const xmlChar *)"length", (const xmlChar *)temp_time);
    snprintf(temp_time, 32, "PT%dS", policy->zsk->lifetime);
    (void) xmlNewTextChild(zsk_node, NULL, (const xmlChar *)"Lifetime", (const xmlChar *)temp_time);
    (void) xmlNewTextChild(zsk_node, NULL, (const xmlChar *)"Repository", (const xmlChar *)policy->zsk->sm_name);
    snprintf(temp_time, 32, "%d", policy->zsk->emergency_keys);
    (void) xmlNewTextChild(zsk_node, NULL, (const xmlChar *)"Emergency", (const xmlChar *)temp_time);

    /* ZONE */
    zone_node = xmlNewTextChild(policy_node, NULL, (const xmlChar *)"Zone", NULL);
    snprintf(temp_time, 32, "PT%dS", policy->zone->propdelay);
    (void) xmlNewTextChild(zone_node, NULL, (const xmlChar *)"PropagationDelay", (const xmlChar *)temp_time);
    zone_soa_node = xmlNewTextChild(zone_node, NULL, (const xmlChar *)"SOA", NULL);
    snprintf(temp_time, 32, "PT%dS", policy->zone->soa_ttl);
    (void) xmlNewTextChild(zone_soa_node, NULL, (const xmlChar *)"TTL", (const xmlChar *)temp_time);
    snprintf(temp_time, 32, "PT%dS", policy->zone->soa_min);
    (void) xmlNewTextChild(zone_soa_node, NULL, (const xmlChar *)"Minimum", (const xmlChar *)temp_time);
    (void) xmlNewTextChild(zone_soa_node, NULL, (const xmlChar *)"Serial", (const xmlChar *) KsmKeywordSerialValueToName(policy->zone->serial));

    /* PARENT */
    parent_node = xmlNewTextChild(policy_node, NULL, (const xmlChar *)"Parent", NULL);
    snprintf(temp_time, 32, "PT%dS", policy->parent->propdelay);
    (void) xmlNewTextChild(parent_node, NULL, (const xmlChar *)"PropagationDelay", (const xmlChar *)temp_time);
    parent_ds_node = xmlNewTextChild(parent_node, NULL, (const xmlChar *)"DS", NULL);
    snprintf(temp_time, 32, "PT%dS", policy->parent->ds_ttl);
    (void) xmlNewTextChild(parent_ds_node, NULL, (const xmlChar *)"TTL", (const xmlChar *)temp_time);
    parent_soa_node = xmlNewTextChild(parent_node, NULL, (const xmlChar *)"SOA", NULL);
    snprintf(temp_time, 32, "PT%dS", policy->parent->soa_ttl);
    (void) xmlNewTextChild(parent_soa_node, NULL, (const xmlChar *)"TTL", (const xmlChar *)temp_time);
    snprintf(temp_time, 32, "PT%dS", policy->parent->soa_min);
    (void) xmlNewTextChild(parent_soa_node, NULL, (const xmlChar *)"Minimum", (const xmlChar *)temp_time);

    /* AUDIT */
    if (strncmp(policy->audit, "NULL", 4) != 0) {
        audit_node = xmlNewChild(policy_node, NULL, (const xmlChar *)"Audit", NULL);

        ret = xmlParseInNodeContext(audit_node, policy->audit, strlen(policy->audit), 0, &encNode);

        if (ret < 0) {
            (void) xmlNewChild(policy_node, NULL, (const xmlChar *)"Error", (const xmlChar *)"audit tag contents could not be parsed");
        }
        else {
            xmlAddChild(audit_node, encNode);
        }
    }

    return(0);
}

/*
 * CallBack to print key info to stdout
 */
int printKey(void* context, KSM_KEYDATA* key_data)
{
    if (key_data->state == KSM_STATE_RETIRE && strcasecmp(key_data->retire, (char *)context) == 0) {
        if (key_data->keytype == KSM_TYPE_KSK)
        {
            fprintf(stdout, "KSK:");
        }
        if (key_data->keytype == KSM_TYPE_ZSK)
        {
            fprintf(stdout, "ZSK:");
        }
        fprintf(stdout, " %s Retired\n", key_data->location);
    }

    return 0;
}

/*
 * log function suitable for libksm callback
 */
    void
ksm_log_msg(const char *format)
{
    fprintf(stderr, "%s\n", format);
}
