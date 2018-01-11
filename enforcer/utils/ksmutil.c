/*
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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>

#include "config.h"

#include <getopt.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

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
#include <libxml/xpointer.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlsave.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* Some value type flags */
#define INT_TYPE 0
#define DURATION_TYPE 1
#define BOOL_TYPE 2
#define REPO_TYPE 3
#define SERIAL_TYPE 4
#define ROLLOVER_TYPE 5
#define INT_TYPE_NO_FREE 6

#ifndef MAXPATHLEN
# define MAXPATHLEN 4096
#endif

/* We write one log message to syslog */
#ifdef LOG_DAEMON
#define DEFAULT_LOG_FACILITY LOG_DAEMON
#else
#define DEFAULT_LOG_FACILITY LOG_USER
#endif /* LOG_DAEMON */

extern char *optarg;
extern int optind;
const char *progname = NULL;
char *config = (char *) OPENDNSSEC_CONFIG_FILE;

char *o_keystate = NULL;
char *o_algo = NULL;
char *o_input = NULL;
char *o_in_type = NULL;
char *o_cka_id = NULL;
char *o_size = NULL;
char *o_interval = NULL;
char *o_output = NULL;
char *o_out_type = NULL;
char *o_policy = NULL;
char *o_repository = NULL;
char *o_signerconf = NULL;
char *o_keytype = NULL;
char *o_time = NULL;
char *o_retire = NULL;
char *o_tdead = NULL;
char *o_zone = NULL;
char *o_zonetotal = NULL;
char *o_keytag = NULL;
static int all_flag = 0;
static int auto_accept_flag = 0;
static int ds_flag = 0;
static int retire_flag = 1;
static int notify_flag = 1;
static int verbose_flag = 0;
static int xml_flag = 1;
static int td_flag = 0;
static int force_flag = 0;
static int hsm_flag = 1;
static int check_repository_flag = 0;
static int rfc5011_flag = 0;

static int restart_enforcerd(void);

/**
 * Use _r() functions on platforms that have. They are thread safe versions of
 * the normal syslog functions. Platforms without _r() usually have thread safe
 * normal functions.
 */
#if defined(HAVE_SYSLOG_R) && defined(HAVE_OPENLOG_R) && defined(HAVE_CLOSELOG_R)
struct syslog_data sdata = SYSLOG_DATA_INIT;
#else
#undef HAVE_SYSLOG_R
#undef HAVE_OPENLOG_R
#undef HAVE_CLOSELOG_R
#endif

    void
usage_general ()
{
    fprintf(stderr,
            "  help\n"
            "  --version                                      aka -V\n");
}

    void
usage_setup ()
{
    fprintf(stderr,
            "  setup\n"
            "\tImport config into a database (deletes current contents)\n");
}

    void
usage_control ()
{
    fprintf(stderr,
            "  start|stop|notify\n"
            "\tStart, stop or SIGHUP the ods-enforcerd\n");
}

    void
usage_update ()
{
    fprintf(stderr,
            "  update kasp\n"
            "  update zonelist\n"
            "  update conf\n"
            "  update all\n"
            "\tUpdate database from config\n");
}

    void
usage_zoneadd ()
{
	fprintf(stderr,
			"  zone add\n"
			"\t--zone <zone>                            aka -z\n"
			"\t[--policy <policy>]                      aka -p\n"
			"\t[--signerconf <signerconf.xml>]          aka -s\n"
			"\t[--input <input>]                        aka -i\n"
			"\t[--in-type <input type>]                 aka -j\n"
			"\t[--output <output>]                      aka -o\n"
			"\t[--out-type <output type>]               aka -q\n"
			"\t[--no-xml]                               aka -m\n");
}

    void
usage_zonedel ()
{
    fprintf(stderr,
            "  zone delete\n"
            "\t--zone <zone> | --all                    aka -z / -a\n"
            "\t[--no-xml]                               aka -m\n");
}

    void
usage_zonelist ()
{
    fprintf(stderr,
            "  zone list\n");
}

    void
usage_zone ()
{
    fprintf(stderr,
            "usage: %s [-c <config> | --config <config>] zone \n\n",
	    progname);
    usage_zoneadd ();
    usage_zonedel ();
    usage_zonelist ();
}

    void
usage_repo ()
{
    fprintf(stderr,
            "  repository list\n");
}

    void
usage_policyexport ()
{
    fprintf(stderr,
            "  policy export\n"
            "\t--policy [policy_name] | --all           aka -p / -a\n");
}

    void
usage_policyimport ()
{
    fprintf(stderr,
            "  policy import\n");
}

    void
usage_policylist ()
{
    fprintf(stderr,
            "  policy list\n");
}

    void
usage_policypurge ()
{
    fprintf(stderr,
            "  policy purge\n");
}

    void
usage_policy ()
{
    fprintf(stderr,
            "usage: %s [-c <config> | --config <config>] \n\n",
	    progname);
    usage_policyexport ();
    usage_policyimport ();
    usage_policylist ();
    usage_policypurge ();
}

    void
usage_keylist ()
{
    fprintf(stderr,
            "  key list\n"
            "\t[--verbose]                              aka -v\n"
            "\t[--zone <zone>]                          aka -z\n"
            "\t[--keystate <state>| --all]              aka -e / -a\n"
            "\t[--keytype <type>]                       aka -t\n"
    );
}

    void
usage_keyexport ()
{
    fprintf(stderr,
            "  key export\n"
            "\t--zone <zone> | --all                    aka -z / -a\n"
            "\t[--keystate <state>]                     aka -e\n"
            "\t[--keytype <type>]                       aka -t\n"
            "\t[--ds]                                   aka -d\n");
}

    void
usage_keyimport ()
{
    fprintf(stderr,
            "  key import\n"
            "\t--cka_id <CKA_ID>                        aka -k\n"
            "\t--repository <repository>                aka -r\n"
            "\t--zone <zone>                            aka -z\n"
            "\t--bits <size>                            aka -b\n"
            "\t--algorithm <algorithm>                  aka -g\n"
            "\t--keystate <state>                       aka -e\n"
            "\t--keytype <type>                         aka -t\n"
            "\t--time <time>                            aka -w\n"
    		"\t[--check-repository]                     aka -C\n"
            "\t[--retire <retire>]                      aka -y\n");
}

    void
usage_keyroll ()
{
    fprintf(stderr,
            "  key rollover\n"
            "\t--zone zone                              aka -z\n"
            "\t--keytype <type> | --all                 aka -t / -a\n"
            "  key rollover\n"
            "\t--policy policy                          aka -p\n"
            "\t--keytype <type> | --all                 aka -t / -a\n");
}

    void
usage_keypurge ()
{
    fprintf(stderr,
            "  key purge\n"
            "\t--zone <zone>                            aka -z\n"
            "  key purge\n"
            "\t--policy <policy>                        aka -p\n");
}

    void
usage_keygen ()
{
    fprintf(stderr,
            "  key generate\n"
		    "\t--policy <policy>                        aka -p\n"
            "\t--interval <interval>                    aka -n\n"
            "\t[--zonetotal <total no. of zones>]       aka -Z\n"
            "\t--auto-accept                            aka -A\n");
}

    void
usage_keykskrevoke ()
{
    fprintf(stderr,
            "  key ksk-revoke\n"
            "\t--zone <zone>                            aka -z\n"
            "\t--keytag <keytag> | --cka_id <CKA_ID>    aka -x / -k\n"
            "\t[--tdead <Tdead>]                        aka -Y\n");
}
    void
usage_keykskretire ()
{
    fprintf(stderr,
            "  key ksk-retire\n"
            "\t--zone <zone>                            aka -z\n"
            "\t--keytag <keytag> | --cka_id <CKA_ID>    aka -x / -k\n");
}

    void
usage_keydsseen ()
{
    fprintf(stderr,
            "  key ds-seen\n"
            /*"\t--zone <zone> (or --all)                 aka -z\n"*/
            "\t--zone <zone>                            aka -z\n"
            "\t--keytag <keytag> | --cka_id <CKA_ID>    aka -x / -k\n"
            "\t[--no-notify|-l]                         aka -l\n"
            "\t[--no-retire|-f]                         aka -f\n");
}

	void
usage_keydelete ()
{
    fprintf(stderr,
            "  key delete\n"
            "\t--cka_id <CKA_ID>                        aka -k\n"
            "\t--no-hsm\n");
}

    void
usage_key ()
{
    fprintf(stderr,
            "usage: %s [-c <config> | --config <config>] \n\n",
	    progname);
    usage_keylist ();
    usage_keyexport ();
    usage_keyimport ();
    usage_keyroll ();
    usage_keypurge ();
    usage_keygen ();
    usage_keykskretire ();
    /* usage_keykskrevoke (); Users shouldn't use this */
    usage_keydsseen ();
    usage_keydelete ();
}

    void
usage_backup ()
{
    fprintf(stderr,
            "  backup prepare\n"
            "\t--repository <repository>                aka -r\n"
            "  backup commit\n"
            "\t--repository <repository>                aka -r\n"
            "  backup rollback\n"
            "\t--repository <repository>                aka -r\n"
            "  backup list\n"
            "\t--repository <repository>                aka -r\n"
            "  backup done\n"
            "\t--repository <repository>                aka -r\n"
            "\t--force\n"
			"\t[NOTE: backup done is deprecated]\n");
}

    void
usage_rollover ()
{
    fprintf(stderr,
            "  rollover list\n"
            "\t[--zone <zone>]\n");
}

    void
usage_database ()
{
    fprintf(stderr,
            "  database backup\n"
            "\t[--output <output>]                      aka -o\n");
}

    void
usage_zonelist2 ()
{
        fprintf(stderr,
            "  zonelist export\n"
            "  zonelist import\n");
}

    void
usage ()
{
    fprintf(stderr,
            "usage: %s [-c <config> | --config <config>] command [options]\n\n",
	    progname);

    usage_general ();
    usage_setup ();
    usage_control ();
    usage_update ();
    usage_zoneadd ();
    usage_zonedel ();
    usage_zonelist ();
    usage_repo ();
    usage_policyexport ();
    usage_policyimport ();
    usage_policylist ();
    usage_policypurge ();
    usage_keylist ();
    usage_keyexport ();
    usage_keyimport ();
    usage_keyroll ();
    usage_keypurge ();
    usage_keydelete ();
    usage_keygen ();
    usage_keykskretire ();
    /* usage_keykskrevoke (); Users shouldn't use this */
    usage_keydsseen ();
    usage_backup ();
    usage_rollover ();
    usage_database ();
    usage_zonelist2 ();

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

void
states_help()
{
    fprintf(stderr,
            "key states: GENERATE|PUBLISH|READY|ACTIVE|RETIRE|DEAD\n");
}

void
types_help()
{
    fprintf(stderr,
            "key types:  KSK|ZSK\n");
}

/*
 * Check if the file exists.
 * @param filename: name of file to be checked.
 * @return: (int) 1 if file exist, 0 otherwise.
 *
 */
static int
exist_file(const char* filename) {
	int status = 0;
	FILE *file = fopen(filename, "r");
	if(file != NULL){
		fclose(file);
		status = 1;
	}
	return status;
}

/* 
 * Do initial import of config files into database
 */
int
cmd_setup ()
{
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */
    char* zone_list_filename;   /* Extracted from conf.xml */
    char* kasp_filename;    /* Extracted from conf.xml */
    int status = 0;

    /* Database connection details */
    char *dbschema = NULL;
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *password = NULL;

	char quoted_user[KSM_NAME_LENGTH];
	char quoted_password[KSM_NAME_LENGTH];

    char* setup_command = NULL;
    char* lock_filename = NULL;

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

        /* Make sure that nothing is happening to the DB */
        StrAppend(&lock_filename, dbschema);
        StrAppend(&lock_filename, ".our_lock");

        lock_fd = fopen(lock_filename, "w");
        status = get_lite_lock(lock_filename, lock_fd);
        if (status != 0) {
            printf("Error getting db lock\n");
            if (lock_fd != NULL) {
                fclose(lock_fd);
            }
            StrFree(lock_filename);
            StrFree(host);
            StrFree(port);
            StrFree(dbschema);
            StrFree(user);
            StrFree(password);
            return(1);
        }
        StrFree(lock_filename);

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
            db_disconnect(lock_fd);
            StrFree(host);
            StrFree(port);
            StrFree(dbschema);
            StrFree(user);
            StrFree(password);
            StrFree(setup_command);
            return(1);
        }
        StrFree(setup_command);

        /* If we are running as root then chmod the file so that the 
           final user/group can access it. */
        if (fix_file_perms(dbschema) != 0)
        {
            printf("Couldn't fix permissions on file %s\n", dbschema);
            printf("Will coninue with setup, but you may need to manually change ownership\n");
        }
    }
    else {
        /* MySQL setup */
        /* will look like: <SQL_BIN> -u <USER> -h <HOST> -P <PORT> -p<PASSWORD> <DBSCHEMA> < <SQL_SETUP> */
		/* Get a quoted version of the username */
		status = ShellQuoteString(user, quoted_user, KSM_NAME_LENGTH);
		if (status != 0) {
			printf("Failed to connect to database, username too long.\n");
			db_disconnect(lock_fd);
			StrFree(host);
			StrFree(port);
			StrFree(dbschema);
			StrFree(user);
			StrFree(password);
			return(1);
		}

		/* Get a quoted version of the password */
		if (password != NULL) {
			status = ShellQuoteString(password, quoted_password, KSM_NAME_LENGTH);
			if (status != 0) {
				printf("Failed to connect to database, password too long.\n");
				db_disconnect(lock_fd);
				StrFree(host);
				StrFree(port);
				StrFree(dbschema);
				StrFree(user);
				StrFree(password);
				return(1);
			}
		}
		
        StrAppend(&setup_command, SQL_BIN);
        StrAppend(&setup_command, " -u '");
        StrAppend(&setup_command, quoted_user);
        StrAppend(&setup_command, "'");
        if (host != NULL) {
            StrAppend(&setup_command, " -h ");
            StrAppend(&setup_command, host);
            if (port != NULL) {
                StrAppend(&setup_command, " -P ");
                StrAppend(&setup_command, port);
            }
        }
        if (password != NULL) {
            StrAppend(&setup_command, " -p'");
            StrAppend(&setup_command, quoted_password);
			StrAppend(&setup_command, "'");
        }
        StrAppend(&setup_command, " ");
        StrAppend(&setup_command, dbschema);
        StrAppend(&setup_command, " < ");
        StrAppend(&setup_command, SQL_SETUP);

        if (system(setup_command) != 0)
        {
            printf("Could not call db setup command:\n\t%s\n", setup_command);
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
    status = DbConnect(&dbhandle, dbschema, host, password, user, port);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        StrFree(host);
        StrFree(port);
        StrFree(dbschema);
        StrFree(user);
        StrFree(password);
        return(1);
    }

    /* Free these up early */
    StrFree(host);
    StrFree(port);
    StrFree(dbschema);
    StrFree(user);
    StrFree(password);

    /* 
     *  Now we will read the conf.xml file again, but this time we will not validate.
     *  Instead we just learn the location of the zonelist.xml and kasp.xml files.
     */
    status = read_filenames(&zone_list_filename, &kasp_filename);
    if (status != 0) {
        /* TODO kasp_filename might or might not be set, we don't know!
         * read_filenames should promise us not to set it on error */
        printf("Failed to read conf.xml\n");
        db_disconnect(lock_fd);
        return(1);
    }

    /* 
     *  Now we will read the conf.xml file again, but this time we will not validate.
     *  Instead we just extract the RepositoryList into the database
     */
    status = update_repositories();
    if (status != 0) {
        printf("Failed to update repositories\n");
        db_disconnect(lock_fd);
        StrFree(zone_list_filename);
		StrFree(kasp_filename);
        return(1);
    }

    /*
     * Now read the kasp.xml which should be in the same directory.
     * This lists all of the policies.
     */
    status = update_policies(kasp_filename);
    if (status != 0) {
        printf("Failed to update policies\n");
        printf("SETUP FAILED\n");
        db_disconnect(lock_fd);
        StrFree(zone_list_filename);
		StrFree(kasp_filename);
        return(1);
    }

    StrFree(kasp_filename);

    /*
     * Take the zonelist we learnt above and read it, updating or inserting zone
     * records in the database as we go.
     */
    status = update_zones(zone_list_filename);
    StrFree(zone_list_filename);
    if (status != 0) {
        printf("Failed to update zones\n");
        db_disconnect(lock_fd);
        return(1);
    }

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

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
cmd_update (const char* qualifier)
{
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;  /* This is the lock file descriptor for a SQLite DB */
    char* zone_list_filename = NULL;    /* Extracted from conf.xml */
    char* kasp_filename = NULL;         /* Extracted from conf.xml */
    int status = 0;
    int done_something = 0;

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

    /* 
     *  Now we will read the conf.xml file again, but this time we will not validate.
     *  Instead we just learn the location of the zonelist.xml and kasp.xml files.
     */
    if (strncmp(qualifier, "ZONELIST", 8) == 0 ||
            strncmp(qualifier, "KASP", 4) == 0 ||
            strncmp(qualifier, "ALL", 3) == 0) {
        status = read_filenames(&zone_list_filename, &kasp_filename);
        if (status != 0) {
            /* TODO kasp_filename *could* be leaking */
            printf("Failed to read conf.xml\n");
            db_disconnect(lock_fd);
            return(1);
        }
    }

    /* 
     *  Read the conf.xml file yet again, but this time we will not validate.
     *  Instead we just extract the RepositoryList into the database.
     */
    if (strncmp(qualifier, "CONF", 4) == 0 ||
            strncmp(qualifier, "ALL", 3) == 0) {
        status = update_repositories();
        if (status != 0) {
            printf("Failed to update repositories\n");
            db_disconnect(lock_fd);
            if (strncmp(qualifier, "ALL", 3) == 0) {
                StrFree(kasp_filename);
                StrFree(zone_list_filename);
            }
            return(1);
        }
        done_something = 1;
    }

    /*
     * Now read the kasp.xml which should be in the same directory.
     * This lists all of the policies.
     */
    if (strncmp(qualifier, "KASP", 4) == 0 ||
            strncmp(qualifier, "ALL", 3) == 0) {
        status = update_policies(kasp_filename);
        if (status != 0) {
            printf("Failed to update policies\n");
            db_disconnect(lock_fd);
            StrFree(kasp_filename);
            StrFree(zone_list_filename);
            return(1);
        }
        done_something = 1;
    }

    /*
     * Take the zonelist we learnt above and read it, updating or inserting zone
     * records in the database as we go.
     */
    if (strncmp(qualifier, "ZONELIST", 8) == 0 ||
            strncmp(qualifier, "ALL", 3) == 0) {
        status = update_zones(zone_list_filename);
        if (status != 0) {
            printf("Failed to update zones\n");
            db_disconnect(lock_fd);
            StrFree(kasp_filename);
            StrFree(zone_list_filename);
            return(1);
        }
        done_something = 1;
    }

    /*
     * See if we did anything, otherwise log an error
     */
    if (done_something == 0) {
        printf("Unrecognised command update %s. Please specify one of:\n", qualifier);
        usage_update();
    } else {
		/* Need to poke the enforcer to wake it up */
		if (restart_enforcerd() != 0)
		{
			fprintf(stderr, "Could not HUP ods-enforcerd\n");
		}
	}

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    DbDisconnect(dbhandle);

    if (kasp_filename != NULL) {
        StrFree(kasp_filename);
    }
    if (zone_list_filename != NULL) {
        StrFree(zone_list_filename);
    }

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
cmd_addzone ()
{
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */
    char* zonelist_filename = NULL;
    char* backup_filename = NULL;
    /* The settings that we need for the zone */
    char* sig_conf_name = NULL;
    char* input_name = NULL;
    char* output_name = NULL;
    char* input_type = NULL;
    char* output_type = NULL;
    int policy_id = 0;
    int new_zone;   /* ignored */

    DB_RESULT      result;         /* Result of parameter query */
    KSM_PARAMETER   data;           /* Parameter information */

    xmlDocPtr doc = NULL;

    int status = 0;

    char *path = getcwd(NULL, MAXPATHLEN);
    if (path == NULL) {
        printf("Couldn't malloc path: %s\n", strerror(errno));
        exit(1);
    }

    /* See what arguments we were passed (if any) otherwise set the defaults */
    if (o_zone == NULL) {
        printf("Please specify a zone with the --zone option\n");
        usage_zone();
        return(1);
    }

    if (o_policy == NULL) {
        o_policy = StrStrdup("default");
    }
    /*
     * Set defaults and turn any relative paths into absolute 
     * (sort of, not the neatest output)
     */
    if (o_signerconf == NULL) {
        StrAppend(&sig_conf_name, OPENDNSSEC_STATE_DIR);
        StrAppend(&sig_conf_name, "/signconf/");
        StrAppend(&sig_conf_name, o_zone);
        StrAppend(&sig_conf_name, ".xml");
    }
    else if (*o_signerconf != '/') {
        StrAppend(&sig_conf_name, path);
        StrAppend(&sig_conf_name, "/");
        StrAppend(&sig_conf_name, o_signerconf);
    } else {
        StrAppend(&sig_conf_name, o_signerconf);
    }

    /* in the case of a 'DNS' adapter using a default path */
    if (o_in_type == NULL) {
      	StrAppend(&input_type, "File");
    } else if (strncmp(o_in_type,"DNS",3)==0 || strncmp(o_in_type,"File",4)==0){
        StrAppend(&input_type, o_in_type);
    } else {
	      printf("Error: Unrecognised in-type %s; should be one of DNS or File\n",o_in_type);
	      StrFree(sig_conf_name);
	      return(1);
    }

    if (o_input == NULL) {
    	if(strcmp(input_type, "DNS")==0){
       		StrAppend(&input_name, OPENDNSSEC_CONFIG_DIR);
   			StrAppend(&input_name, "/addns.xml");
       	}else{
       		StrAppend(&input_name, OPENDNSSEC_STATE_DIR);
   			StrAppend(&input_name, "/unsigned/");
   			StrAppend(&input_name, o_zone);
       	}
    }
    else if (*o_input != '/') {
    	StrAppend(&input_name, path);
    	StrAppend(&input_name, "/");
    	StrAppend(&input_name, o_input);
    } else {
    	StrAppend(&input_name, o_input);
    }

	if (o_out_type == NULL) {
		StrAppend(&output_type, "File");
	} else if (strncmp(o_out_type,"DNS",3)==0 || strncmp(o_out_type,"File",4)==0){
		StrAppend(&output_type, o_out_type);
	} else {
		printf("Error: Unrecognised out-type %s; should be one of DNS or File\n",o_out_type);
        StrFree(sig_conf_name);
        StrFree(input_type);
        StrFree(input_name);
		return(1);
	}

    if (o_output == NULL) {
    	if(strcmp(output_type, "DNS") == 0){
       		StrAppend(&output_name, OPENDNSSEC_CONFIG_DIR);
   			StrAppend(&output_name, "/addns.xml");
   		}else{
   			StrAppend(&output_name, OPENDNSSEC_STATE_DIR);
   			StrAppend(&output_name, "/signed/");
   			StrAppend(&output_name, o_zone);
   		}

    }
    else if (*o_output != '/') {
    	StrAppend(&output_name, path);
    	StrAppend(&output_name, "/");
    	StrAppend(&output_name, o_output);
    } else {
    	StrAppend(&output_name, o_output);
    }


   	/* validate if the input file exist */
   	if(!exist_file(input_name)){
   		fprintf(stdout, "WARNING: The input file %s for zone %s does not currently exist. The zone will been added to the database anyway. \n",input_name, o_zone);
   	}

   	if(strcmp(output_type, "DNS") == 0 && !exist_file(output_name)){
   		fprintf(stdout, "WARNING: The output file %s for zone %s does not currently exist. \n",output_name, o_zone);
   	}

    free(path);

    /* Set zonelist from the conf.xml that we have got */
    status = read_zonelist_filename(&zonelist_filename);
    if (status != 0) {
        printf("couldn't read zonelist\n");
        StrFree(zonelist_filename);
        StrFree(sig_conf_name);
        StrFree(input_name);
        StrFree(output_name);
        StrFree(input_type);
        StrFree(output_type);
        return(1);
    }

	/* check that zonelist.xml.backup is writable */
	StrAppend(&backup_filename, zonelist_filename);
	StrAppend(&backup_filename, ".backup");
    if (xml_flag == 1) {
		if (access(backup_filename, F_OK) == 0){
			if (access(backup_filename, W_OK)){
				printf("ERROR: The backup file %s can not be written.\n",backup_filename);
				StrFree(zonelist_filename);
				StrFree(sig_conf_name);
				StrFree(input_name);
				StrFree(output_name);
				StrFree(input_type);
				StrFree(output_type);
				StrFree(backup_filename);
				return(1);
			}
		}else{
			if (access(OPENDNSSEC_CONFIG_DIR, W_OK)){
				printf("ERROR: The backup file %s can not be written.\n",backup_filename);
				StrFree(zonelist_filename);
				StrFree(sig_conf_name);
				StrFree(input_name);
				StrFree(output_name);
				StrFree(input_type);
				StrFree(output_type);
				StrFree(backup_filename);
				return(1);
			}
		}
	}
	/*
     * Push this new zonelist into the database
     */

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        StrFree(zonelist_filename);
        StrFree(sig_conf_name);
        StrFree(input_name);
        StrFree(output_name);
        StrFree(input_type);
        StrFree(output_type);
		StrFree(backup_filename);
        return(1);
    } 

    /* Now stick this zone into the database */
    status = KsmPolicyIdFromName(o_policy, &policy_id);
    if (status != 0) {
        printf("Error, can't find policy : %s\n", o_policy);
        printf("Failed to update zones\n");
        db_disconnect(lock_fd);
        StrFree(zonelist_filename);
        StrFree(sig_conf_name);
        StrFree(input_name);
        StrFree(output_name);
        StrFree(input_type);
        StrFree(output_type);
		StrFree(backup_filename);
        return(1);
    }
    status = KsmImportZone(o_zone, policy_id, 1, &new_zone, sig_conf_name, input_name, output_name, input_type, output_type);
    if (status != 0) {
        if (status == -2) {
            printf("Failed to Import zone %s; it already exists\n", o_zone);
		} else if (status == -3) {
            printf("Failed to Import zone %s; it already exists both with and without a trailing dot\n", o_zone);
        } else {
            printf("Failed to Import zone\n");
        }
        db_disconnect(lock_fd);
        StrFree(zonelist_filename);
        StrFree(sig_conf_name);
        StrFree(input_name);
        StrFree(output_name);
        StrFree(input_type);
        StrFree(output_type);
		StrFree(backup_filename);
        return(1);
    }

    /* If need be (keys shared on policy) link existing keys to zone */
    /* First work out if the keys are shared on this policy */
    status = KsmParameterInit(&result, "zones_share_keys", "keys", policy_id);
    if (status != 0) {
        printf("Can't retrieve shared-keys parameter for policy\n");
        db_disconnect(lock_fd);
        StrFree(zonelist_filename);
        StrFree(sig_conf_name);
        StrFree(input_name);
        StrFree(output_name);
        StrFree(input_type);
        StrFree(output_type);
		StrFree(backup_filename);
        return(1);
    }
    status = KsmParameter(result, &data);
    if (status != 0) {
        printf("Can't retrieve shared-keys parameter for policy\n");
        db_disconnect(lock_fd);
        StrFree(zonelist_filename);
        StrFree(sig_conf_name);
        StrFree(input_name);
        StrFree(output_name);
        StrFree(input_type);
        StrFree(output_type);
		StrFree(backup_filename);
        return(1);
    }
    KsmParameterEnd(result);
    
    /* If the policy does not share keys then skip this */
    if (data.value == 1) {
        status = LinkKeys(o_zone, policy_id);
        if (status != 0) {
            printf("Failed to Link Keys to zone\n");
            /* Carry on and write the xml if the error code was 2 
               (not enough keys) */
            if (status != 2) {
                db_disconnect(lock_fd);
                StrFree(zonelist_filename);
                StrFree(sig_conf_name);
                StrFree(input_name);
                StrFree(output_name);
				StrFree(input_type);
				StrFree(output_type);
				StrFree(backup_filename);
                return(1);
            }
        }
    }

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);
    DbDisconnect(dbhandle);

    if (xml_flag == 1) {
        /* Read the file and add our new node in memory */
        /* TODO don't add if it already exists */
        xmlKeepBlanksDefault(0);
        xmlTreeIndentString = "\t";
        doc = add_zone_node(zonelist_filename, o_zone, o_policy, sig_conf_name, input_name, output_name, input_type, output_type);

        StrFree(sig_conf_name);
        StrFree(input_name);
        StrFree(output_name);
        StrFree(input_type);
        StrFree(output_type);

        if (doc == NULL) {
            printf("Error: Couldn't add our new node in memory\n");
            StrFree(zonelist_filename);
			StrFree(backup_filename);
            return(1);
        }

        /* Backup the current zonelist */
        status = backup_file(zonelist_filename, backup_filename);
        if (status != 0) {
            printf("Error: Backup %s FAILED, please backup %s manually and run \"ods-ksmutil zonelist export\" to update zonelist.xml\n", backup_filename, backup_filename);
            StrFree(zonelist_filename);
			StrFree(backup_filename);
            return(status);
        }

        /* Save our new one over, TODO should we validate it first? */
        status = xmlSaveFormatFile(zonelist_filename, doc, 1);
        StrFree(zonelist_filename);
        xmlFreeDoc(doc);

        if (status == -1) {
            printf("Error: couldn't save zonelist, please run \"ods-ksmutil zonelist export\" to update zonelist.xml\n");
			StrFree(backup_filename);
            return(1);
        }
    }
    else {
        StrFree(zonelist_filename);
        StrFree(sig_conf_name);
        StrFree(input_name);
        StrFree(output_name);
        StrFree(input_type);
        StrFree(output_type);
    }

    /* TODO - KICK THE ENFORCER? */
    /* <matthijs> TODO - ods-signer update? */

    if (xml_flag == 0) {
        printf("Imported zone: %s into database only, please run \"ods-ksmutil zonelist export\" to update zonelist.xml\n", o_zone);
    } else {
        printf("Imported zone: %s\n", o_zone);
    }

    StrFree(backup_filename);

    return 0;
}

/*
 * Delete a zone from the config 
 */
    int
cmd_delzone ()
{

    char* zonelist_filename = NULL;
    char* backup_filename = NULL;
    /* The settings that we need for the zone */
    int zone_id = -1;
    int policy_id = -1;

    xmlDocPtr doc = NULL;

    int status = 0;
    int user_certain;           /* Continue ? */

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

    /* We should either have a policy name or --all but not both */
    if (all_flag && o_zone != NULL) {
        printf("can not use --all with --zone\n");
        return(1);
    } 
    else if (!all_flag && o_zone == NULL) {
        printf("please specify either --zone <zone> or --all\n");
        return(1);
    }

    /* Warn and confirm if they have asked to delete all zones */
    if (all_flag == 1) {
        printf("*WARNING* This will remove all zones from OpenDNSSEC; are you sure? [y/N] ");

        user_certain = getchar();
        if (user_certain != 'y' && user_certain != 'Y') {
            printf("Okay, quitting...\n");
            exit(0);
        }
    }

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

	/* Put dot back in if we need to; delete zone is the only time we do this */
	if (td_flag == 1) {
		StrAppend(&o_zone, ".");
	}
    /*
     * DO XML STUFF FIRST
     */

    if (xml_flag == 1) {
        /* Set zonelist from the conf.xml that we have got */
        status = read_zonelist_filename(&zonelist_filename);
        if (status != 0) {
            printf("couldn't read zonelist\n");
            db_disconnect(lock_fd);
            StrFree(zonelist_filename);
            return(1);
        }

        /* Read the file and delete our zone node(s) in memory */
		/* N.B. This is deliberately _not_ trailing dot agnostic; the user will have to ask to delete the exact zone */
        doc = del_zone_node(zonelist_filename, o_zone);
        if (doc == NULL) {
            db_disconnect(lock_fd);
            StrFree(zonelist_filename);
            return(1);
        }

		/* rename the Signconf file so that if the zone is readded the old 
		 * file will not be used */
		status = rename_signconf(zonelist_filename, o_zone);
		if (status != 0) {
            StrFree(zonelist_filename);
            db_disconnect(lock_fd);
            return(status);
        }

        /* Backup the current zonelist */
        StrAppend(&backup_filename, zonelist_filename);
        StrAppend(&backup_filename, ".backup");
        status = backup_file(zonelist_filename, backup_filename);
        StrFree(backup_filename);
        if (status != 0) {
            StrFree(zonelist_filename);
            db_disconnect(lock_fd);
            return(status);
        }

        /* Save our new one over, TODO should we validate it first? */
        status = xmlSaveFormatFile(zonelist_filename, doc, 1);
        xmlFreeDoc(doc);
        StrFree(zonelist_filename);
        if (status == -1) {
            printf("Could not save %s\n", zonelist_filename);
            db_disconnect(lock_fd);
            return(1);
        }
    }

    /*
     * NOW SORT OUT THE DATABASE (zone_id will still be -1 if we are deleting all)
     */

    /* See if the zone exists and get its ID, assuming we are not deleting all */
    if (all_flag == 0) {
        status = KsmZoneIdAndPolicyFromName(o_zone, &policy_id, &zone_id);
        if (status != 0) {
            printf("Couldn't find zone %s\n", o_zone);
            db_disconnect(lock_fd);
            return(1);
        }
    }

    /* Mark keys as dead */
    status = KsmMarkKeysAsDead(zone_id);
    if (status != 0) {
        printf("Error: failed to mark keys as dead in database\n");
        db_disconnect(lock_fd);
        return(status);
    }

    /* Finally, we can delete the zone */
    status = KsmDeleteZone(zone_id);

    if (status != 0) {
        printf("Error: failed to remove zone%s from database\n", (all_flag == 1) ? "s" : "");
        db_disconnect(lock_fd);
        return status;
    }
    
    /* Call the signer_engine_cli to tell it that the zonelist has changed */
    if (all_flag == 0) {
        if (system(SIGNER_CLI_UPDATE) != 0)
        {
            printf("Could not call signer engine\n");
        }
    }

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    if (xml_flag == 0) {
        printf("Deleted zone: %s from database only, please run \"ods-ksmutil zonelist export\" to update zonelist.xml\n", o_zone);
    }

    return 0;
}

/*
 * List a zone 
 */
    int
cmd_listzone ()
{

    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;  /* This is the lock file descriptor for a SQLite DB */

    char* zonelist_filename = NULL;
    int* zone_ids;      /* List of zone_ids seen from zonelist.xml */

    xmlTextReaderPtr reader = NULL;
    int ret = 0; /* status of the XML parsing */
    char* tag_name = NULL;

    int file_zone_count = 0; /* As a quick check we will compare the number of */
    int     j = 0;          /* Another counter */
    char    buffer[256];    /* For constructing part of the command */
    char*   sql = NULL;   /* SQL "IN" query */
    DB_RESULT	result;         /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */
    char*       temp_name = NULL;

    int status = 0;

    /* Set zonelist from the conf.xml that we have got */
    status = read_zonelist_filename(&zonelist_filename);
    if (status != 0) {
        printf("couldn't read zonelist\n");
        if (zonelist_filename != NULL) {
            StrFree(zonelist_filename);
        }
        return(1);
    }

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

    /* Read through the file counting zones TODO better way to do this? */
    reader = xmlNewTextReaderFilename(zonelist_filename);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            tag_name = (char*) xmlTextReaderLocalName(reader);
            /* Found <Zone> */
            if (strncmp(tag_name, "Zone", 4) == 0 
                    && strncmp(tag_name, "ZoneList", 8) != 0
                    && xmlTextReaderNodeType(reader) == 1) {
                file_zone_count++;
            }
            /* Read the next line */
            ret = xmlTextReaderRead(reader);
            StrFree(tag_name);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            printf("%s : failed to parse\n", zonelist_filename);
        }
    } else {
        printf("Unable to open %s\n", zonelist_filename);
    }

    /* Allocate space for the list of zone IDs */
    zone_ids = MemMalloc(file_zone_count * sizeof(int));

    /* Read the file and list the zones as we go */
    list_zone_node(zonelist_filename, zone_ids);

	/* Now see if there are any zones in the DB which are not in the file */
	if (file_zone_count != 0) {
		StrAppend(&sql, "select name from zones where id not in (");
		for (j = 0; j < file_zone_count; ++j) {
			if (j != 0) {
				StrAppend(&sql, ",");
			}
			snprintf(buffer, sizeof(buffer), "%d", zone_ids[j]);
			StrAppend(&sql, buffer);
		}
		StrAppend(&sql, ")");
	} else {
		StrAppend(&sql, "select name from zones");
	}

    status = DbExecuteSql(DbHandle(), sql, &result);
    if (status == 0) {
        status = DbFetchRow(result, &row);
        while (status == 0) {
            /* Got a row, print it */
            DbString(row, 0, &temp_name);

            printf("Found zone %s in DB but not zonelist.\n", temp_name);
            status = DbFetchRow(result, &row);
			file_zone_count++;
        }

        /* Convert EOF status to success */

        if (status == -1) {
            status = 0;
        }

        DbFreeResult(result);
    }

    db_disconnect(lock_fd);
    DbDisconnect(dbhandle);

	if (file_zone_count == 0) {
		printf("No zones in DB or zonelist.\n");
	}

	DbFreeRow(row);
    MemFree(zone_ids);
    StrFree(sql);
    StrFree(zonelist_filename);
    StrFree(temp_name);

    return 0;
}

/*
 * To export: 
 *          keys|ds for zone
 */
    int
cmd_exportkeys ()
{
    int status = 0;
    /* Database connection details */
    DB_HANDLE	dbhandle;

    int zone_id = -1;
    int state_id = -1;
    int keytype_id = KSM_TYPE_KSK;
	int red_seen = -1; /* Warn if no active or ready keys seen */
	int act_seen = -1; /* Also warn if it looks like a rollover is happening */
	int prev_zone_id = -1;

    char *case_keytype = NULL;
    char *case_keystate = NULL;
    char *zone_name = NULL;

    /* Key information */
    hsm_key_t *key = NULL;
    ldns_rr *dnskey_rr = NULL;
    ldns_rr *ds_sha1_rr = NULL;
    ldns_rr *ds_sha256_rr = NULL;
    hsm_sign_params_t *sign_params = NULL;

	/* To find the ttl of the DS */
	int policy_id = -1;
	int rrttl = -1;
	int param_id = -1; /* unused */

    char* sql = NULL;
    KSM_KEYDATA data;       /* Data for each key */
    DB_RESULT	result;     /* Result set from query */
    size_t  nchar;          /* Number of characters written */
    char    buffer[256];    /* For constructing part of the command */

	int done_something = 0; /* Have we exported any keys? */
    hsm_ctx_t* ctx;

    /* See what arguments we were passed (if any) otherwise set the defaults */
    /* Check keystate, can be state or keytype */
    if (o_keystate != NULL) {
        case_keystate = StrStrdup(o_keystate);
        (void) StrToUpper(case_keystate);
        if (strncmp(case_keystate, "KEYPUBLISH", 10) == 0 || strncmp(o_keystate, "10", 2) == 0) {
            state_id =  KSM_STATE_KEYPUBLISH;
        }
        else if (strncmp(case_keystate, "GENERATE", 8) == 0 || strncmp(o_keystate, "1", 1) == 0) {
            state_id = KSM_STATE_GENERATE;
        }
        else if (strncmp(case_keystate, "PUBLISH", 7) == 0 || strncmp(o_keystate, "2", 1) == 0) {
            state_id =  KSM_STATE_PUBLISH;
        }
        else if (strncmp(case_keystate, "READY", 5) == 0 || strncmp(o_keystate, "3", 1) == 0) {
            state_id =  KSM_STATE_READY;
        }
        else if (strncmp(case_keystate, "ACTIVE", 6) == 0 || strncmp(o_keystate, "4", 1) == 0) {
            state_id =  KSM_STATE_ACTIVE;
        }
        else if (strncmp(case_keystate, "RETIRE", 6) == 0 || strncmp(o_keystate, "5", 1) == 0) {
            state_id =  KSM_STATE_RETIRE;
        }
        else if (strncmp(case_keystate, "DEAD", 4) == 0 || strncmp(o_keystate, "6", 1) == 0) {
            state_id =  KSM_STATE_DEAD;
        }
        else if (strncmp(case_keystate, "DSSUB", 5) == 0 || strncmp(o_keystate, "7", 1) == 0) {
            state_id =  KSM_STATE_DSSUB;
        }
        else if (strncmp(case_keystate, "DSPUBLISH", 9) == 0 || strncmp(o_keystate, "8", 1) == 0) {
            state_id =  KSM_STATE_DSPUBLISH;
        }
        else if (strncmp(case_keystate, "DSREADY", 7) == 0 || strncmp(o_keystate, "9", 1) == 0) {
            state_id =  KSM_STATE_DSREADY;
        }
        else {
            printf("Error: Unrecognised state %s; should be one of GENERATE, PUBLISH, READY, ACTIVE, RETIRE, DEAD, DSSUB, DSPUBLISH, DSREADY or KEYPUBLISH\n", o_keystate);

            StrFree(case_keystate);
            return(1);
        }
        StrFree(case_keystate);
    }

    /* Check keytype */
    if (o_keytype != NULL) {
        case_keytype = StrStrdup(o_keytype);
        (void) StrToUpper(case_keytype);
        if (strncmp(case_keytype, "KSK", 3) == 0 || strncmp(o_keytype, "257", 3) == 0) {
            keytype_id = KSM_TYPE_KSK;
        }
        else if (strncmp(case_keytype, "ZSK", 3) == 0 || strncmp(o_keytype, "256", 3) == 0) {
            keytype_id = KSM_TYPE_ZSK;
        }
        else {
            printf("Error: Unrecognised keytype %s; should be one of KSK or ZSK\n", o_keytype);

            StrFree(case_keytype);
            return(1);
        }
        StrFree(case_keytype);
    }

    /* try to connect to the database */
    status = db_connect(&dbhandle, NULL, 0);
    if (status != 0) {
        printf("Failed to connect to database\n");
        return(1);
    }

    /* check that the zone name is valid and use it to get some ids */
    if (o_zone != NULL) {
        status = KsmZoneIdFromName(o_zone, &zone_id);
        if (status != 0) {
			/* Try again with td */
			StrAppend(&o_zone, ".");
			status = KsmZoneIdFromName(o_zone, &zone_id);
			if (status != 0) {
				printf("Error: unable to find a zone named \"%s\" in database\n", o_zone);
				return(status);
			}
		}
    }

    status = hsm_open(config, hsm_prompt_pin);
    if (status) {
        hsm_print_error(NULL);
        exit(-1);
    }
    ctx = hsm_create_context();

    sql = DqsSpecifyInit("KEYDATA_VIEW", DB_KEYDATA_FIELDS);
    if (state_id != -1) {
        DqsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, state_id, 0);
    } else {
        nchar = snprintf(buffer, sizeof(buffer), "(%d, %d, %d, %d, %d, %d)",
                KSM_STATE_READY, KSM_STATE_ACTIVE, KSM_STATE_DSSUB, 
                KSM_STATE_DSPUBLISH, KSM_STATE_DSREADY, KSM_STATE_KEYPUBLISH);
        if (nchar >= sizeof(buffer)) {
            status = -1;
                        hsm_destroy_context(ctx);
			hsm_close();
            return status;
        }
        DqsConditionKeyword(&sql, "STATE", DQS_COMPARE_IN, buffer, 0);

    }
    DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype_id, 1);
    if (zone_id != -1) {
        DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, 2);
    }
    DqsOrderBy(&sql, "STATE");
    DqsEnd(&sql);

    status = KsmKeyInitSql(&result, sql);
    if (status == 0) {
        status = KsmKey(result, &data);
        while (status == 0) {

			if (ds_flag == 1 && data.zone_id != prev_zone_id) {
				prev_zone_id = data.zone_id;
				if (red_seen == 0 && act_seen == 0) {
					printf("\nWARNING: No active or ready keys seen for this zone. Do not load any DS records to the parent unless you understand the possible consequences.\n");
				} else if (red_seen == 1 && act_seen == 1) {
					printf("\nWARNING: BOTH ready and active keys seen for this zone. Probably a key rollover is happening and you may only want the ready key to be submitted.\n");
				} else {
					red_seen = 0;
					act_seen = 0;
				}
			}

			if (data.state == KSM_STATE_READY) {
				red_seen = 1;
			} else if (data.state == KSM_STATE_ACTIVE) {
				act_seen = 1;
			}

            /* Code to output the DNSKEY record  (stolen from hsmutil) */
            key = hsm_find_key_by_id(ctx, data.location);

            if (!key) {
                printf("Key %s in DB but not repository\n", data.location);
                                hsm_destroy_context(ctx);
				hsm_close();
                return -1;
            }

            sign_params = hsm_sign_params_new();
            /* If zone_id == -1 then we need to work out the zone name from data.zone_id */
            if (zone_id == -1) {
                status = KsmZoneNameFromId(data.zone_id, &zone_name);
                if (status != 0) {
                    printf("Error: unable to find zone name for id %d\n", zone_id);
                    hsm_sign_params_free(sign_params);
                                        hsm_destroy_context(ctx);
					hsm_close();
                    return(status);
                }
                sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, zone_name);
                StrFree(zone_name);
            }
            else {
                sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, o_zone);
            }

            sign_params->algorithm = data.algorithm;
            sign_params->flags = LDNS_KEY_ZONE_KEY;
            if (keytype_id == KSM_TYPE_KSK) {
                sign_params->flags += LDNS_KEY_SEP_KEY;
            }
            dnskey_rr = hsm_get_dnskey(ctx, key, sign_params);
            sign_params->keytag = ldns_calc_keytag(dnskey_rr);

            if (ds_flag == 0) {

				/* Set TTL if we can find it; else leave it as the default */
				/* We need a policy id */
				status = KsmPolicyIdFromZoneId(data.zone_id, &policy_id);
				if (status == 0) {

					/* Use this to get the TTL parameter value */
					if (keytype_id == KSM_TYPE_KSK) {
						status = KsmParameterValue(KSM_PAR_KSKTTL_STRING, KSM_PAR_KSKTTL_CAT, &rrttl, policy_id, &param_id);
					} else {
						status = KsmParameterValue(KSM_PAR_ZSKTTL_STRING, KSM_PAR_ZSKTTL_CAT, &rrttl, policy_id, &param_id);
					}
					if (status == 0) {
						ldns_rr_set_ttl(dnskey_rr, rrttl);
					}
				}

                printf("\n;%s %s DNSKEY record:\n", KsmKeywordStateValueToName(data.state), (keytype_id == KSM_TYPE_KSK ? "KSK" : "ZSK"));
                ldns_rr_print(stdout, dnskey_rr);
            }
            else {

				/* Set TTL if we can find it; else leave it as the default */
				/* We need a policy id */
				status = KsmPolicyIdFromZoneId(data.zone_id, &policy_id);
				if (status == 0) {

					/* Use this to get the DSTTL parameter value */
					status = KsmParameterValue(KSM_PAR_DSTTL_STRING, KSM_PAR_DSTTL_CAT, &rrttl, policy_id, &param_id);
					if (status == 0) {
						ldns_rr_set_ttl(dnskey_rr, rrttl);
					}
				}

                printf("\n;%s %s DS record (SHA1):\n", KsmKeywordStateValueToName(data.state), (keytype_id == KSM_TYPE_KSK ? "KSK" : "ZSK"));
                ds_sha1_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA1);
                ldns_rr_print(stdout, ds_sha1_rr);

                printf("\n;%s %s DS record (SHA256):\n", KsmKeywordStateValueToName(data.state), (keytype_id == KSM_TYPE_KSK ? "KSK" : "ZSK"));
                ds_sha256_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA256);
                ldns_rr_print(stdout, ds_sha256_rr);
            }

			done_something = 1;

            hsm_sign_params_free(sign_params);
            hsm_key_free(key);
            status = KsmKey(result, &data);

        }
        /* Convert EOF status to success */
        if (status == -1) {
            status = 0;
        }

        KsmKeyEnd(result);
    }
	if (ds_flag == 1 && red_seen == 0 && act_seen == 0) {
		printf("\nWARNING: No active or ready keys seen for this zone. Do not load any DS records to the parent unless you understand the possible consequences.\n");
	} else if (ds_flag == 1 && red_seen == 1 && act_seen == 1) {
		printf("\nWARNING: BOTH ready and active keys seen for this zone. Probably a key rollover is happening and you may only want the ready key to be submitted.\n");
	}

	/* If we did nothing then explain why not */
	if (!done_something) {
		if (state_id != -1) {
			printf("No keys in %s state to export.\n", KsmKeywordStateValueToName(state_id) );
		} else {
			printf("No keys in READY state or higher to export.\n");
		}
	}

    /* TODO when the above is working then replicate it twice for the case where keytype == -1 */

    if (dnskey_rr != NULL) {
        ldns_rr_free(dnskey_rr);
    }
    if (ds_sha1_rr != NULL) {
        ldns_rr_free(ds_sha1_rr);
    }
    if (ds_sha256_rr != NULL) {
        ldns_rr_free(ds_sha256_rr);
    }

        hsm_destroy_context(ctx);
	hsm_close();
    DbDisconnect(dbhandle);

    return 0;
}

/*
 * To export: 
 *          policies (all, unless one is named) to xml
 */
    int
cmd_exportpolicy ()
{
    int status = 0;
    /* Database connection details */
    DB_HANDLE	dbhandle;

    xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");
    xmlNodePtr root;
    KSM_POLICY *policy;

    DB_RESULT	result;     /* Result set from query */

    /* We should either have a policy name or --all but not both */
    if (all_flag && o_policy != NULL) {
        printf("can not use --all with --policy\n");
        return(1);
    } 
    else if (!all_flag && o_policy == NULL) {
        printf("please specify either --policy <policy> or --all\n");
        return(1);
    } 

    /* try to connect to the database */
    status = db_connect(&dbhandle, NULL, 0);
    if (status != 0) {
        printf("Failed to connect to database\n");
        return(1);
    }

    /* Make some space for the policy */ 
    policy = (KSM_POLICY *)malloc(sizeof(KSM_POLICY));
	if (policy == NULL) {
        fprintf(stderr, "Malloc for policy struct failed\n");
        exit(1);
    }

    policy->signer = (KSM_SIGNER_POLICY *)malloc(sizeof(KSM_SIGNER_POLICY));
    policy->signature = (KSM_SIGNATURE_POLICY *)malloc(sizeof(KSM_SIGNATURE_POLICY));
    policy->zone = (KSM_ZONE_POLICY *)malloc(sizeof(KSM_ZONE_POLICY));
    policy->parent = (KSM_PARENT_POLICY *)malloc(sizeof(KSM_PARENT_POLICY));
    policy->keys = (KSM_COMMON_KEY_POLICY *)malloc(sizeof(KSM_COMMON_KEY_POLICY));
    policy->ksk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
    policy->zsk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
    policy->denial = (KSM_DENIAL_POLICY *)malloc(sizeof(KSM_DENIAL_POLICY));
    policy->enforcer = (KSM_ENFORCER_POLICY *)malloc(sizeof(KSM_ENFORCER_POLICY));
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
    status = KsmPolicyInit(&result, o_policy);
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

    DbDisconnect(dbhandle);

    return 0;
}

/*
 * To export: 
 *          zonelist to xml
 */
    int
cmd_exportzonelist ()
{
    int status = 0;
    /* Database connection details */
    DB_HANDLE	dbhandle;

    xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");
    xmlNodePtr root;
    KSM_ZONE *zone;
    int prev_policy_id = -1;

    DB_RESULT	result;     /* Result set from query */

    /* try to connect to the database */
    status = db_connect(&dbhandle, NULL, 0);
    if (status != 0) {
        printf("Failed to connect to database\n");
        return(1);
    }

    /* Make some space for the zone */ 
    zone = (KSM_ZONE *)malloc(sizeof(KSM_ZONE));
    if (zone == NULL) {
        fprintf(stderr, "Malloc for zone struct failed\n");
        exit(1);
    }

    /* Setup doc with a root node of <ZoneList> */
    xmlKeepBlanksDefault(0);
    xmlTreeIndentString = "    ";
    root = xmlNewDocNode(doc, NULL, (const xmlChar *)"ZoneList", NULL);
    (void) xmlDocSetRootElement(doc, root);

    /* Read zones */
    status = KsmZoneInit(&result, -1);
    if (status == 0) {
        /* get the first zone */
        status = KsmZone(result, zone);

        while (status == 0) {
            if (zone->policy_id != prev_policy_id) {
                prev_policy_id = zone->policy_id;
                status = get_policy_name_from_id(zone);
                if (status != 0) {
                    fprintf(stderr, "Couldn't get name for policy with ID: %d, exiting...\n", zone->policy_id);
                    return(1);
                }
            }
            append_zone(doc, zone);

            /* get next zone */
            status = KsmZone(result, zone);

        }
    }

    xmlSaveFormatFile("-", doc, 1);

    xmlFreeDoc(doc);
    /*KsmZoneFree(zone);*/

    DbDisconnect(dbhandle);

    return 0;
}

/*
 * To rollover a zone (or all zones on a policy if keys are shared)
 */
    int
cmd_rollzone ()
{
    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */
    DB_RESULT	result;         /* Result of parameter query */
    KSM_PARAMETER data;         /* Parameter information */
    
    int key_type = -1;
    int zone_id = -1;
    int policy_id = -1;

    int status = 0;
    int user_certain;

    char logmsg[256]; /* For the message that we log when we are done here */

    /* If we were given a keytype, turn it into a number */
    if (o_keytype != NULL) {
        StrToLower(o_keytype);
        key_type = KsmKeywordTypeNameToValue(o_keytype);
    }

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

    status = KsmZoneIdAndPolicyFromName(o_zone, &policy_id, &zone_id);
	if (status != 0) {
		/* Try again with td */
		StrAppend(&o_zone, ".");
		status = KsmZoneIdAndPolicyFromName(o_zone, &policy_id, &zone_id);
		if (status != 0) {
			printf("Error, can't find zone : %s\n", o_zone);
			db_disconnect(lock_fd);
			return(status);
		}
    }

    /* Get the shared_keys parameter */
    status = KsmParameterInit(&result, "zones_share_keys", "keys", policy_id);
    if (status != 0) {
        db_disconnect(lock_fd);
        return(status);
    }
    status = KsmParameter(result, &data);
    if (status != 0) {
        db_disconnect(lock_fd);
        return(status);
    }
    KsmParameterEnd(result);
    
    /* Warn and confirm if this will roll more than one zone */
    if (data.value == 1) {
        printf("*WARNING* This zone shares keys with others, all instances of the active key on this zone will be retired; are you sure? [y/N] ");

        user_certain = getchar();
        if (user_certain != 'y' && user_certain != 'Y') {
            printf("Okay, quitting...\n");
            db_disconnect(lock_fd);
            exit(0);
        }
    }

    status = keyRoll(zone_id, -1, key_type);
    if (status != 0) {
        db_disconnect(lock_fd);
        return(status);
    }

	/* Let them know that it seemed to work */
	snprintf(logmsg, 256, "Manual key rollover for key type %s on zone %s initiated" , (o_keytype == NULL) ? "all" : o_keytype, o_zone);
	printf("\n%s\n", logmsg);

/* send the msg to syslog */
#ifdef HAVE_OPENLOG_R
        openlog_r("ods-ksmutil", 0, DEFAULT_LOG_FACILITY, &sdata);
#else
        openlog("ods-ksmutil", 0, DEFAULT_LOG_FACILITY);
#endif
#ifdef HAVE_SYSLOG_R
        syslog_r(LOG_INFO, &sdata, "%s", logmsg);
#else
        syslog(LOG_INFO, "%s", logmsg);
#endif
#ifdef HAVE_CLOSELOG_R
        closelog_r(&sdata);
#else
        closelog();
#endif

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    /* Need to poke the enforcer to wake it up */
    if (restart_enforcerd() != 0)
    {
        fprintf(stderr, "Could not HUP ods-enforcerd\n");
    }

    DbDisconnect(dbhandle);

    return 0;
}

/*
 * To rollover all zones on a policy
 */
    int
cmd_rollpolicy ()
{
    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

    DB_RESULT   result;     /* To see if the policy shares keys or not */

    int zone_count = -1;
    
    int key_type = -1;
    int policy_id = 0;

    int status = 0;
    int user_certain;

    char logmsg[256]; /* For the message that we log when we are done here */

    /* If we were given a keytype, turn it into a number */
    if (o_keytype != NULL) {
        StrToLower(o_keytype);
        key_type = KsmKeywordTypeNameToValue(o_keytype);
    }

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

    status = KsmPolicyIdFromName(o_policy, &policy_id);
    if (status != 0) {
        printf("Error, can't find policy : %s\n", o_policy);
        db_disconnect(lock_fd);
        return(status);
    }

    /* Warn and confirm */
    printf("*WARNING* This will roll all keys on the policy; are you sure? [y/N] ");

    user_certain = getchar();
    if (user_certain != 'y' && user_certain != 'Y') {
        printf("Okay, quitting...\n");
        db_disconnect(lock_fd);
        exit(0);
    }

    /* Find out how many zones we will need to do */
    /* how many zones on this policy */ 
    status = KsmZoneCountInit(&result, policy_id); 
    if (status == 0) { 
        status = KsmZoneCount(result, &zone_count); 
    } 
    DbFreeResult(result); 

    if (status == 0) { 
        /* make sure that we have at least one zone */ 
        if (zone_count == 0) {
            printf("No zones on policy; nothing to roll\n");
            db_disconnect(lock_fd);
            return status; 
        } 
    } else { 
        printf("Couldn't count zones on policy; quitting...\n");
        db_disconnect(lock_fd);
        exit(1); 
    }

    status = keyRoll(-1, policy_id, key_type);
    if (status != 0) {
        db_disconnect(lock_fd);
        return(status);
    }
 
	/* Let them know that it seemed to work */
	snprintf(logmsg, 256, "Manual key rollover for key type %s on policy %s initiated" , (o_keytype == NULL) ? "all" : o_keytype, o_policy);
	printf("%s\n", logmsg);

/* send the msg to syslog */
#ifdef HAVE_OPENLOG_R
        openlog_r("ods-ksmutil", 0, DEFAULT_LOG_FACILITY, &sdata);
#else
        openlog("ods-ksmutil", 0, DEFAULT_LOG_FACILITY);
#endif
#ifdef HAVE_SYSLOG_R
        syslog_r(LOG_INFO, &sdata, "%s", logmsg);
#else
        syslog(LOG_INFO, "%s", logmsg);
#endif
#ifdef HAVE_CLOSELOG_R
        closelog_r(&sdata);
#else
        closelog();
#endif

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    /* Need to poke the enforcer to wake it up */
    if (restart_enforcerd() != 0)
    {
        fprintf(stderr, "Could not HUP ods-enforcerd\n");
    }

    DbDisconnect(dbhandle);

    return 0;
}

/*
 * purge dead keys from the database
 */
    int
cmd_keypurge ()
{
    int status = 0;

    int policy_id = -1;
    int zone_id = -1;

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

    /* Turn policy name into an id (if provided) */
    if (o_policy != NULL) {
        status = KsmPolicyIdFromName(o_policy, &policy_id);
        if (status != 0) {
            printf("Error: unable to find a policy named \"%s\" in database\n", o_policy);
            db_disconnect(lock_fd);
            return status;
        }
    }

    /* Turn zone name into an id (if provided) */
    if (o_zone != NULL) {
        status = KsmZoneIdFromName(o_zone, &zone_id);
        if (status != 0) {
		/* Try again with td */
			StrAppend(&o_zone, ".");
			status = KsmZoneIdFromName(o_zone, &zone_id);
			if (status != 0) {
				printf("Error: unable to find a zone named \"%s\" in database\n", o_zone);
				db_disconnect(lock_fd);
				return(status);
			}
        }
    }

    status = PurgeKeys(zone_id, policy_id);

    if (status != 0) {
        printf("Error: failed to purge dead keys\n");
        db_disconnect(lock_fd);
        return status;
    }

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    DbDisconnect(dbhandle);
    return 0;
}

/*
 * note that fact that a backup has been performed
 */
    int
cmd_backup (const char* qualifier)
{
    int status = 0;

    int repo_id = -1;

	int user_certain;           /* Continue ? */

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

    char* datetime = DtParseDateTimeString("now");

    /* Check datetime in case it came back NULL */
    if (datetime == NULL) {
        printf("Couldn't turn \"now\" into a date, quitting...\n");
        exit(1);
    }

	/* Warn about deprecation if we are doing the one-step backup */
	if ( strncmp(qualifier, "DONE", 4) == 0 ) {
		printf("*WARNING* One-step backups are deprecated in favour of a two-step process; see the documentation on key management for the explanation.\n");

		/* Allow force flag to override the question for scripts */
		if (force_flag == 0) {
			printf("Do you wish to continue? [y/N] ");

			user_certain = getchar();
			if (user_certain != 'y' && user_certain != 'Y') {
				printf("Okay, quitting...\n");
				exit(0);
			}
		}
	}

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        StrFree(datetime);
        return(1);
    }

    /* Turn repo name into an id (if provided) */
    if (o_repository != NULL) {
        status = KsmSmIdFromName(o_repository, &repo_id);
        if (status != 0) {
            printf("Error: unable to find a repository named \"%s\" in database\n", o_repository);
            db_disconnect(lock_fd);
            StrFree(datetime);
            return status;
        }
    }

    /* Do Pre first */
    if (strncmp(qualifier, "PREPARE", 7) == 0 ||
            strncmp(qualifier, "DONE", 4) == 0 ) {
        status = KsmMarkPreBackup(repo_id, datetime);
        if (status == -1) {
            printf("There were no keys to mark\n");
        }
        else if (status != 0) {
            printf("Error: failed to mark pre_backup as done\n");
            db_disconnect(lock_fd);
            StrFree(datetime);
            return status;
        } else {
            if (strncmp(qualifier, "PREPARE", 7) == 0) {
                if (o_repository != NULL) {
                    printf("Marked repository %s as pre-backed up at %s\n", o_repository, datetime);
                } else {
                    printf("Marked all repositories as pre-backed up at %s\n", datetime);
                }
            }
        }
    }

    /* Then commit */
    if (strncmp(qualifier, "COMMIT", 6) == 0 ||
            strncmp(qualifier, "DONE", 4) == 0 ) {
        status = KsmMarkBackup(repo_id, datetime);
        if (status == -1) {
            printf("There were no keys to mark\n");
        }
        else if (status != 0) {
            printf("Error: failed to mark backup as done\n");
            db_disconnect(lock_fd);
            StrFree(datetime);
            return status;
        } else {
            if (o_repository != NULL) {
                printf("Marked repository %s as backed up at %s\n", o_repository, datetime);
            } else {
                printf("Marked all repositories as backed up at %s\n", datetime);
            }
        }
    }

    /* Finally rollback */
    if (strncmp(qualifier, "ROLLBACK", 6) == 0 ) {
        status = KsmRollbackMarkPreBackup(repo_id);
        if (status == -1) {
            printf("There were no keys to rollback\n");
        }
        else if (status != 0) {
            printf("Error: failed to mark backup as done\n");
            db_disconnect(lock_fd);
            StrFree(datetime);
            return status;
        } else {
            if (o_repository != NULL) {
                printf("Rolled back pre-backup of repository %s\n", o_repository);
            } else {
                printf("Rolled back pre-backup of all repositories\n");
            }
        }
    }

    StrFree(datetime);
    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    DbDisconnect(dbhandle);
    return 0;
}

/*
 * List rollovers
 */
    int
cmd_listrolls ()
{
    int status = 0;
	int ds_count = 0;

    int qualifier_id = -1;      /* ID of qualifer (if given) */

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

    /* Turn zone name into an id (if provided) */
    if (o_zone != NULL) {
        status = KsmZoneIdFromName(o_zone, &qualifier_id);
        if (status != 0) {
			/* Try again with td */
			StrAppend(&o_zone, ".");
			status = KsmZoneIdFromName(o_zone, &qualifier_id);
			if (status != 0) {
				printf("Error: unable to find a zone named \"%s\" in database\n", o_zone);
				db_disconnect(lock_fd);
				return(status);
			}
        }
    }

    printf("Rollovers:\n");

    status = KsmListRollovers(qualifier_id, &ds_count);

    if (status != 0) {
        printf("Error: failed to list rollovers\n");
        db_disconnect(lock_fd);
        return status;
    }

    printf("\n");

	/* If verbose flag set and some keys waiting for ds-seen then print some
	 * helpful information for the user */
	if (verbose_flag && ds_count > 0) {

		status = ListDS(qualifier_id);

		if (status != 0) {
			printf("Error: failed to list DS records\n");
			db_disconnect(lock_fd);
			return status;
		}
	}

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    DbDisconnect(dbhandle);
    return 0;
}

/*
 * List backups
 */
    int
cmd_listbackups ()
{
    int status = 0;

    int qualifier_id = -1;      /* ID of qualifer (if given) */

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 0);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

    /* Turn repo name into an id (if provided) */
    if (o_repository != NULL) {
        status = KsmSmIdFromName(o_repository, &qualifier_id);
        if (status != 0) {
            printf("Error: unable to find a repository named \"%s\" in database\n", o_repository);
            db_disconnect(lock_fd);
            return status;
        }
    }

    printf("Backups:\n");
    status = KsmListBackups(qualifier_id, verbose_flag);

    if (status != 0) {
        printf("Error: failed to list backups\n");
        db_disconnect(lock_fd);
        return status;
    }
    printf("\n");

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    DbDisconnect(dbhandle);
    return 0;
}

/*
 * List repos
 */
    int
cmd_listrepo ()
{
    int status = 0;

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 0);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

    printf("Repositories:\n");

    status = KsmListRepos();

    if (status != 0) {
        printf("Error: failed to list repositories\n");
        if (lock_fd != NULL) {
            fclose(lock_fd);
        }
        return status;
    }

    printf("\n");

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    DbDisconnect(dbhandle);
    return 0;
}

/*
 * List policy
 */
    int
cmd_listpolicy ()
{
    int status = 0;

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 0);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

    printf("Policies:\n");

    status = KsmListPolicies();

    if (status != 0) {
        printf("Error: failed to list policies\n");
        db_disconnect(lock_fd);
        return status;
    }

    printf("\n");

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    DbDisconnect(dbhandle);
    return 0;
}

/*
 * List keys
 */
    int
cmd_listkeys ()
{
    int status = 0;
    int qualifier_id = -1;

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 0);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

    /* Turn zone name into an id (if provided) */
    if (o_zone != NULL) {
        status = KsmZoneIdFromName(o_zone, &qualifier_id);
        if (status != 0) {
			/* Try again with td */
			StrAppend(&o_zone, ".");
			status = KsmZoneIdFromName(o_zone, &qualifier_id);
			if (status != 0) {
				printf("Error: unable to find a zone named \"%s\" in database\n", o_zone);
				db_disconnect(lock_fd);
				return(status);
			}
        }
    }

    printf("Keys:\n");

    status = ListKeys(qualifier_id);

    if (status != 0) {
        printf("Error: failed to list keys\n");
        db_disconnect(lock_fd);
        return status;
    }

    printf("\n");

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    DbDisconnect(dbhandle);
    return 0;
}

/*
 * KSKretire
       find key (either by details provided or oldest active), 
       make sure that it is unique and in active state,
       retire key and set its dead time,
 */
    int
cmd_kskretire()
{
    int status = 0;
    int zone_id = -1;
    int policy_id = -1;
    int key_count = -1;
    int keytag_int = -1;
    int temp_key_state = -1;
    int temp_keypair_id = -1;
    char* temp_cka_id = NULL; /* This will be set if we find a single matching key */
    int user_certain;           /* Continue ? */

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

    char*   datetime = DtParseDateTimeString("now");

    /* Check datetime in case it came back NULL */
    if (datetime == NULL) {
        printf("Couldn't turn \"now\" into a date, quitting...\n");
        StrFree(datetime);
        exit(1);
    }

    /* Warn and confirm that they realise this will retire the old key */
    printf("*WARNING* This will retire the currently active KSK; are you sure? [y/N] ");

    user_certain = getchar();
    if (user_certain != 'y' && user_certain != 'Y') {
        printf("Okay, quitting...\n");
        exit(0);
    }

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        StrFree(datetime);
        return(1);
    }

    /* Turn zone name into an id (if provided) */
    if (o_zone != NULL) {
        status = KsmZoneIdFromName(o_zone, &zone_id);
        if (status != 0) {
			/* Try again with td */
			StrAppend(&o_zone, ".");
			status = KsmZoneIdFromName(o_zone, &zone_id);
			if (status != 0) {
				printf("Error: unable to find a zone named \"%s\" in database\n", o_zone);
				db_disconnect(lock_fd);
				StrFree(datetime);
				return(status);
			}
        }
    }

    /* Check the keytag is numeric */
    if (o_keytag != NULL) {
        if (StrIsDigits(o_keytag)) {
            status = StrStrtoi(o_keytag, &keytag_int);
            if (status != 0) {
                printf("Error: Unable to convert keytag \"%s\"; to an integer\n", o_keytag);
                db_disconnect(lock_fd);
                StrFree(datetime);
                return(status);
            }
        } else {
            printf("Error: keytag \"%s\"; should be numeric only\n", o_keytag);
            db_disconnect(lock_fd);
            StrFree(datetime);
            return(1);
        }
    }

    if (o_keytag == NULL && o_cka_id == NULL) {
        /* We will retire the oldest key if there are 2 or more active keys */
        if (o_zone == NULL) {
            printf("Please provide a zone or details of the key to roll\n");
            usage_keykskretire();
            db_disconnect(lock_fd);
            StrFree(datetime);
            return(-1);
        }

        status = CountKeysInState(KSM_TYPE_KSK, KSM_STATE_ACTIVE, &key_count, zone_id);
        if (status != 0) {
            printf("Error: failed to count active keys\n");
            db_disconnect(lock_fd);
            StrFree(datetime);
            return status;
        }

        /* If there are not at least 2 active keys then quit */
        if (key_count < 2) {
            printf("Error: completing this action would leave no active keys on zone, quitting...\n");
            db_disconnect(lock_fd);
            StrFree(datetime);
            return -1;
        }

        /* We will need a policy id for the next bit */
        status = KsmPolicyIdFromZoneId(zone_id, &policy_id);
        if (status != 0) {
            printf("Error: failed to find policy for zone\n");
            db_disconnect(lock_fd);
            StrFree(datetime);
            return status;
        }

        status = RetireOldKey(zone_id, policy_id, datetime);

        if (status == 0) {
            printf("Old key retired\n");
        } else {
            printf("Old key NOT retired\n");
        }
    } else {

        /* 
         * Get a count of keys that match our specifiers, will also print out
         * matching keys; note that zone_id may be overwritten
         */
        status = CountKeys(&zone_id, keytag_int, o_cka_id, &key_count, &temp_cka_id, &temp_key_state, &temp_keypair_id);
        if (status != 0) {
            printf("Error: failed to count keys\n");
            db_disconnect(lock_fd);
            StrFree(datetime);
            return status;
        }

        /* If the keycount is more than 1 then display the cka_ids of the keys */
        if (key_count > 1) {
            printf("More than one key matched your parameters, please include more information from the above keys\n");
            db_disconnect(lock_fd);
            StrFree(datetime);
            return -1;
        }

        /* If the keycount is 0 or the key is not ACTIVE then write a message and exit */
        if (key_count == 0 || temp_key_state != KSM_STATE_ACTIVE) {
            printf("No keys in the ACTIVE state matched your parameters, please check the parameters\n");
            db_disconnect(lock_fd);
            StrFree(datetime);
            return -1;
        }

        status = CountKeysInState(KSM_TYPE_KSK, KSM_STATE_ACTIVE, &key_count, zone_id);
        if (status != 0) {
            printf("Error: failed to count active keys\n");
            db_disconnect(lock_fd);
            StrFree(datetime);
            return status;
        }

        /* If there are not at least 2 active keys then quit */
        if (key_count < 2) {
            printf("Error: completing this action would leave no active keys on zone, quitting...\n");
            db_disconnect(lock_fd);
            StrFree(datetime);
            return -1;
        }

        /* We will need a policy id for the next bit */
        status = KsmPolicyIdFromZoneId(zone_id, &policy_id);
        if (status != 0) {
            printf("Error: failed to find policy for zone\n");
            db_disconnect(lock_fd);
            StrFree(datetime);
            return status;
        }

        /* Retire the key */
        status = ChangeKeyState(KSM_TYPE_KSK, temp_cka_id, zone_id, policy_id, datetime, KSM_STATE_RETIRE);

        /* Let them know that it seemed to work */
        if (status == 0) {
            printf("Key %s retired\n", temp_cka_id);
        }
    }

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    DbDisconnect(dbhandle);

    StrFree(datetime);
    
    return status;
}

/*
 * KSKrevoke
       find key (either by details provided or oldest retired), 
       make sure that it is unique and in retire state,
       revoke key.
 */
    int
cmd_kskrevoke()
{
    int status = 0;
    int zone_id = -1;
    int policy_id = -1;
    int key_count = -1;
    int keytag_int = -1;
    int temp_key_state = -1;
    int temp_keypair_id = -1;
    char* temp_cka_id = NULL; /* This will be set if we find a single matching key */
    struct tm datetime;         /* Local date and time */
    char time_buffer[KSM_TIME_LENGTH];

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

    /* Turn zone name into an id (if provided) */
    if (o_zone != NULL) {
        status = KsmZoneIdFromName(o_zone, &zone_id);
        if (status != 0) {
			/* Try again with td */
			StrAppend(&o_zone, ".");
			status = KsmZoneIdFromName(o_zone, &zone_id);
			if (status != 0) {
				printf("Error: unable to find a zone named \"%s\" in database\n", o_zone);
				db_disconnect(lock_fd);
				return(status);
			}
        }
    }

    /* Check the keytag is numeric */
    if (o_keytag != NULL) {
        if (StrIsDigits(o_keytag)) {
            status = StrStrtoi(o_keytag, &keytag_int);
            if (status != 0) {
                printf("Error: Unable to convert keytag \"%s\"; to an integer\n", o_keytag);
                db_disconnect(lock_fd);
                return(status);
            }
        } else {
            printf("Error: keytag \"%s\"; should be numeric only\n", o_keytag);
            db_disconnect(lock_fd);
            return(1);
        }
    }

    if (o_tdead)
        status = DtGeneral(o_tdead, &datetime);
    else
        status = DtNow(&datetime);
        
    if (status) {
        printf("Error parsing time, quitting...\n");
        db_disconnect(lock_fd);
        return status;
    }
    if (!o_tdead) {
        /* add 30 days to now */
        datetime.tm_mday += 30;
        (void)mktime(&datetime); /* normalize result */
    }
    snprintf(time_buffer, KSM_TIME_LENGTH, 
        "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
        datetime.tm_year + 1900, datetime.tm_mon + 1, 
        datetime.tm_mday, datetime.tm_hour, datetime.tm_min, 
        datetime.tm_sec);

    if (o_keytag == NULL && o_cka_id == NULL) {
        /* We will retire the oldest key if there are 2 or more active keys */
        if (o_zone == NULL) {
            printf("Please provide a zone or details of the key to roll\n");
            usage_keykskrevoke();
            db_disconnect(lock_fd);
            return(-1);
        }

        status = CountKeysInState(KSM_TYPE_KSK, KSM_STATE_RETIRE, &key_count, zone_id);
        if (status != 0) {
            printf("Error: failed to count retired keys\n");
            db_disconnect(lock_fd);
            return status;
        }

        /* If there is not at least 1 retired key then quit */
        if (key_count < 1) {
            printf("Error: Could not find a key to retire, quitting...\n");
            db_disconnect(lock_fd);
            return -1;
        }

        /* We will need a policy id for the next bit */
        status = KsmPolicyIdFromZoneId(zone_id, &policy_id);
        if (status != 0) {
            printf("Error: failed to find policy for zone\n");
            db_disconnect(lock_fd);
            return status;
        }
    
        status = RevokeOldKey(zone_id, policy_id, time_buffer);

        if (status == 0) {
            printf("Old key revoked\n");
        } else {
            printf("Old key NOT revoked\n");
        }
    } else {
        char *sql2 = NULL;    /* SQL query */

        /* 
         * Get a count of keys that match our specifiers, will also print out
         * matching keys; note that zone_id may be overwritten
         */
        status = CountKeys(&zone_id, keytag_int, o_cka_id, &key_count, &temp_cka_id, &temp_key_state, &temp_keypair_id);
        if (status != 0) {
            printf("Error: failed to count keys\n");
            db_disconnect(lock_fd);
            return status;
        }

        /* If the keycount is more than 1 then display the cka_ids of the keys */
        if (key_count > 1) {
            printf("More than one key matched your parameters, please include more information from the above keys\n");
            db_disconnect(lock_fd);
            return -1;
        }

        /* If the keycount is 0 or the key is not RETIRE then write a message and exit */
        if (key_count == 0 || temp_key_state != KSM_STATE_RETIRE) {
            printf("No keys in the RETIRE state matched your parameters, please check the parameters\n");
            db_disconnect(lock_fd);
            return -1;
        }

        status = CountKeysInState(KSM_TYPE_KSK, KSM_STATE_RETIRE, &key_count, zone_id);
        if (status != 0) {
            printf("Error: failed to count revoked keys\n");
            db_disconnect(lock_fd);
            return status;
        }

        /* If there are not at least 2 retired keys then quit */
        if (key_count < 1) {
            printf("Error: Could not find a key to revoke, quitting...\n");
            db_disconnect(lock_fd);
            return -1;
        }

        /* We will need a policy id for the next bit */
        status = KsmPolicyIdFromZoneId(zone_id, &policy_id);
        if (status != 0) {
            printf("Error: failed to find policy for zone\n");
            db_disconnect(lock_fd);
            return status;
        }

        /* 0) Start a transaction */
        status = DbBeginTransaction();
        if (status != 0) {
            /* Something went wrong */
            MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
            return status;
        }

        /* Retire the key */
        sql2 = DusInit("dnsseckeys");
        DusSetInt(&sql2, "revoked", 1, 0);
        DusSetString(&sql2, KsmKeywordStateValueToName(KSM_STATE_DEAD), time_buffer, 1);
        DusConditionInt(&sql2, "keypair_id", DQS_COMPARE_EQ, temp_keypair_id, 0);
        status = DbExecuteSqlNoResult(DbHandle(), sql2);
        DusFree(sql2);

        if (!status) {
            sql2 = DusInit("keypairs");
            DusSetInt(&sql2, "fixedDate", 1, 0);
            DusConditionInt(&sql2, "id", DQS_COMPARE_EQ, temp_keypair_id, 0);
            status = DbExecuteSqlNoResult(DbHandle(), sql2);
            DusFree(sql2);
        }

        /* Report any errors */
        if (status != 0) {
            status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
            DbRollback();
            return status;
        }

        /* 2) Commit */
        /* Everything worked by the looks of it */
        DbCommit();

        /* Let them know that it seemed to work */
        if (status == 0) {
            printf("Key %s revoked\n", temp_cka_id);
        }
    }

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    DbDisconnect(dbhandle);

    if (restart_enforcerd() != 0) {
        fprintf(stderr, "Could not HUP ods-enforcerd\n");
    } else {
        fprintf(stdout, "Performed a HUP ods-enforcerd\n");
    }
    return status;
}

/*
 * DS Seen
       mark key as having had its DS published
       i.e. change its state to ACTIVE and set the time
            also set the time at which it will go to RETIRED
 */
    int
cmd_dsseen()
{
    int status = 0;
    int zone_id = -1;
    int policy_id = -1;
    int key_count = -1;
    int retired_count = -1;
    int keytag_int = -1;
    int temp_key_state = -1;
    int temp_keypair_id = -1;
    char* temp_cka_id = NULL; /* This will be set if we find a single matching key */
    int user_certain;           /* Continue ? */

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

    char logmsg[256]; /* For the message that we log when a key moves */

    char*   datetime = DtParseDateTimeString("now");

    /* Check datetime in case it came back NULL */
    if (datetime == NULL) {
        printf("Couldn't turn \"now\" into a date, quitting...\n");
        StrFree(datetime);
        exit(1);
    }

    /* Check that we have either a keytag or a cka_id */
    if (o_keytag == NULL && o_cka_id == NULL) {
        printf("Please provide a keytag or a CKA_ID for the key (CKA_ID will be used if both are provided\n");
        usage_keydsseen();
        StrFree(datetime);
        return(-1);
    }

    /* Warn and confirm that they realise this will retire the old key */
    if (0) {
        printf("*WARNING* This will retire the currently active KSK; are you sure? [y/N] ");

        user_certain = getchar();
        if (user_certain != 'y' && user_certain != 'Y') {
            printf("Okay, quitting...\n");
            exit(0);
        }
    }
    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        StrFree(datetime);
        return(1);
    }

    /* Turn zone name into an id (if provided) */
    /* TODO sort out all flag */
    /*if (o_zone == NULL && !all_flag) {
        printf("Please specify a zone or use the --all flag to indicate all zones using this key\n");*/
    if (o_zone == NULL) {
        printf("Please specify a zone using the --zone flag\n");
        usage_keydsseen();
        StrFree(datetime);
        db_disconnect(lock_fd);
        return(-1);
    } 
	else if (o_zone != NULL) {
		status = KsmZoneIdFromName(o_zone, &zone_id);
		if (status != 0) {
			/* Try again with td */
			StrAppend(&o_zone, ".");
			status = KsmZoneIdFromName(o_zone, &zone_id);
			if (status != 0) {
				printf("Error: unable to find a zone named \"%s\" in database\n", o_zone);
				db_disconnect(lock_fd);
				StrFree(datetime);
				return(status);
			}
		}
	}
    else if (all_flag) {
        printf("*WARNING* This will act on every zone where this key is in use; are you sure? [y/N] ");

        user_certain = getchar();
        if (user_certain != 'y' && user_certain != 'Y') {
            printf("Okay, quitting...\n");
            exit(0);
        }
        
        zone_id = -1;
    }

    /* Check the keytag is numeric */
    if (o_keytag != NULL) {
        if (StrIsDigits(o_keytag)) {
            status = StrStrtoi(o_keytag, &keytag_int);
            if (status != 0) {
                printf("Error: Unable to convert keytag \"%s\"; to an integer\n", o_keytag);
                db_disconnect(lock_fd);
                StrFree(datetime);
                return(status);
            }
        } else {
            printf("Error: keytag \"%s\"; should be numeric only\n", o_keytag);
            db_disconnect(lock_fd);
            StrFree(datetime);
            return(1);
        }
    }

    /* 
     * Get a count of keys that match our specifiers, will also print out
     * matching keys; note that zone_id may be overwritten
     */
    status = CountKeys(&zone_id, keytag_int, o_cka_id, &key_count, &temp_cka_id, &temp_key_state, &temp_keypair_id);
    if (status != 0) {
        printf("Error: failed to count keys\n");
        db_disconnect(lock_fd);
        StrFree(datetime);
        return status;
    }

    /* If the keycount is more than 1 then display the cka_ids of the keys */
    if (key_count > 1) {
        printf("More than one key matched your parameters, please include more information from the above keys\n");
        db_disconnect(lock_fd);
        StrFree(datetime);
        return -1;
    }

    /* If the key is already active then write a message and exit */
    if (temp_key_state == KSM_STATE_ACTIVE) {
        printf("Key is already active\n");
        db_disconnect(lock_fd);
        StrFree(datetime);
        return -1;
    }

    /* If the keycount is 0 then write a message and exit */
    if (key_count == 0) {
        printf("No keys in the READY state matched your parameters, please check the parameters\n");
        db_disconnect(lock_fd);
        StrFree(datetime);
        return -1;
    }

    /* We will need a policy id for the next bit */
    status = KsmPolicyIdFromZoneId(zone_id, &policy_id);
    if (status != 0) {
        printf("Error: failed to find policy for zone\n");
        db_disconnect(lock_fd);
        StrFree(datetime);
        return status;
    }

    /* Do stuff */
    status = MarkDSSeen(temp_keypair_id, zone_id, policy_id, datetime, temp_key_state);

    /* Let them know that it seemed to work */
    if (status == 0) {
        snprintf(logmsg, 256, "Key %s made %s", temp_cka_id, (temp_key_state == KSM_STATE_READY) ? "active" : "into standby");
        printf("%s\n", logmsg);
        
        /* send the msg to syslog */
#ifdef HAVE_OPENLOG_R
        openlog_r("ods-ksmutil", 0, DEFAULT_LOG_FACILITY, &sdata);
#else
        openlog("ods-ksmutil", 0, DEFAULT_LOG_FACILITY);
#endif
#ifdef HAVE_SYSLOG_R
        syslog_r(LOG_INFO, &sdata, "%s", logmsg);
#else
        syslog(LOG_INFO, "%s", logmsg);
#endif
#ifdef HAVE_CLOSELOG_R
        closelog_r(&sdata);
#else
        closelog();
#endif
        
    }

    /* Retire old key, unless asked not to */
    if (temp_key_state == KSM_STATE_READY) {
        if (retire_flag == 1) {

            /* We will retire the oldest key if there are 2 or more active keys */
            status = CountKeysInState(KSM_TYPE_KSK, KSM_STATE_ACTIVE, &key_count, zone_id);
            if (status != 0) {
                printf("Error: failed to count active keys\n");
                db_disconnect(lock_fd);
                StrFree(datetime);
                return status;
            }

            /* If there are not at least 2 active keys then quit */
            if (key_count < 2) {
                /* Count retired keys to work out if this is a new zone */
                status = CountKeysInState(KSM_TYPE_KSK, KSM_STATE_RETIRE, &retired_count, zone_id);
                if (status != 0) {
                    printf("Error: failed to count retired keys\n");
                    db_disconnect(lock_fd);
                    StrFree(datetime);
                    return status;
                }

				db_disconnect(lock_fd);
				StrFree(datetime);
				/* Cleanup and print an error message... */
                if (retired_count != 0) {
					printf("Error: retiring a key would leave no active keys on zone, skipping...\n");
					return -1;
				} else {
					/* ...Unless this looks like a new zone, in which case poke
					   the enforcerd*/
					if (notify_flag == 1) {
						if (restart_enforcerd() != 0) {
						fprintf(stderr, "Could not HUP ods-enforcerd\n");
						} else {
							fprintf(stdout, "Performed a HUP ods-enforcerd\n"); /** too verbose? */
					}
					} else {
						fprintf(stdout, "No HUP ods-enforcerd was performed as the '--no-notify' flag was specified.\n");
						fprintf(stdout, "Warning: The enforcer must be manually notified or the changes will not take full effect until the next scheduled enforcer run.\n");						
					}
					return 0;
				}
            }

            status = RetireOldKey(zone_id, policy_id, datetime);

            /* Let them know that it seemed to work */
            if (status == 0) {
                printf("Old key retired\n");
            } else {
                printf("Old key NOT retired\n");
            }
        } else {
            printf("Old key NOT retired\n");
        }
    }

	if (notify_flag == 1) {
		if (restart_enforcerd() != 0) {
        fprintf(stderr, "Could not HUP ods-enforcerd\n");
		} else {
			fprintf(stdout, "Performed a HUP ods-enforcerd\n"); /** too verbose? */
    }
	} else {
		fprintf(stdout, "No HUP ods-enforcerd was performed as the '--no-notify' flag was specified.\n");
		fprintf(stdout, "Warning: The enforcer must be manually notified or the changes will not take full effect until the next scheduled enforcer run.\n");						
	}

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    DbDisconnect(dbhandle);

    StrFree(datetime);
    
    return status;
}

/*
 * import a key into the ksm and set its values as specified
 */
    int
cmd_import ()
{
    int status = 0;

    /* some strings to hold upper case versions of arguments */
    char* case_keytype = NULL;    /* KSK or ZSK */
    char* case_algorithm = NULL;  /* RSASHA1 or RSASHA1-NSEC3-SHA1 (5 or 7) */
    char* case_state = NULL;      /* GENERATE, PUBLISH, READY, ACTIVE or RETIRE */

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

	int fix_time = 0;	/* Will we be setting the retire time? */

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

    DB_RESULT	result;         /* Result of parameter query */
    KSM_PARAMETER data;         /* Parameter information */

    int user_certain;           /* Continue ? */

	hsm_key_t *key = NULL;
        hsm_ctx_t* ctx;

    /* Chech that we got all arguments. */

    if (o_cka_id == NULL) {
        printf("Error: please specify a CKA_ID with the --cka_id <CKA_ID>\n");
        return(1);
    }
    if (o_repository == NULL) {
        printf("Error: please specify a repository with the --repository <repository>\n");
        return(1);
    }
    if (o_zone == NULL) {
        printf("Error: please specify a zone with the --zone <zone>\n");
        return(1);
    }
    if (o_size == NULL) {
        printf("Error: please specify the number of bits with the --bits <size>\n");
        return(1);
    }
    if (o_algo == NULL) {
        printf("Error: please specify the algorithm with the --algorithm <algorithm>\n");
        return(1);
    }
    if (o_keystate == NULL) {
        printf("Error: please specify the state with the --keystate <state>\n");
        return(1);
    }
    if (o_keytype == NULL) {
        printf("Error: please specify a keytype, KSK or ZSK, with the --keytype <type>\n");
        return(1);
    }
    if (o_time == NULL) {
        printf("Error: please specify the time of when the key entered the given state with the --time <time>\n");
        return(1);
    }

    /* Check the key does not exist in the specified HSM */
	status = hsm_open(config, hsm_prompt_pin);
	if (status) {
		hsm_print_error(NULL);
		return(1);
	}
        ctx = hsm_create_context();
	key = hsm_find_key_by_id(ctx, o_cka_id);
        hsm_destroy_context(ctx);
	hsm_close();
	if (!key) {
		if(check_repository_flag){
			fprintf(stderr, "Error: No key with the CKA_ID %-33s exists in the repository %s. When the option [--check-repository] is used the key MUST exist in the repository for the key to be imported. \n", o_cka_id,o_repository);
			return(1);
		}else{
			fprintf(stdout, "Warning: No key with the CKA_ID %-33s exists in the repository %s. The key will be imported into the database anyway. \n", o_cka_id,o_repository);
		}
	}else{
		hsm_key_free(key);
	}

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

    /* check that the repository exists */
    status = KsmSmIdFromName(o_repository, &repo_id);
    if (status != 0) {
        printf("Error: unable to find a repository named \"%s\" in database\n", o_repository);
        db_disconnect(lock_fd);
        return status;
    }

    /* check that the zone name is valid and use it to get some ids */
	status = KsmZoneIdAndPolicyFromName(o_zone, &policy_id, &zone_id);
	if (status != 0) {
		/* Try again with td */
		StrAppend(&o_zone, ".");
		status = KsmZoneIdAndPolicyFromName(o_zone, &policy_id, &zone_id);
		if (status != 0) {
			printf("Error: unable to find a zone named \"%s\" in database\n", o_zone);
			db_disconnect(lock_fd);
			return(status);
		}
	}

    /* Check that the cka_id does not exist (in the specified HSM) */
    status = (KsmCheckHSMkeyID(repo_id, o_cka_id, &cka_id_exists));
    if (status != 0) {
        db_disconnect(lock_fd);
        return(status);
    }
    if (cka_id_exists == 1) {
        printf("Error: key with CKA_ID \"%s\" already exists in database\n", o_cka_id);
        db_disconnect(lock_fd);
        return(1);
    }

    /* Check the Keytype */
    case_keytype = StrStrdup(o_keytype);
    (void) StrToUpper(case_keytype);
    if (strncmp(case_keytype, "KSK", 3) == 0 || strncmp(o_keytype, "257", 3) == 0) {
        keytype_id = 257;
    }
    else if (strncmp(case_keytype, "ZSK", 3) == 0 || strncmp(o_keytype, "256", 3) == 0) {
        keytype_id = 256;
    }
    else {
        printf("Error: Unrecognised keytype %s; should be one of KSK or ZSK\n", o_keytype);

        db_disconnect(lock_fd);
        StrFree(case_keytype);
        return(1);
    }
    StrFree(case_keytype);
        
    /* Check the size is numeric */
    if (StrIsDigits(o_size)) {
        status = StrStrtoi(o_size, &size_int);
        if (status != 0) {
            printf("Error: Unable to convert bits \"%s\"; to an integer\n", o_size);
            db_disconnect(lock_fd);
            return(status);
        }
    } else {
        printf("Error: Bits \"%s\"; should be numeric only\n", o_size);
        db_disconnect(lock_fd);
        return(1);
    }

    /* Check the algorithm */
    if (StrIsDigits(o_algo)) {
        /* Accept it as-is; The HSM will tell us if the number is not valid */
        status = StrStrtoi(o_algo, &algo_id);
    } else {
        /* Convert name to an id, we get 0 if it is unrecognised */
        case_algorithm = StrStrdup(o_algo);
        (void) StrToLower(case_algorithm);

        algo_id = KsmKeywordAlgorithmNameToValue(case_algorithm);
        StrFree(case_algorithm);
    }

    if (status != 0 || algo_id == 0 || hsm_supported_algorithm(algo_id) != 0) {
        printf("Error: Key algorithm %s not supported; try one of RSASHA1, RSASHA1-NSEC3-SHA1 or RSASHA256\n", o_algo);
        db_disconnect(lock_fd);
        return(status);
    }

    /* Check the state */
    case_state = StrStrdup(o_keystate);
    (void) StrToUpper(case_state);
    if (strncmp(case_state, "GENERATE", 8) == 0 || strncmp(o_keystate, "1", 1) == 0) {
        state_id = 1;
    }
    else if (strncmp(case_state, "PUBLISH", 7) == 0 || strncmp(o_keystate, "2", 1) == 0) {
        state_id = 2;
    }
    else if (strncmp(case_state, "READY", 5) == 0 || strncmp(o_keystate, "3", 1) == 0) {
        state_id = 3;
    }
    else if (strncmp(case_state, "ACTIVE", 6) == 0 || strncmp(o_keystate, "4", 1) == 0) {
        state_id = 4;
    }
    else if (strncmp(case_state, "RETIRE", 6) == 0 || strncmp(o_keystate, "5", 1) == 0) {
        state_id = 5;
    }
    else {
        printf("Error: Unrecognised state %s; should be one of GENERATE, PUBLISH, READY, ACTIVE or RETIRE\n", o_keystate);

        db_disconnect(lock_fd);
        StrFree(case_state);
        return(1);
    }
    StrFree(case_state);

    /* Check, and convert, the time(s) */
    status = DtGeneral(o_time, &datetime);
    if (status != 0) {
        printf("Error: unable to convert \"%s\" into a date\n", o_time);
        date_help();

        db_disconnect(lock_fd);
        return(status);
    }
    else {
        snprintf(form_time, KSM_TIME_LENGTH, "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
            datetime.tm_year + 1900, datetime.tm_mon + 1, datetime.tm_mday,
            datetime.tm_hour, datetime.tm_min, datetime.tm_sec);
            printf("Converted time is %s\n", form_time);
    }

    if (o_retire != NULL) {
        /* can only specify a retire time if the key is being inserted in the active state */
        if (state_id != KSM_STATE_ACTIVE) {
            printf("Error: unable to specify retire time for a key in state \"%s\"\n", o_keystate);
            db_disconnect(lock_fd);
            return(status);
        }

        status = DtGeneral(o_retire, &datetime);
        if (status != 0) {
            printf("Error: unable to convert retire time \"%s\" into a date\n", o_retire);
            date_help();

            db_disconnect(lock_fd);
            return(status);
        }
        else {
            snprintf(form_opt_time, KSM_TIME_LENGTH, "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
                    datetime.tm_year + 1900, datetime.tm_mon + 1, datetime.tm_mday,
                    datetime.tm_hour, datetime.tm_min, datetime.tm_sec);
			fix_time = 1;
        }
    } else {
        form_opt_time[0] = '\0';
    }

    /* Find out if this zone has any others on a "shared keys" policy and warn */
    status = KsmParameterInit(&result, "zones_share_keys", "keys", policy_id);
    if (status != 0) {
        db_disconnect(lock_fd);
        return(status);
    }
    status = KsmParameter(result, &data);
    if (status != 0) {
        db_disconnect(lock_fd);
        return(status);
    }
    KsmParameterEnd(result);
    
    /* Warn and confirm if this will roll more than one zone */
    if (data.value == 1) {
        printf("*WARNING* This zone shares keys with others, the key will be added to all; are you sure? [y/N] ");

        user_certain = getchar();
        if (user_certain != 'y' && user_certain != 'Y') {
            printf("Okay, quitting...\n");
            db_disconnect(lock_fd);
            exit(0);
        }
    }

    /* create basic keypair */
    status = KsmImportKeyPair(policy_id, o_cka_id, repo_id, size_int, algo_id, state_id, form_time, fix_time, &keypair_id);
    if (status != 0) {
        printf("Error: couldn't import key\n");
        db_disconnect(lock_fd);
        return(status);
    }

    /* allocate key to zone(s) */
    /* TODO might not need this any more */
/*    if (data.value == 1) {
        status = KsmDnssecKeyCreateOnPolicy(policy_id, (int) keypair_id, keytype_id);
    } else {*/
    status = KsmDnssecKeyCreate(zone_id, (int) keypair_id, keytype_id, state_id, rfc5011_flag, form_time, form_opt_time, &ignore);

    if (status != 0) {
        printf("Error: couldn't allocate key to zone(s)\n");
        db_disconnect(lock_fd);
        return(status);
    }

    printf("Key imported into zone(s)\n");

    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    DbDisconnect(dbhandle);
    return 0;
}

/*
 * make a backup of a sqlite database
 */
    int
cmd_dbbackup ()
{
    /* Database details */
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

    /* what we will read from the file */
    char *dbschema = NULL;
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *password = NULL;

    int status;

    char* backup_filename = NULL;
    char* lock_filename;

    char *path = getenv("PWD");

    if (DbFlavour() != SQLITE_DB) {
        printf("Sorry, currently this utility can only backup a sqlite database file\n");
        return -1;
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

    /* set up DB lock */
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
        StrFree(host);
        StrFree(port);
        StrFree(dbschema);
        StrFree(user);
        StrFree(password);
		StrFree(lock_filename);
        return(1);
    }
    StrFree(lock_filename);

    /* Work out what file to output */
    if (o_output == NULL) {
        StrAppend(&backup_filename, dbschema);
        StrAppend(&backup_filename, ".backup");
    } else if (*o_output != '/') {
        StrAppend(&backup_filename, path);
        StrAppend(&backup_filename, "/");
        StrAppend(&backup_filename, o_output);
    } else {
        StrAppend(&backup_filename, o_output);
    }

    status = backup_file(dbschema, backup_filename);

    StrFree(backup_filename);

    /* Cleanup */
    StrFree(host);
    StrFree(port);
    StrFree(dbschema);
    StrFree(user);
    StrFree(password);

    /* Release sqlite lock */
    db_disconnect(lock_fd);

    return status;
}

/*
 * Delete any policies with no zones 
 */
    int 
cmd_purgepolicy ()
{
    int status = 0;

    char* kasp_filename = NULL;
    char* zonelist_filename = NULL;
    char* backup_filename = NULL;

    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;
    KSM_POLICY *policy;
    DB_RESULT	result;     /* Result set from policy query */
    DB_RESULT	result2;    /* Result set from zone count query */
    char        sql[KSM_SQL_SIZE];
    int         size = -1;
    char* sql2;

    FILE *test;
    int zone_count = -1;

    xmlDocPtr doc = NULL;
    
    int user_certain;
    printf("*WARNING* This feature is experimental and has not been fully tested; are you sure? [y/N] ");

    user_certain = getchar();
    if (user_certain != 'y' && user_certain != 'Y') {
        printf("Okay, quitting...\n");
        exit(0);
    }

    /* Read the conf.xml file to learn the location of the kasp.xml file. */
    status = read_filenames(&zonelist_filename, &kasp_filename);
    if (status != 0) {
        printf("Failed to read conf.xml\n");
        db_disconnect(lock_fd);
        return(1);
    }

    /* Backup the current kasp.xml */
    StrAppend(&backup_filename, kasp_filename);
    StrAppend(&backup_filename, ".backup");
    status = backup_file(kasp_filename, backup_filename);
    StrFree(backup_filename);
    if (status != 0) {
        StrFree(kasp_filename);
        StrFree(zonelist_filename);
        db_disconnect(lock_fd);
        return(status);
    }

    /* Check that we will be able to make the changes to kasp.xml */
    if ((test = fopen(kasp_filename, "ab"))==NULL) {
        printf("Cannot open kasp.xml for writing: %s\n", strerror(errno));
        StrFree(kasp_filename);
        StrFree(zonelist_filename);
        return(-1);
    } else {
        fclose(test);
    }

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        StrFree(kasp_filename);
        StrFree(zonelist_filename);
        return(1);
    }

    /* Start a transaction */
    status = DbBeginTransaction();
    if (status != 0) {
        /* Something went wrong */

        MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        db_disconnect(lock_fd);
        StrFree(kasp_filename);
        StrFree(zonelist_filename);
        return status;
    }

    /* Loop through each policy */
    policy = KsmPolicyAlloc();
    if (policy == NULL) {
        printf("Malloc for policy struct failed\n");
        exit(1);
    }

    /* Read all policies */
    status = KsmPolicyInit(&result, NULL);
    if (status == 0) {
        /* get the first policy */
        status = KsmPolicy(result, policy);
        while (status == 0) {
            /* Count zones on this policy */
            status = KsmZoneCountInit(&result2, policy->id); 
            if (status == 0) { 
                status = KsmZoneCount(result2, &zone_count); 
            } 
            DbFreeResult(result2); 

            if (status == 0) { 
                /* Only carry on if we have no zones */
                if (zone_count == 0) {
                    printf("No zones on policy %s; purging...\n", policy->name);
                    /* set keystate to 6 across the board */
                    size = snprintf(sql, KSM_SQL_SIZE, "update dnsseckeys set state = %d where keypair_id in (select id from keypairs where policy_id = %d)", KSM_STATE_DEAD, policy->id);

                    /* Quick check that we didn't run out of space */
                    if (size < 0 || size >= KSM_SQL_SIZE) {
                        printf("Couldn't construct SQL to kill orphaned keys\n");
						db_disconnect(lock_fd);
						KsmPolicyFree(policy);
						StrFree(kasp_filename);
						StrFree(zonelist_filename);
                        return -1;
                    }

                    status = DbExecuteSqlNoResult(DbHandle(), sql);

                    /* Report any errors */
                    if (status != 0) {
                        printf("SQL failed: %s\n", DbErrmsg(DbHandle()));
						db_disconnect(lock_fd);
						KsmPolicyFree(policy);
						StrFree(kasp_filename);
						StrFree(zonelist_filename);
                        return status;
                    }

                    /* call purge keys on that policy (all zones) */
                    status = PurgeKeys(-1, policy->id);
                    if (status != 0) {
                        printf("Key purge failed for policy %s\n", policy->name);
						db_disconnect(lock_fd);
						KsmPolicyFree(policy);
						StrFree(kasp_filename);
						StrFree(zonelist_filename);
                        return status;
                    }

                    /* Delete the policy from DB */
                    sql2 = DdsInit("parameters_policies");
                    DdsConditionInt(&sql2, "policy_id", DQS_COMPARE_EQ,  policy->id, 0); 
                    DdsEnd(&sql2); 
                    status = DbExecuteSqlNoResult(DbHandle(), sql2); 
                    DdsFree(sql2); 

                    if (status != 0) 
                    { 
                        printf("SQL failed: %s\n", DbErrmsg(DbHandle()));
						db_disconnect(lock_fd);
						KsmPolicyFree(policy);
						StrFree(kasp_filename);
						StrFree(zonelist_filename);
                        return status; 
                    }

                    sql2 = DdsInit("policies"); 
                    DdsConditionInt(&sql2, "id", DQS_COMPARE_EQ,  policy->id, 0); 
                    DdsEnd(&sql2); 
                    status = DbExecuteSqlNoResult(DbHandle(), sql2); 
                    DdsFree(sql2); 

                    if (status != 0) 
                    { 
                        printf("SQL failed: %s\n", DbErrmsg(DbHandle()));
						db_disconnect(lock_fd);
						KsmPolicyFree(policy);
						StrFree(kasp_filename);
						StrFree(zonelist_filename);
                        return status; 
                    }

                    /* Delete the policy from the XML */
                    /* Read the file and delete our policy node(s) in memory */
                    doc = del_policy_node(kasp_filename, policy->name);
                    if (doc == NULL) {
						db_disconnect(lock_fd);
						KsmPolicyFree(policy);
						StrFree(kasp_filename);
						StrFree(zonelist_filename);
                        return(1);
                    }

                    /* Save our new file over the old, TODO should we validate it first? */
                    status = xmlSaveFormatFile(kasp_filename, doc, 1);
                    xmlFreeDoc(doc);
                    if (status == -1) {
                        printf("Could not save %s\n", kasp_filename);
						StrFree(kasp_filename);
						StrFree(zonelist_filename);
						db_disconnect(lock_fd);
						KsmPolicyFree(policy);
                        return(1);
                    }

                } 
            } else { 
                printf("Couldn't count zones on policy; quitting...\n");
                db_disconnect(lock_fd);
                exit(1); 
            }

            /* get next policy */
            status = KsmPolicy(result, policy);
        }
        /* Reset EOF */
        if (status == -1) {
            status = 0;
        }
        DbFreeResult(result);
    }

    /* Commit or Rollback */
    if (status == 0) {
        /* Everything worked by the looks of it */
        DbCommit();
    } else {
        /* Whatever happened, it was not good */
        DbRollback();
    }

    StrFree(kasp_filename);
	StrFree(zonelist_filename);
    db_disconnect(lock_fd);
    KsmPolicyFree(policy);
    return status;
}

/*
 * Send command to ods-control
 */
    int 
cmd_control(char *command)
{
    int status = 0;
    char* ods_control_cmd = NULL;
    char* ptr = command;

    /* We need the command in lower case */
    if (ptr) {
        while (*ptr) {
            *ptr = tolower((int) *ptr);
            ++ptr;
        }
    }

    /* Call "ods-control enforcer COMMAND" */
    StrAppend(&ods_control_cmd, ODS_EN_CONTROL);
    StrAppend(&ods_control_cmd, command);

    status = system(ods_control_cmd);
    if (status != 0)
    {
        fprintf(stderr, "Couldn't run %s\n", ods_control_cmd);
    }

    StrFree(ods_control_cmd);

    return(status);
}

/* 
 * Fairly basic main, just pass most things through to their handlers
 */
    int
main (int argc, char *argv[])
{
    int result;
    int ch;
    char* case_command = NULL;
    char* case_verb = NULL;

    int option_index = 0;
    static struct option long_options[] =
    {
        {"all",     no_argument,       0, 'a'},
        {"auto-accept", no_argument,   0, 'A'},
        {"bits",    required_argument, 0, 'b'},
        {"rfc5011", no_argument,       0, '5'},
        {"config",  required_argument, 0, 'c'},
        {"check-repository", no_argument,     0, 'C'},
        {"ds",      no_argument,       0, 'd'},
        {"keystate", required_argument, 0, 'e'},
        {"no-retire", no_argument,       0, 'f'},
        {"force", 	no_argument,       0, 'F'},
        {"algorithm", required_argument, 0, 'g'},
        {"help",    no_argument,       0, 'h'},
        {"input",   required_argument, 0, 'i'},
        {"in-type", required_argument, 0, 'j'},
        {"cka_id",  required_argument, 0, 'k'},
        {"no-notify", no_argument,       0, 'l'},
        {"no-xml",  no_argument,        0, 'm'},
        {"no-hsm",  no_argument,        0, 'M'},
        {"interval",  required_argument, 0, 'n'},
        {"output",  required_argument, 0, 'o'},
        {"policy",  required_argument, 0, 'p'},
        {"out-type", 	required_argument, 0, 'q'},
        {"repository",  required_argument, 0, 'r'},
        {"signerconf",  required_argument, 0, 's'},
        {"keytype", required_argument, 0, 't'},
        {"time",    required_argument, 0, 'w'},
        {"verbose", no_argument,       0, 'v'},
        {"version", no_argument,       0, 'V'},
        {"keytag",  required_argument, 0, 'x'},
        {"retire",  required_argument, 0, 'y'},
        {"tdead",  required_argument, 0, 'Y'},
        {"zone",    required_argument, 0, 'z'},
		{"zonetotal", required_argument, 0, 'Z'},
        {0,0,0,0}
    };

    progname = argv[0];

    while ((ch = getopt_long(argc, argv, "aAb:Cc:de:fFg:hi:j:k:mMln:o:p:q:r:s:t:vVw:x:y:Y:z:Z:5", long_options, &option_index)) != -1) {
        switch (ch) {
            case 'a':
                all_flag = 1;
                break;
            case 'A':
                auto_accept_flag = 1;
                break;
            case 'b':
                o_size = StrStrdup(optarg);
                break;
            case '5':
                rfc5011_flag = 1;
                break;
            case 'c':
                config = StrStrdup(optarg);
                break;
            case 'C':
            	check_repository_flag = 1;
            	break;
            case 'd':
                ds_flag = 1;
                break;
            case 'e':
                o_keystate = StrStrdup(optarg);
                break;
            case 'f':
                retire_flag = 0;
                break;
            case 'F':
                force_flag = 1;
                break;
            case 'g':
                o_algo = StrStrdup(optarg);
                break;
            case 'h':
                usage();
                states_help();
                types_help();
                date_help();
                exit(0);
                break;
            case 'i':
                o_input = StrStrdup(optarg);
                break;
            case 'j':
                o_in_type = StrStrdup(optarg);
                break;
            case 'k':
                o_cka_id = StrStrdup(optarg);
                break;
            case 'l':
                notify_flag = 0;
                break;
            case 'm':
                xml_flag = 0;
                break;
            case 'M':
                hsm_flag = 0;
                break;
            case 'n':
                o_interval = StrStrdup(optarg);
                break;
            case 'o':
                o_output = StrStrdup(optarg);
                break;
            case 'p':
                o_policy = StrStrdup(optarg);
                break;
            case 'q':
                o_out_type = StrStrdup(optarg);
                break;
            case 'r':
                o_repository = StrStrdup(optarg);
                break;
            case 's':
                o_signerconf = StrStrdup(optarg);
                break;
            case 't':
                o_keytype = StrStrdup(optarg);
                break;
            case 'V':
                printf("%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
                exit(0);
                break;
            case 'v':
                verbose_flag = 1;
                break;
            case 'w':
                o_time = StrStrdup(optarg);
                break;
            case 'x':
                o_keytag = StrStrdup(optarg);
                break;
            case 'y':
                o_retire = StrStrdup(optarg);
                break;
            case 'Y':
                o_tdead = StrStrdup(optarg);
                break;
            case 'z':
				/* Remove trailing dot here */
                o_zone = StrStrdup(optarg);
				if (strlen(o_zone) > 1 && o_zone[strlen(o_zone)-1] == '.') {
					o_zone[strlen(o_zone)-1] = '\0';
					td_flag = 1;
				}

                break;
			case 'Z':
				o_zonetotal = StrStrdup(optarg);
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

    /* command should be one of SETUP UPDATE ZONE REPOSITORY POLICY KEY BACKUP or ROLLOVER */
    case_command = StrStrdup(argv[0]);
    (void) StrToUpper(case_command);
    if (argc > 1) {
        /* verb should be stuff like ADD, LIST, DELETE, etc */
        case_verb = StrStrdup(argv[1]);
        (void) StrToUpper(case_verb);
    } else {
        case_verb = StrStrdup("NULL");
    }
    

    if (!strncmp(case_command, "SETUP", 5)) {
        argc --;
        argv ++;
        result = cmd_setup();
    } else if (!strncmp(case_command, "UPDATE", 6)) {
        argc --;
        argv ++;
        result = cmd_update(case_verb);
    } else if (!strncmp(case_command, "START", 5) ||
               !strncmp(case_command, "STOP", 4) ||
               !strncmp(case_command, "NOTIFY", 6)) {
        argc --;
        argv ++;
        result = cmd_control(case_command);
    } else if (!strncmp(case_command, "ZONE", 4) && strlen(case_command) == 4) {
        argc --; argc --;
        argv ++; argv ++;

        /* verb should be add, delete or list */
        if (!strncmp(case_verb, "ADD", 3)) {
            result = cmd_addzone();
        } else if (!strncmp(case_verb, "DELETE", 6)) {
            result = cmd_delzone();
        } else if (!strncmp(case_verb, "LIST", 4)) {
            result = cmd_listzone();
        } else {
            printf("Unknown command: zone %s\n", case_verb);
            usage_zone();
            result = -1;
        }
    } else if (!strncmp(case_command, "REPOSITORY", 10)) {
        argc --; argc --;
        argv ++; argv ++;
        /* verb should be list */
        if (!strncmp(case_verb, "LIST", 4)) {
            result = cmd_listrepo();
        } else {
            printf("Unknown command: repository %s\n", case_verb);
            usage_repo();
            result = -1;
        }
    } else if (!strncmp(case_command, "POLICY", 6)) {
        argc --; argc --;
        argv ++; argv ++;
        /* verb should be export, import, list or purge */
        if (!strncmp(case_verb, "EXPORT", 6)) {
            result = cmd_exportpolicy();
        } else if (!strncmp(case_verb, "IMPORT", 6)) {
            result = cmd_update("KASP");
        } else if (!strncmp(case_verb, "LIST", 4)) {
            result = cmd_listpolicy();
        } else if (!strncmp(case_verb, "PURGE", 5)) {
            result = cmd_purgepolicy();
        } else {
            printf("Unknown command: policy %s\n", case_verb);
            usage_policy();
            result = -1;
        }
    } else if (!strncmp(case_command, "KEY", 3)) {
        argc --; argc --;
        argv ++; argv ++;
        /* verb should be list, export import, rollover, purge, generate, ksk-retire or ds-seen */
        if (!strncmp(case_verb, "LIST", 4)) {
            result = cmd_listkeys();
        }
        else if (!strncmp(case_verb, "EXPORT", 6)) {
            result = cmd_exportkeys();
        }
        else if (!strncmp(case_verb, "IMPORT", 6)) {
            result = cmd_import();
        }
        else if (!strncmp(case_verb, "ROLLOVER", 8)) {
            /* Check that we have either a key type or the all flag */
            if (all_flag == 0 && o_keytype == NULL) {
		        printf("Please specify either a keytype, KSK or ZSK, with the --keytype <type> option or use the --all option\n");
                usage_keyroll();
                result = -1;
		    } 
		    else {
	            /* Are we rolling a zone or a whole policy? */
	            if (o_zone != NULL && o_policy == NULL) {
	                result = cmd_rollzone();
	            }
	            else if (o_zone == NULL && o_policy != NULL) {
	                result = cmd_rollpolicy();
	            }
	            else {
	                printf("Please provide either a zone OR a policy to rollover\n");
	                usage_keyroll();
	                result = -1;
	            }
	        }
        }
        else if (!strncmp(case_verb, "PURGE", 5)) {
            if ((o_zone != NULL && o_policy == NULL) || 
                    (o_zone == NULL && o_policy != NULL)){
                result = cmd_keypurge();
            }
            else {
                printf("Please provide either a zone OR a policy to key purge\n");
                usage_keypurge();
                result = -1;
            }
        }
        else if (!strncmp(case_verb, "GENERATE", 8)) {
            result = cmd_genkeys();
        }
        else if (!strncmp(case_verb, "KSK-RETIRE", 10)) {
            result = cmd_kskretire();
        }
        else if (!strncmp(case_verb, "KSK-REVOKE", 10)) {
            result = cmd_kskrevoke();
        }
        else if (!strncmp(case_verb, "DS-SEEN", 7)) {
            result = cmd_dsseen();
        } else if (!strncmp(case_verb, "DELETE", 6)) {
            result = cmd_delkey();
        } else {
            printf("Unknown command: key %s\n", case_verb);
            usage_key();
            result = -1;
        }
    } else if (!strncmp(case_command, "BACKUP", 6)) {
        argc --; argc --;
        argv ++; argv ++;
        /* verb should be done, prepare, commit, rollback or list */
        if (!strncmp(case_verb, "DONE", 4) ||
                !strncmp(case_verb, "PREPARE", 7) ||
                !strncmp(case_verb, "COMMIT", 6) ||
                !strncmp(case_verb, "ROLLBACK", 8)) {
            result = cmd_backup(case_verb);
        }
        else if (!strncmp(case_verb, "LIST", 4)) {
            result = cmd_listbackups();
        } else {
            printf("Unknown command: backup %s\n", case_verb);
            usage_backup();
            result = -1;
        }
    } else if (!strncmp(case_command, "ROLLOVER", 8)) {
        argc --; argc --;
        argv ++; argv ++;
        if (!strncmp(case_verb, "LIST", 4)) {
            result = cmd_listrolls();
        } else {
            printf("Unknown command: rollover %s\n", case_verb);
            usage_rollover();
            result = -1;
        }
    } else if (!strncmp(case_command, "DATABASE", 8)) {
        argc --; argc --;
        argv ++; argv ++;
        /* verb should be backup */
        if (!strncmp(case_verb, "BACKUP", 6)) {
            result = cmd_dbbackup();
        } else {
            printf("Unknown command: database %s\n", case_verb);
            usage_database();
            result = -1;
        }
    } else if (!strncmp(case_command, "ZONELIST", 8)) {
        argc --; argc --;
        argv ++; argv ++;
        /* verb should be import or export */
        if (!strncmp(case_verb, "EXPORT", 6)) {
            result = cmd_exportzonelist();
        }
        else if (!strncmp(case_verb, "IMPORT", 6)) {
            result = cmd_update("ZONELIST");
        } else {
            printf("Unknown command: zonelist %s\n", case_verb);
            usage_zonelist2();
            result = -1;
        }
    } else {
        printf("Unknown command: %s\n", argv[0]);
        usage();
        result = -1;
    }

    StrFree(case_command);
    StrFree(case_verb);

    /*(void) hsm_close();*/
    /*if (config) free(config);*/

    xmlCleanupParser();
    xmlCleanupGlobals();
    xmlCleanupThreads();

    exit(result);
}


/* 
 * Given a conf.xml location connect to the database contained within it
 *
 * A lock will be taken out on the DB if it is SQLite; so it is important to release it
 * in the calling Fn when we are done with it.
 * If backup is set to 1 then a backup will be made (of a sqlite DB file)
 *
 * Returns 0 if a connection was made.
 *         1 if a connection could not be made.
 *        -1 if any of the config files could not be read/parsed
 *
 */
    int
db_connect(DB_HANDLE *dbhandle, FILE** lock_fd, int backup)
{
    /* what we will read from the file */
    char *dbschema = NULL;
    char *host = NULL;
    char *port = NULL;
    char *user = NULL;
    char *password = NULL;

    int status;

    char* backup_filename = NULL;
    char* lock_filename;

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
        if (lock_fd != NULL) {
            lock_filename = NULL;
            StrAppend(&lock_filename, dbschema);
            StrAppend(&lock_filename, ".our_lock");

            *lock_fd = fopen(lock_filename, "w");
            status = get_lite_lock(lock_filename, *lock_fd);
            if (status != 0) {
                printf("Error getting db lock\n");
                if (*lock_fd != NULL) {
                    fclose(*lock_fd);
                }
                StrFree(host);
                StrFree(port);
                StrFree(dbschema);
                StrFree(user);
                StrFree(password);
				StrFree(lock_filename);
                return(1);
            }
            StrFree(lock_filename);
        }

        /* Make a backup of the sqlite DB */
        if (backup == 1) {
            StrAppend(&backup_filename, dbschema);
            StrAppend(&backup_filename, ".backup");

            status = backup_file(dbschema, backup_filename);

            StrFree(backup_filename);

            if (status == 1) {
                if (lock_fd != NULL) {
                    fclose(*lock_fd);
                }
                StrFree(host);
                StrFree(port);
                StrFree(dbschema);
                StrFree(user);
                StrFree(password);
                return(status);
            }
        }

    }

    /* Finally we can do what we came here to do, connect to the database */
    status = DbConnect(dbhandle, dbschema, host, password, user, port);

    /* Cleanup */
    StrFree(host);
    StrFree(port);
    StrFree(dbschema);
    StrFree(user);
    StrFree(password);

    return(status);
}

/* 
 * Release the lock if the DB is SQLite
 *
 */
    void
db_disconnect(FILE* lock_fd)
{
    int status = 0;

    if (DbFlavour() == SQLITE_DB) {
        if (lock_fd != NULL) {
            status = release_lite_lock(lock_fd);
            if (status != 0) {
                printf("Error releasing db lock");
                /*fclose(lock_fd);*/
                return;
            }
            fclose(lock_fd);
        }
    }
    return;
}

/* To overcome the potential differences in sqlite compile flags assume that it is not
   happy with multiple connections.

   The following 2 functions take out a lock and release it
 */

int get_lite_lock(char *lock_filename, FILE* lock_fd)
{
    struct flock fl;
    struct timeval tv;
	int retry = 0;

    if (lock_fd == NULL) {
        printf("%s could not be opened\n", lock_filename);
        return 1;
    }

    memset(&fl, 0, sizeof(struct flock));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_pid = getpid();

    while (fcntl(fileno(lock_fd), F_SETLK, &fl) == -1) {
		if (retry >= 6) {
			printf("couldn't get lock on %s; %s\n", lock_filename, strerror(errno));
			return 1;
		}
        if (errno == EACCES || errno == EAGAIN) {
            printf("%s already locked, sleep\n", lock_filename);

            /* sleep for 10 seconds TODO make this configurable? */
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            select(0, NULL, NULL, NULL, &tv);

			retry++;

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
 *  Now we will read the conf.xml file again, but this time we will not validate.
 *  Instead we just learn the location of the zonelist.xml and kasp.xml files.
 */
int read_filenames(char** zone_list_filename, char** kasp_filename)
{
    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    int ret = 0; /* status of the XML parsing */
    char* tag_name = NULL;
    char* temp_char = NULL;

    xmlChar *zonelist_expr = (unsigned char*) "//Common/ZoneListFile";
    xmlChar *kaspfile_expr = (unsigned char*) "//Common/PolicyFile";

    /* Start reading the file; we will be looking for "Repository" tags */ 
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
                if (xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
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
                    StrAppend(kasp_filename, OPENDNSSEC_CONFIG_DIR);
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
            printf("%s : failed to parse\n", config);
            return(1);
        }
    } else {
        printf("Unable to open %s\n", config);
            return(1);
    }
    if (doc) {
        xmlFreeDoc(doc);
    }

    return 0;
}

/* 
 *  Read the conf.xml file yet again, but this time we will not validate.
 *  Instead we just extract the RepositoryList into the database.
 */
int update_repositories()
{
    int status = 0;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode *curNode;
    char* repo_name = NULL;
    char* repo_capacity = NULL;
    int require_backup = 0;
    int i = 0;

    xmlChar *node_expr = (unsigned char*) "//Configuration/RepositoryList/Repository";

    /* Start reading the file; we will be looking for "Repository" tags */
    /* Load XML document */
    doc = xmlParseFile(config);
    if (doc == NULL) {
        printf("Unable to open %s\n", config);
        return(1);
    }

    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        xmlFreeDoc(doc);
        return(1);
    }

    /* Evaluate xpath expression */
    xpathObj = xmlXPathEvalExpression(node_expr, xpathCtx);
    if(xpathObj == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(1);
    }

    if (xpathObj->nodesetval) {
        for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {

            require_backup = 0;
            StrAppend(&repo_capacity, "");

            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            repo_name = (char *) xmlGetProp(xpathObj->nodesetval->nodeTab[i],
                                             (const xmlChar *)"name");
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar *)"Capacity")) {
                    repo_capacity = (char *) xmlNodeGetContent(curNode);
                }
                if (xmlStrEqual(curNode->name, (const xmlChar *)"RequireBackup")) {
                    require_backup = 1;
                }

                curNode = curNode->next;
            }

            if (strlen(repo_name) != 0) {
                /* Log what we are about to do */
                printf("Repository %s found\n", repo_name);
                if (strlen(repo_capacity) == 0) {
                    printf("No Maximum Capacity set.\n");
                    /*
                     * We have all the information, update/insert this repository
                     */
                    status = KsmImportRepository(repo_name, "0", require_backup);
                } else {
                    printf("Capacity set to %s.\n", repo_capacity);
                    /*
                     * We have all the information, update/insert this repository
                     */
                    status = KsmImportRepository(repo_name, repo_capacity, require_backup);
                }
                if (require_backup == 0) {
                    printf("RequireBackup NOT set; please make sure that you know the potential problems of using keys which are not recoverable\n");
                } else {
                    printf("RequireBackup set.\n");
                }

                if (status != 0) {
                    printf("Error Importing Repository %s", repo_name);
                    /* Don't return? try to parse the rest of the zones? */
                }
            } else {
                printf("WARNING: Repository found with NULL name, skipping...\n");
            }
            StrFree(repo_name);
            StrFree(repo_capacity);
        }
    }

    if (xpathObj) {
        xmlXPathFreeObject(xpathObj);
    }
    if (xpathCtx) {
        xmlXPathFreeContext(xpathCtx);
    }
    if (doc) {
        xmlFreeDoc(doc);
    }

    return 0;
}

/* Read kasp.xml, validate it and grab each policy in it as we go. */
int update_policies(char* kasp_filename)
{
    int status;

    /* what we will read from the file */
    char *policy_name = NULL;
    char *policy_description = NULL;

    /* All of the XML stuff */
    xmlDocPtr doc = NULL;
    xmlDocPtr pol_doc = NULL;
    xmlDocPtr rngdoc = NULL;
    xmlNode *curNode;
    xmlNode *childNode;
    xmlNode *childNode2;
    xmlNode *childNode3;
    xmlChar *opt_out_flag = (xmlChar *)"N";
    xmlChar *nsec3param_ttl = NULL ;
    xmlChar *share_keys_flag = (xmlChar *)"N";
    xmlChar *man_roll_flag = (xmlChar *)"N";
    xmlChar *rfc5011_flag = (xmlChar *)"N";
    int standby_keys_flag = 0;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlRelaxNGParserCtxtPtr rngpctx = NULL;
    xmlRelaxNGValidCtxtPtr rngctx = NULL;
    xmlRelaxNGPtr schema = NULL;
    int i = 0;

    xmlChar *node_expr = (unsigned char*) "//Policy";

    KSM_POLICY *policy;

	/* Some stuff for the algorithm change check */
	int value = 0;
	int algo_change = 0;
	int user_certain;
	char* changes_made = NULL;
	int size = -1;
	char tmp_change[KSM_MSG_LENGTH];

    /* Some files, the xml and rng */
    const char* rngfilename = OPENDNSSEC_SCHEMA_DIR "/kasp.rng";
    char* kaspcheck_cmd = NULL;
    char* kaspcheck_cmd_version = NULL;
    
    StrAppend(&kaspcheck_cmd, ODS_EN_KASPCHECK);
    StrAppend(&kaspcheck_cmd, " -c ");
    StrAppend(&kaspcheck_cmd, config);

    StrAppend(&kaspcheck_cmd_version, ODS_EN_KASPCHECK);
    StrAppend(&kaspcheck_cmd_version, " --version > /dev/null");

    /* Run kaspcheck */
    status = system(kaspcheck_cmd_version);
    if (status == 0)
    {
        status = system(kaspcheck_cmd);
        if (status != 0)
        {
            fprintf(stderr, "ods-kaspcheck returned an error, please check your policy\n");
            StrFree(kaspcheck_cmd);
            StrFree(kaspcheck_cmd_version);
            return(-1);
        }
    }
    else
    {
            fprintf(stderr, "Couldn't run ods-kaspcheck, will carry on\n");
    }

    StrFree(kaspcheck_cmd);
    StrFree(kaspcheck_cmd_version);

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
    policy = KsmPolicyAlloc();
    if (policy == NULL) {
        printf("Malloc for policy struct failed");
        exit(1);
    }

    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        xmlFreeDoc(doc);
	KsmPolicyFree(policy);
        return(1);
    }

    /* Evaluate xpath expression */
    xpathObj = xmlXPathEvalExpression(node_expr, xpathCtx);
    if(xpathObj == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
	KsmPolicyFree(policy);
        return(1);
    }

    if (xpathObj->nodesetval) {

		/* 
		 * We will loop through twice, the first time to check on any algorithm
		 * changes (which are not advised)
		 */
		for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) { /* foreach policy */

            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            policy_name = (char *) xmlGetProp(xpathObj->nodesetval->nodeTab[i], (const xmlChar *)"name");
            if (strlen(policy_name) == 0) {
                /* error */
                printf("Error extracting policy name from %s\n", kasp_filename);
                break;
            }

			/* 
			 * Only carry on if this is an existing policy
			 */
			SetPolicyDefaults(policy, policy_name);
			status = KsmPolicyExists(policy_name);
			if (status == 0) {
				/* Policy exists */
				status = KsmPolicyRead(policy);
				if(status != 0) {
					printf("Error: unable to read policy %s; skipping\n", policy_name);
					break;
				}

				while (curNode) {
					if (xmlStrEqual(curNode->name, (const xmlChar *)"Keys")) {
						childNode = curNode->children;
						while (childNode){
							if (xmlStrEqual(childNode->name, (const xmlChar *)"KSK")) {
								childNode2 = childNode->children;
								while (childNode2){
									if (xmlStrEqual(childNode2->name, (const xmlChar *)"Algorithm")) {
										/* Compare with existing */
										value = 0;
										status = StrStrtoi((char *)xmlNodeGetContent(childNode2), &value);
										if (status != 0) {
											printf("Error extracting KSK algorithm for policy %s, exiting...", policy_name);
											return status;
										}
										if (value != policy->ksk->algorithm) {
											/* Changed */
											if (!algo_change) {
												printf("\n\nAlgorithm change attempted... details:\n");
												StrAppend(&changes_made, "Algorithm changes made, details:");
												algo_change = 1;
											}
											size = snprintf(tmp_change, KSM_MSG_LENGTH, "Policy: %s, KSK algorithm changed from %d to %d.", policy_name, policy->ksk->algorithm, value);
											/* Check overflow */
											if (size < 0 || size >= KSM_MSG_LENGTH) {
												printf("Error constructing log message for policy %s, exiting...", policy_name);
												return -1;
											}
											printf("%s\n", tmp_change);
											StrAppend(&changes_made, "  ");
											StrAppend(&changes_made, tmp_change);
										}
										
									}
									childNode2 = childNode2->next;
								}

							} /* End of KSK */
							/* ZSK */
							else if (xmlStrEqual(childNode->name, (const xmlChar *)"ZSK")) {
								childNode2 = childNode->children;
								while (childNode2){
									if (xmlStrEqual(childNode2->name, (const xmlChar *)"Algorithm")) {
										/* Compare with existing */
										value = 0;
										status = StrStrtoi((char *)xmlNodeGetContent(childNode2), &value);
										if (status != 0) {
											printf("Error extracting ZSK algorithm for policy %s, exiting...", policy_name);
											return status;
										}
										if (value != policy->zsk->algorithm) {
											/* Changed */
											if (!algo_change) {
												printf("\n\nAlgorithm change attempted... details:\n");
												StrAppend(&changes_made, "Algorithm changes made, details:");
												algo_change = 1;
											}
												size = snprintf(tmp_change, KSM_MSG_LENGTH, "Policy: %s, ZSK algorithm changed from %d to %d.", policy_name, policy->zsk->algorithm, value);
											/* Check overflow */
											if (size < 0 || size >= KSM_MSG_LENGTH) {
												printf("Error constructing log message for policy %s, exiting...", policy_name);
												return -1;
											}
											printf("%s\n", tmp_change);
											StrAppend(&changes_made, "  ");
											StrAppend(&changes_made, tmp_change);
										}

									}
									childNode2 = childNode2->next;
								}

							} /* End of ZSK */

							childNode = childNode->next;
						}
					}
					curNode = curNode->next;
				}
			}
			/* Free up some stuff that we don't need any more */
            StrFree(policy_name);

		} /* End of <Policy> */

		/*
		 * Did we see any changes? If so then warn and confirm before continuing
		 */
		
		if (algo_change == 1 && force_flag == 0) {
			printf("*WARNING* This will change the algorithms used as noted above. Algorithm rollover is _not_ supported by OpenDNSSEC and zones may break. Are you sure? [y/N] ");

			user_certain = getchar();
			if (user_certain != 'y' && user_certain != 'Y') {
				printf("\nOkay, quitting...\n");
				xmlXPathFreeContext(xpathCtx);
				xmlFreeDoc(doc);
				KsmPolicyFree(policy);

				exit(0);
			}

			/* Newline for the output */
			printf("\n");

			/*
			 * Log this change to syslog for posterity
			 */
#ifdef HAVE_OPENLOG_R
        openlog_r("ods-ksmutil", 0, DEFAULT_LOG_FACILITY, &sdata);
#else
        openlog("ods-ksmutil", 0, DEFAULT_LOG_FACILITY);
#endif
#ifdef HAVE_SYSLOG_R
        syslog_r(LOG_INFO, &sdata, "%s", changes_made);
#else
        syslog(LOG_INFO, "%s", changes_made);
#endif
#ifdef HAVE_CLOSELOG_R
        closelog_r(&sdata);
#else
        closelog();
#endif

		}

		/*
		 * Then loop through to actually make the updates
		 */
        for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {

            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            policy_name = (char *) xmlGetProp(xpathObj->nodesetval->nodeTab[i], (const xmlChar *)"name");
            if (strlen(policy_name) == 0) {
                /* error */
                printf("Error extracting policy name from %s\n", kasp_filename);
                break;
            }

            printf("Policy %s found\n", policy_name);
			while (curNode) {
				if (xmlStrEqual(curNode->name, (const xmlChar *)"Description")) {
					policy_description = (char *) xmlNodeGetContent(curNode);

					/* Insert or update this policy with the description found,
					   we will need the policy_id too */
					SetPolicyDefaults(policy, policy_name);
					status = KsmPolicyExists(policy_name);
					if (status == 0) {
						/* Policy exists; we will be updating it */
						status = KsmPolicyRead(policy);
						if(status != 0) {
							printf("Error: unable to read policy %s; skipping\n", policy_name);
							curNode = curNode->next;
							break;
						}

						/* Set description if it has changed */
						if (strncmp(policy_description, policy->description, KSM_POLICY_DESC_LENGTH) != 0) {
							status = KsmPolicyUpdateDesc(policy->id, policy_description);
							if(status != 0) {
								printf("Error: unable to update policy description for %s; skipping\n", policy_name);
								/* Don't return? try to parse the rest of the file? */
								curNode = curNode->next;
								continue;
							}
						}
					}
					else {
						/* New policy, insert it and get the new policy_id */
						status = KsmImportPolicy(policy_name, policy_description);
						if(status != 0) {
							printf("Error: unable to insert policy %s; skipping\n", policy_name);
							/* Don't return? try to parse the rest of the file? */
							curNode = curNode->next;
							continue;
						}
						status = KsmPolicySetIdFromName(policy);

						if (status != 0) {
							printf("Error: unable to get policy id for %s; skipping\n", policy_name);
							curNode = curNode->next;
							continue;
						}
					}
				}
            /* SIGNATURES */
                else if (xmlStrEqual(curNode->name, (const xmlChar *)"Signatures")) {
                    childNode = curNode->children;
                    while (childNode){
                        if (xmlStrEqual(childNode->name, (const xmlChar *)"Resign")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode), "resign", "signature", policy->signature->resign, policy->id, DURATION_TYPE);
                        }
                        else if (xmlStrEqual(childNode->name, (const xmlChar *)"Refresh")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode), "refresh", "signature", policy->signer->refresh, policy->id, DURATION_TYPE);
                        }
                        else if (xmlStrEqual(childNode->name, (const xmlChar *)"Validity")) {
                            childNode2 = childNode->children;
                            while (childNode2){
                                if (xmlStrEqual(childNode2->name, (const xmlChar *)"Default")) {
                                    SetParamOnPolicy(xmlNodeGetContent(childNode2), "valdefault", "signature", policy->signature->valdefault, policy->id, DURATION_TYPE);
                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Denial")) {
                                    SetParamOnPolicy(xmlNodeGetContent(childNode2), "valdenial", "signature", policy->signature->valdenial, policy->id, DURATION_TYPE);
                                }
                                childNode2 = childNode2->next;
                            }
                        }
                        else if (xmlStrEqual(childNode->name, (const xmlChar *)"Jitter")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode), "jitter", "signature", policy->signer->jitter, policy->id, DURATION_TYPE);
                        }
                        else if (xmlStrEqual(childNode->name, (const xmlChar *)"InceptionOffset")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode), "clockskew", "signature", policy->signature->clockskew, policy->id, DURATION_TYPE);
                        }
                        childNode = childNode->next;
                    }
                } /* End of Signatures */
                else if (xmlStrEqual(curNode->name, (const xmlChar *)"Denial")) {
                    opt_out_flag = (xmlChar *)"N";
                    childNode = curNode->children;
                    while (childNode){
                        if (xmlStrEqual(childNode->name, (const xmlChar *)"NSEC3")) {
                            /* NSEC3 */
                            status = KsmParameterSet("version", "denial", 3, policy->id);
                            if (status != 0) {
                                printf("Error: unable to insert/update %s for policy\n", "Denial version");
                            }
                            childNode2 = childNode->children;
                            while (childNode2){
                                if (xmlStrEqual(childNode2->name, (const xmlChar *)"OptOut")) {
                                    opt_out_flag = (xmlChar *)"Y";
                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Resalt")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode2), "resalt", "denial", policy->denial->resalt, policy->id, DURATION_TYPE);
                                }
								else if (xmlStrEqual(childNode2->name, (const xmlChar *)"TTL")) {
									nsec3param_ttl = xmlNodeGetContent(childNode2);
                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Hash")) {
                                    childNode3 = childNode2->children;
                                    while (childNode3){
                                        if (xmlStrEqual(childNode3->name, (const xmlChar *)"Algorithm")) {
                                            SetParamOnPolicy(xmlNodeGetContent(childNode3), "algorithm", "denial", policy->denial->algorithm, policy->id, INT_TYPE);
                                        }
                                        else if (xmlStrEqual(childNode3->name, (const xmlChar *)"Iterations")) {
                                            SetParamOnPolicy(xmlNodeGetContent(childNode3), "iterations", "denial", policy->denial->iteration, policy->id, INT_TYPE);
                                        }
                                        else if (xmlStrEqual(childNode3->name, (const xmlChar *)"Salt")) {
                                            SetParamOnPolicy(xmlGetProp(childNode3, (const xmlChar *)"length"), "saltlength", "denial", policy->denial->saltlength, policy->id, INT_TYPE);
                                        }
                                        childNode3 = childNode3->next;
                                    }
                                }

                                childNode2 = childNode2->next;
                            }
                            /* Set things that we flagged */
                            SetParamOnPolicy(opt_out_flag, "optout", "denial", policy->denial->optout, policy->id, BOOL_TYPE);
                            if (nsec3param_ttl == NULL)
                            	nsec3param_ttl = (xmlChar *) StrStrdup("PT0S"); 
                            SetParamOnPolicy(nsec3param_ttl, "ttl", "denial", policy->denial->ttl, policy->id, DURATION_TYPE);
                            nsec3param_ttl = NULL;
                        } /* End of NSEC3 */
                        else if (xmlStrEqual(childNode->name, (const xmlChar *)"NSEC")) {
                            status = KsmParameterSet("version", "denial", 1, policy->id);
                            if (status != 0) {
                                printf("Error: unable to insert/update %s for policy\n", "Denial version");
                            }
                        }
                        childNode = childNode->next;
                    }
                } /* End of Denial */
                else if (xmlStrEqual(curNode->name, (const xmlChar *)"Keys")) {
                    share_keys_flag = (xmlChar *)"N";
                    childNode = curNode->children;
                    while (childNode){
                        if (xmlStrEqual(childNode->name, (const xmlChar *)"TTL")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode), "ttl", "keys", policy->keys->ttl, policy->id, DURATION_TYPE);
                        }
                        else if (xmlStrEqual(childNode->name, (const xmlChar *)"RetireSafety")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode), "retiresafety", "keys", policy->keys->retire_safety, policy->id, DURATION_TYPE);
                        }
                        else if (xmlStrEqual(childNode->name, (const xmlChar *)"PublishSafety")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode), "publishsafety", "keys", policy->keys->publish_safety, policy->id, DURATION_TYPE);
                        }
                        else if (xmlStrEqual(childNode->name, (const xmlChar *)"ShareKeys")) {
                            share_keys_flag = (xmlChar *)"Y";
                        }
                        else if (xmlStrEqual(childNode->name, (const xmlChar *)"Purge")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode), "purge", "keys", policy->keys->purge, policy->id, DURATION_TYPE);
                        }
                        /* KSK */
                        else if (xmlStrEqual(childNode->name, (const xmlChar *)"KSK")) {
                            man_roll_flag = (xmlChar *)"N";
                            rfc5011_flag = (xmlChar *)"N";
                            childNode2 = childNode->children;
                            while (childNode2){
                                if (xmlStrEqual(childNode2->name, (const xmlChar *)"Algorithm")) {
                                    SetParamOnPolicy(xmlNodeGetContent(childNode2), "algorithm", "ksk", policy->ksk->algorithm, policy->id, INT_TYPE);
                                    SetParamOnPolicy(xmlGetProp(childNode2, (const xmlChar *)"length"), "bits", "ksk", policy->ksk->bits, policy->id, INT_TYPE);

                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Lifetime")) {
                                    SetParamOnPolicy(xmlNodeGetContent(childNode2), "lifetime", "ksk", policy->ksk->lifetime, policy->id, DURATION_TYPE);
                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Repository")) {
                                    if (SetParamOnPolicy(xmlNodeGetContent(childNode2), "repository", "ksk", policy->ksk->sm, policy->id, REPO_TYPE) != 0) {
                                        printf("Please either add the repository to conf.xml or remove the reference to it from kasp.xml\n");
                                        /* return the error, we do not want to continue */
                                        xmlFreeDoc(pol_doc);
                                        xmlXPathFreeContext(xpathCtx);
                                        xmlRelaxNGFree(schema);
                                        xmlRelaxNGFreeValidCtxt(rngctx);
                                        xmlRelaxNGFreeParserCtxt(rngpctx);
                                        xmlFreeDoc(doc);
                                        xmlFreeDoc(rngdoc);
                                        KsmPolicyFree(policy);

                                        return(1);
                                    }
                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Standby")) {
                                    SetParamOnPolicy(xmlNodeGetContent(childNode2), "standby", "ksk", policy->ksk->standby_keys, policy->id, INT_TYPE);
                                    standby_keys_flag = 1;
                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"ManualRollover")) {
                                    man_roll_flag = (xmlChar *)"Y";
                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"RFC5011")) {
                                    rfc5011_flag = (xmlChar *)"Y";
                                }
                                /*else if (xmlStrEqual(childNode2->name, (const xmlChar *)"RolloverScheme")) {
                                    SetParamOnPolicy(xmlNodeGetContent(childNode2), "rollover_scheme", "ksk", policy->ksk->rollover_scheme, policy->id, ROLLOVER_TYPE);
                                }*/
                                childNode2 = childNode2->next;
                            }
                            /* Set things that we flagged */
                            SetParamOnPolicy(man_roll_flag, "manual_rollover", "ksk", policy->ksk->manual_rollover, policy->id, BOOL_TYPE);
                            SetParamOnPolicy(rfc5011_flag, "rfc5011", "ksk", policy->ksk->rfc5011, policy->id, BOOL_TYPE);
                            if (standby_keys_flag == 0) {
                                SetParamOnPolicy((xmlChar *)"0", "standby", "ksk", policy->ksk->standby_keys, policy->id, INT_TYPE_NO_FREE);
                            } else {
                                standby_keys_flag = 0;
                            }
                        } /* End of KSK */
                        /* ZSK */
                        else if (xmlStrEqual(childNode->name, (const xmlChar *)"ZSK")) {
                            man_roll_flag = (xmlChar *)"N";
                            childNode2 = childNode->children;
                            while (childNode2){
                                if (xmlStrEqual(childNode2->name, (const xmlChar *)"Algorithm")) {
                                    SetParamOnPolicy(xmlNodeGetContent(childNode2), "algorithm", "zsk", policy->zsk->algorithm, policy->id, INT_TYPE);
                                    SetParamOnPolicy(xmlGetProp(childNode2, (const xmlChar *)"length"), "bits", "zsk", policy->zsk->bits, policy->id, INT_TYPE);

                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Lifetime")) {
                                    SetParamOnPolicy(xmlNodeGetContent(childNode2), "lifetime", "zsk", policy->zsk->lifetime, policy->id, DURATION_TYPE);
                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Repository")) {
                                    if (SetParamOnPolicy(xmlNodeGetContent(childNode2), "repository", "zsk", policy->zsk->sm, policy->id, REPO_TYPE) != 0) {
                                        printf("Please either add the repository to conf.xml or remove the reference to it from kasp.xml\n");
                                        /* return the error, we do not want to continue */
                                        xmlFreeDoc(pol_doc);
                                        xmlXPathFreeContext(xpathCtx);
                                        xmlRelaxNGFree(schema);
                                        xmlRelaxNGFreeValidCtxt(rngctx);
                                        xmlRelaxNGFreeParserCtxt(rngpctx);
                                        xmlFreeDoc(doc);
                                        xmlFreeDoc(rngdoc);
                                        KsmPolicyFree(policy);

                                        return(1);
                                    }
                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Standby")) {
                                    SetParamOnPolicy(xmlNodeGetContent(childNode2), "standby", "zsk", policy->zsk->standby_keys, policy->id, INT_TYPE);
                                    standby_keys_flag = 1;
                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"ManualRollover")) {
                                    man_roll_flag = (xmlChar *)"Y";
                                }
                                childNode2 = childNode2->next;
                            }
                        /* Set things that we flagged */
                        SetParamOnPolicy(man_roll_flag, "manual_rollover", "zsk", policy->zsk->manual_rollover, policy->id, BOOL_TYPE);
                        } /* End of ZSK */

                        childNode = childNode->next;
                    }
                    /* Set things that we flagged */
                    SetParamOnPolicy(share_keys_flag, "zones_share_keys", "keys", policy->keys->share_keys, policy->id, BOOL_TYPE);
                    if (standby_keys_flag == 0) {
                        SetParamOnPolicy((xmlChar *)"0", "standby", "zsk", policy->zsk->standby_keys, policy->id, INT_TYPE_NO_FREE);
                    } else {
                        standby_keys_flag = 0;
                    }

                } /* End of Keys */
                /* Zone */
                else if (xmlStrEqual(curNode->name, (const xmlChar *)"Zone")) {
                    childNode = curNode->children;
                    while (childNode){
                        if (xmlStrEqual(childNode->name, (const xmlChar *)"PropagationDelay")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode), "propagationdelay", "zone", policy->zone->propdelay, policy->id, DURATION_TYPE);
                        }
                        else if (xmlStrEqual(childNode->name, (const xmlChar *)"SOA")) {
                            childNode2 = childNode->children;
                            while (childNode2){
                                if (xmlStrEqual(childNode2->name, (const xmlChar *)"TTL")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode2), "ttl", "zone", policy->zone->soa_ttl, policy->id, DURATION_TYPE);
                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Minimum")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode2), "min", "zone", policy->zone->soa_min, policy->id, DURATION_TYPE);
                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Serial")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode2), "serial", "zone", policy->zone->serial, policy->id, SERIAL_TYPE);
                                }
                                childNode2 = childNode2->next;
                            }
                        }
                        childNode = childNode->next;
                    }
                } /* End of Zone */
                /* Parent */
                else if (xmlStrEqual(curNode->name, (const xmlChar *)"Parent")) {
                    childNode = curNode->children;
                    while (childNode){
                        if (xmlStrEqual(childNode->name, (const xmlChar *)"PropagationDelay")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode), "propagationdelay", "parent", policy->parent->propdelay, policy->id, DURATION_TYPE);
                        }
                        else if (xmlStrEqual(childNode->name, (const xmlChar *)"DS")) {
                            childNode2 = childNode->children;
                            while (childNode2){
                                if (xmlStrEqual(childNode2->name, (const xmlChar *)"TTL")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode2), "ttlds", "parent", policy->parent->ds_ttl, policy->id, DURATION_TYPE);
                                }
                                childNode2 = childNode2->next;
                            }
                        }
                        else if (xmlStrEqual(childNode->name, (const xmlChar *)"SOA")) {
                            childNode2 = childNode->children;
                            while (childNode2){
                                if (xmlStrEqual(childNode2->name, (const xmlChar *)"TTL")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode2), "ttl", "parent", policy->parent->soa_ttl, policy->id, DURATION_TYPE);
                                }
                                else if (xmlStrEqual(childNode2->name, (const xmlChar *)"Minimum")) {
                            SetParamOnPolicy(xmlNodeGetContent(childNode2), "min", "parent", policy->parent->soa_min, policy->id, DURATION_TYPE);
                                }
                                childNode2 = childNode2->next;
                            }
                        }
                        childNode = childNode->next;
                    }
                } /* End of Parent */

                curNode = curNode->next;
            }

            /* Free up some stuff that we don't need any more */
            StrFree(policy_name);
            StrFree(policy_description);

        } /* End of <Policy> */
    }

    /* Cleanup */
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

	/* All of the XML stuff */
    xmlDocPtr doc = NULL;
    xmlDocPtr rngdoc = NULL;
    xmlNode *curNode;
    xmlNode *childNode;
    xmlNode *childNode2;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
	xmlRelaxNGParserCtxtPtr rngpctx = NULL;
    xmlRelaxNGValidCtxtPtr rngctx = NULL;
    xmlRelaxNGPtr schema = NULL;

    char* zone_name = NULL;
    char* policy_name = NULL;
    char* current_policy = NULL;
    char* current_signconf = NULL;
    char* current_input = NULL;
    char* current_output = NULL;
    char* current_in_type = NULL;
    char* current_out_type = NULL;
    int policy_id = 0;
    int new_zone = 0;   /* flag to say if the zone is new or not */
    int file_zone_count = 0; /* As a quick check we will compare the number of */
    int db_zone_count = 0;   /* zones in the file to the number in the database */
    int* zone_ids;      /* List of zone_ids seen from zonelist.xml */
    int temp_id;

    char* sql = NULL;
    DB_RESULT	result;         /* Result of the query */
    DB_RESULT	result2;        /* Result of the query */
    DB_RESULT	result3;        /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */
    KSM_PARAMETER shared;       /* Parameter information */
    int seen_zone = 0;
    int temp_count = 0;
    int i = 0;

	xmlChar *node_expr = (unsigned char*) "//Zone";
    const char* rngfilename = OPENDNSSEC_SCHEMA_DIR "/zonelist.rng";

	/* Load XML document */
    doc = xmlParseFile(zone_list_filename);
    if (doc == NULL) {
        printf("Error: unable to parse file \"%s\"\n", zone_list_filename);
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
        printf("Error validating file \"%s\"\n", zone_list_filename);
        return(-1);
    }

	/* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        xmlFreeDoc(doc);
        return(1);
    }

	/* Evaluate xpath expression */
    xpathObj = xmlXPathEvalExpression(node_expr, xpathCtx);
    if(xpathObj == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(1);
    }

	if (xpathObj->nodesetval) {
		file_zone_count = xpathObj->nodesetval->nodeNr;
	} else {
		printf("Error extracting zone count from %s\n", zone_list_filename);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(1);
	}

	/* Allocate space for the list of zone IDs */
    zone_ids = MemMalloc(file_zone_count * sizeof(int));

    if (xpathObj->nodesetval) {
        for (i = 0; i < file_zone_count; i++) {

            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            zone_name = (char *) xmlGetProp(xpathObj->nodesetval->nodeTab[i], (const xmlChar *)"name");
			if (strlen(zone_name) == 0) {
                /* error */
                printf("Error extracting zone name from %s\n", zone_list_filename);
                return(1);
            }

			/* 
			   It is tempting to remove the trailing dot here; however I am 
			   not sure that it is the right thing to do... It trashed my 
			   test setup by deleting the zone sion. and replacing it with 
			   sion (but of course none of the keys were moved). I think 
			   that allowing people to edit zonelist.xml means that we must 
			   allow them to add the td if they want to. 
		   */
			
			printf("Zone %s found; ", zone_name);
			while (curNode) {
				/* POLICY */
				if (xmlStrEqual(curNode->name, (const xmlChar *)"Policy")) {
					current_policy = (char *) xmlNodeGetContent(curNode);

					printf("policy set to %s\n", current_policy);

					/* If we have a different policy to last time get its ID */
					if (policy_name == NULL || strcmp(current_policy, policy_name) != 0) {
						StrFree(policy_name);
						StrAppend(&policy_name, current_policy);

						status = KsmPolicyIdFromName(policy_name, &policy_id);
						if (status != 0) {
							printf("ERROR, can't find policy %s.\n", policy_name);
							StrFree(zone_ids);
							return(1);
						}
					}
				}
				/* SIGNERCONFIGURATION */
				else if (xmlStrEqual(curNode->name, (const xmlChar *)"SignerConfiguration")) {
					current_signconf = (char *) xmlNodeGetContent(curNode);
				}
				/* ADAPTERS */
				else if (xmlStrEqual(curNode->name, (const xmlChar *)"Adapters")) {
					childNode = curNode->children;
					while (childNode){
						/* INPUT */
						if (xmlStrEqual(childNode->name, (const xmlChar *)"Input")) {		
							childNode2 = childNode->children;
							while (childNode2){
								if (xmlStrEqual(childNode2->name, (const xmlChar *)"Adapter")) {
									current_input = (char *) xmlNodeGetContent(childNode2);
									current_in_type = (char *) xmlGetProp(childNode2, (const xmlChar *)"type");
								}
								else if (xmlStrEqual(childNode2->name, (const xmlChar *)"File")) {
									current_input = (char *) xmlNodeGetContent(childNode2);
									current_in_type = (char *) childNode2->name;
								}
								childNode2 = childNode2->next;
							}
						}
						/* OUTPUT */
						else if (xmlStrEqual(childNode->name, (const xmlChar *)"Output")) {		
							childNode2 = childNode->children;
							while (childNode2){
								if (xmlStrEqual(childNode2->name, (const xmlChar *)"Adapter")) {
									current_output = (char *) xmlNodeGetContent(childNode2);
									current_out_type = (char *) xmlGetProp(childNode2, (const xmlChar *)"type");
								}
								else if (xmlStrEqual(childNode2->name, (const xmlChar *)"File")) {
									current_output = (char *) xmlNodeGetContent(childNode2);
									current_out_type = (char *) childNode2->name;
								}
								childNode2 = childNode2->next;
							}
						}
						childNode = childNode->next;
					}
				}
				curNode = curNode->next;
            }

			/*
			 * Now we have all the information update/insert this repository
			 */
			status = KsmImportZone(zone_name, policy_id, 0, &new_zone, current_signconf, current_input, current_output, current_in_type, current_out_type);
			if (status != 0) {
				if (status == -3) {
					printf("Error Importing zone %s; it already exists both with and without a trailing dot\n", zone_name);
				} else {
					printf("Error Importing Zone %s\n", zone_name);
				}
				StrFree(zone_ids);
				return(1);
			}

			if (new_zone == 1) {
				printf("Added zone %s to database\n", zone_name);
			}

			/* make a note of the zone_id */
			status = KsmZoneIdFromName(zone_name, &temp_id);
			if (status != 0) {
				printf("Error: unable to find a zone named \"%s\" in database\n", zone_name);
				printf("Error: Possibly two domains differ only by having a trailing dot or not?\n");
				StrFree(zone_ids);
				return(status);
			}

			/* We malloc'd this above */
			zone_ids[i] = temp_id;

			new_zone = 0;
		} /* End of <Zone> */

	}

	/* Cleanup */
    xmlXPathFreeContext(xpathCtx);
    xmlRelaxNGFree(schema);
    xmlRelaxNGFreeValidCtxt(rngctx);
    xmlRelaxNGFreeParserCtxt(rngpctx);
    xmlFreeDoc(doc);
    xmlFreeDoc(rngdoc);

    /* Now see how many zones are in the database */
    sql = DqsCountInit(DB_ZONE_TABLE);
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), &db_zone_count, sql);
    DqsFree(sql);

    /* If the 2 numbers match then our work is done */
    if (file_zone_count == db_zone_count) {
        StrFree(zone_ids);
        return 0;
    }
    /* If the file count is larger then something went wrong */
    else if (file_zone_count > db_zone_count) {
        printf("Failed to add all zones from zonelist\n");
        StrFree(zone_ids);
        return(1);
    }

    /* If we get here we need to do some deleting, get each zone in the db 
     * and see if it is in the zone_list that we built earlier */
    /* In case there are thousands of zones we don't use an "IN" clause*/
    sql = DqsSpecifyInit(DB_ZONE_TABLE, "id, name, policy_id");
    DqsOrderBy(&sql, "ID");
    DqsEnd(&sql);

    status = DbExecuteSql(DbHandle(), sql, &result);

    if (status == 0) {
        status = DbFetchRow(result, &row);
        while (status == 0) {
            DbInt(row, 0, &temp_id);
            DbString(row, 1, &zone_name);
            DbInt(row, 2, &policy_id);

            seen_zone = 0;
            for (i = 0; i < db_zone_count; ++i) {
                if (temp_id == zone_ids[i]) {
                    seen_zone = 1;
                    break;
                }
            }
            
            if (seen_zone == 0) {
                /* We need to delete this zone */
                /* Get the shared_keys parameter */
                printf("Removing zone %s from database\n", zone_name);

                status = KsmParameterInit(&result2, "zones_share_keys", "keys", policy_id);
                if (status != 0) {
                    DbFreeRow(row);
                    DbStringFree(zone_name);
                    StrFree(zone_ids);
					DusFree(sql);
                    return(status);
                }
                status = KsmParameter(result2, &shared);
                if (status != 0) {
                    DbFreeRow(row);
                    DbStringFree(zone_name);
                    StrFree(zone_ids);
					DusFree(sql);
                    return(status);
                }
                KsmParameterEnd(result2);

                /* how many zones on this policy (needed to unlink keys) */ 
                status = KsmZoneCountInit(&result3, policy_id); 
                if (status == 0) { 
                    status = KsmZoneCount(result3, &temp_count); 
                } 
                DbFreeResult(result3);

                /* Mark keys as dead if appropriate */
                if ((shared.value == 1 && temp_count == 1) || shared.value == 0) {
                    status = KsmMarkKeysAsDead(temp_id);
                    if (status != 0) {
                        printf("Error: failed to mark keys as dead in database\n");
                        StrFree(zone_ids);
						DusFree(sql);
                        return(status);
                    }
                }

                /* Finally, we can delete the zone (and any dnsseckeys entries) */
                status = KsmDeleteZone(temp_id);
            }

            status = DbFetchRow(result, &row);
        }
        /* Convert EOF status to success */

        if (status == -1) {
            status = 0;
        }
        DbFreeResult(result);
    }
    
    DusFree(sql);
    DbFreeRow(row);
    DbStringFree(zone_name);
    StrFree(zone_ids);

    return 0;
}

/* 
 * This encapsulates all of the steps needed to insert/update a parameter value
 * try to update the policy value, if it has changed
 * TODO possible bug where parmeters which have a value of 0 are not written (because we 
 * only write what looks like it has changed
 */
int SetParamOnPolicy(const xmlChar* new_value, const char* name, const char* category, int current_value, int policy_id, int value_type)
{
    int status = 0;
    int value = 0;
    char* temp_char = (char *)new_value;

    /* extract the value into an int */
    if (value_type == DURATION_TYPE) {
        if (strlen(temp_char) != 0) {
            status = DtXMLIntervalSeconds(temp_char, &value);
            if (status > 0) {
                printf("Error: unable to convert interval %s to seconds, error: %i\n", temp_char, status);
                StrFree(temp_char);
                return status;
            }
            else if (status == -1) {
                printf("Info: converting %s to seconds; M interpreted as 31 days, Y interpreted as 365 days\n", temp_char);
            }
            StrFree(temp_char);
        } else {
            value = -1;
        }
    }
    else if (value_type == BOOL_TYPE) {
        /* Do we have an empty tag or no tag? */
        if (strncmp(temp_char, "Y", 1) == 0) {
            value = 1;
        } else {
            value = 0;
        }
    }
    else if (value_type == REPO_TYPE) {
        /* We need to convert the repository name into an id */
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
        status = KsmSerialIdFromName(temp_char, &value);
        if (status != 0) {
            printf("Error: unable to find serial type %s\n", temp_char);
            StrFree(temp_char);
            return status;
        }
        StrFree(temp_char);
    }
    else if (value_type == ROLLOVER_TYPE) {
        /* We need to convert the rollover scheme name into an id */
        value = KsmKeywordRollNameToValue(temp_char);
        if (value == 0) {
            printf("Error: unable to find rollover scheme %s\n", temp_char);
            StrFree(temp_char);
            return status;
        }
        StrFree(temp_char);
    }
    else {
        status = StrStrtoi(temp_char, &value);
        if (status != 0) {
            printf("Error: unable to convert %s to int\n", temp_char);
            StrFree(temp_char);
            return status;
        }
        if (value_type != INT_TYPE_NO_FREE) {
            StrFree(temp_char);
        }
    }

    /* Now update the policy with what we found, if it is different */
    if (value != current_value || current_value == 0) {
        status = KsmParameterSet(name, category, value, policy_id);
        if (status != 0) {
            printf("Error: unable to insert/update %s for policy\n", name);
            printf("Error: Is your database schema up to date?\n");
            return status;
        }

        /* Special step if salt length changed make sure that the salt is 
           regenerated when the enforcer runs next */
        if (strncmp(name, "saltlength", 10) == 0) {
            status = KsmPolicyNullSaltStamp(policy_id);
            if (status != 0) {
                printf("Error: unable to insert/update %s for policy\n", name);
                printf("Error: Is your database schema up to date?\n");
                return status;
            }
        }
    }

    return 0;
}

void SetPolicyDefaults(KSM_POLICY *policy, char *name)
{
    if (policy == NULL) {
        printf("Error, no policy provided");
        return;
    }

	if (name) {
        snprintf(policy->name, KSM_NAME_LENGTH, "%s", name);
    }

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
    policy->keys->purge = -1;

    policy->ksk->algorithm = 0;
    policy->ksk->bits = 0;
    policy->ksk->lifetime = 0;
    policy->ksk->sm = 0;
    policy->ksk->overlap = 0;
    policy->ksk->ttl = 0;
    policy->ksk->rfc5011 = 0;
    policy->ksk->type = KSM_TYPE_KSK;
    policy->ksk->standby_keys = 0;
    policy->ksk->manual_rollover = 0;
    policy->ksk->rollover_scheme = KSM_ROLL_DEFAULT;

    policy->zsk->algorithm = 0;
    policy->zsk->bits = 0;
    policy->zsk->lifetime = 0;
    policy->zsk->sm = 0;
    policy->zsk->overlap = 0;
    policy->zsk->ttl = 0;
    policy->zsk->rfc5011 = 0;
    policy->zsk->type = KSM_TYPE_ZSK;
    policy->zsk->standby_keys = 0;
    policy->zsk->manual_rollover = 0;
    policy->zsk->rollover_scheme = 0;

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
    const char* rngfilename = OPENDNSSEC_SCHEMA_DIR "/conf.rng";

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
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Create an XML RelaxNGs parser context for the relax-ng document. */
    rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);
    xmlFreeDoc(rngdoc);
    if (rngpctx == NULL) {
        printf("Error: unable to create XML RelaxNGs parser context\n");
        xmlFreeDoc(doc);
        return(-1);
    }

    /* parse a schema definition resource and build an internal XML Schema structure which can be used to validate instances. */
    schema = xmlRelaxNGParse(rngpctx);
    xmlRelaxNGFreeParserCtxt(rngpctx);
    if (schema == NULL) {
        printf("Error: unable to parse a schema definition resource\n");
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Create an XML RelaxNGs validation context based on the given schema */
    rngctx = xmlRelaxNGNewValidCtxt(schema);
    if (rngctx == NULL) {
        printf("Error: unable to create RelaxNGs validation context based on the schema\n");
        xmlRelaxNGFree(schema);
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Validate a document tree in memory. */
    status = xmlRelaxNGValidateDoc(rngctx,doc);
    xmlRelaxNGFreeValidCtxt(rngctx);
    xmlRelaxNGFree(schema);
    if (status != 0) {
        printf("Error validating file \"%s\"\n", config);
        xmlFreeDoc(doc);
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
    if(xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
        db_found = SQLITE_DB;
        temp_char = (char *)xmlXPathCastToString(xpathObj);
        StrAppend(dbschema, temp_char);
        StrFree(temp_char);
		if (verbose_flag) {
			fprintf(stderr, "SQLite database set to: %s\n", *dbschema);
		}
    }
    xmlXPathFreeObject(xpathObj);

    if (db_found == 0) {
        db_found = MYSQL_DB;

        /* Get all of the MySQL stuff read in too */
        /* HOST, optional */
        xpathObj = xmlXPathEvalExpression(mysql_host, xpathCtx);
        if(xpathObj == NULL) {
            printf("Error: unable to evaluate xpath expression: %s\n", mysql_host);
            xmlXPathFreeContext(xpathCtx);
            xmlFreeDoc(doc);
            return(-1);
        }
        if(xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
            temp_char = (char *)xmlXPathCastToString(xpathObj);
            StrAppend(host, temp_char);
            StrFree(temp_char);
			if (verbose_flag) {
				fprintf(stderr, "MySQL database host set to: %s\n", *host);
			}
        }
        xmlXPathFreeObject(xpathObj);

        /* PORT, optional */
        xpathObj = xmlXPathEvalExpression(mysql_port, xpathCtx);
        if(xpathObj == NULL) {
            printf("Error: unable to evaluate xpath expression: %s\n", mysql_port);
            xmlXPathFreeContext(xpathCtx);
            xmlFreeDoc(doc);
            return(-1);
        }
        if(xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
            temp_char = (char *)xmlXPathCastToString(xpathObj);
            StrAppend(port, temp_char);
            StrFree(temp_char);
			if (verbose_flag) {
				fprintf(stderr, "MySQL database port set to: %s\n", *port);
			}
        }
        xmlXPathFreeObject(xpathObj);

        /* SCHEMA */
        xpathObj = xmlXPathEvalExpression(mysql_db, xpathCtx);
        if(xpathObj == NULL) {
            printf("Error: unable to evaluate xpath expression: %s\n", mysql_db);
            xmlXPathFreeContext(xpathCtx);
            xmlFreeDoc(doc);
            return(-1);
        }
        if(xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
            temp_char = (char *)xmlXPathCastToString(xpathObj);
            StrAppend(dbschema, temp_char);
            StrFree(temp_char);
			if (verbose_flag) {
				fprintf(stderr, "MySQL database schema set to: %s\n", *dbschema);
			}
        } else {
            db_found = 0;
        }
        xmlXPathFreeObject(xpathObj);

        /* DB USER */
        xpathObj = xmlXPathEvalExpression(mysql_user, xpathCtx);
        if(xpathObj == NULL) {
            printf("Error: unable to evaluate xpath expression: %s\n", mysql_user);
            xmlXPathFreeContext(xpathCtx);
            xmlFreeDoc(doc);
            return(-1);
        }
        if(xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
            temp_char = (char *)xmlXPathCastToString(xpathObj);
            StrAppend(user, temp_char);
            StrFree(temp_char);
			if (verbose_flag) {
				fprintf(stderr, "MySQL database user set to: %s\n", *user);
			}
        } else {
            db_found = 0;
        }
        xmlXPathFreeObject(xpathObj);

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
        xmlXPathFreeObject(xpathObj);

		if (verbose_flag) {
			fprintf(stderr, "MySQL database password set\n");
		}

    }

    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);

    /* Check that we found one or the other database */
    if(db_found == 0) {
        printf("Error: unable to find complete database connection expression\n");
        return(-1);
    }

    /* Check that we found the right database type */
    if (db_found != DbFlavour()) {
        printf("Error: Config file %s specifies database type %s but system is compiled to use %s\n", config, (db_found==1) ? "MySQL" : "sqlite3", (db_found==2) ? "MySQL" : "sqlite3");
        return(-1);
    }

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
                xmlXPathFreeObject(xpathObj);
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
                        const char *output_name,
                        const char *input_type, 
                        const char *output_type)
{
    xmlDocPtr doc;
    xmlNodePtr cur;
    xmlNodePtr newzonenode;
    xmlNodePtr newadaptnode;
    xmlNodePtr newinputnode;
    xmlNodePtr newinadnode;
    xmlNodePtr newoutputnode;
    xmlNodePtr newoutadnode;
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

    newinadnode = xmlNewTextChild (newinputnode, NULL, (const xmlChar *)"Adapter", (const xmlChar *)input_name);
    (void) xmlNewProp(newinadnode, (const xmlChar *)"type", (const xmlChar *)input_type);

    newoutputnode = xmlNewChild (newadaptnode, NULL, (const xmlChar *)"Output", NULL);

    newoutadnode = xmlNewTextChild (newoutputnode, NULL, (const xmlChar *)"Adapter", (const xmlChar *)output_name);
    (void) xmlNewProp(newoutadnode, (const xmlChar *)"type", (const xmlChar *)output_type);

    return(doc);
}

xmlDocPtr del_zone_node(const char *docname,
                        const char *zone_name)
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
    if (all_flag == 1) {
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

void list_zone_node(const char *docname, int *zone_ids)
{
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr cur;
    xmlNodePtr pol;
    xmlChar *polChar = NULL;
    xmlChar *propChar = NULL;

    int temp_id;
    int i = 0;
    int status = 0;

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
            propChar = xmlGetProp(cur, (xmlChar *) "name");
            printf("Found Zone: %s", propChar);

            /* make a note of the zone_id */
            status = KsmZoneIdFromName((char *) propChar, &temp_id);
            xmlFree(propChar);
            if (status != 0) {
                printf(" (zone not in database)");
                zone_ids[i] = 0;
            } else {
                zone_ids[i] = temp_id;
                i++;
            }

            /* Print the policy name for this zone */
            for(pol = cur->children; pol != NULL; pol = pol->next)
            {
                if (xmlStrcmp( pol->name, (const xmlChar *)"Policy") == 0)
                {
                    polChar = xmlNodeGetContent(pol);
                    printf("; on policy %s\n", polChar);
                    xmlFree(polChar);
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
		if (policy->denial->ttl != 0) {
			snprintf(temp_time, 32, "PT%dS", policy->denial->ttl);
			(void) xmlNewTextChild(nsec_node, NULL, (const xmlChar *)"TTL", (const xmlChar *)temp_time);
		}
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
        (void) xmlNewTextChild(hash_node, NULL, (const xmlChar *)"Iterations", (const xmlChar *)temp_time);
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
            (void) xmlNewTextChild(keys_node, NULL, (const xmlChar *)"ShareKeys", NULL);
    }
    if (policy->keys->purge != -1) {
        snprintf(temp_time, 32, "PT%dS", policy->keys->purge);
    (void) xmlNewTextChild(keys_node, NULL, (const xmlChar *)"Purge", (const xmlChar *)temp_time);
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
    snprintf(temp_time, 32, "%d", policy->ksk->standby_keys);
    (void) xmlNewTextChild(ksk_node, NULL, (const xmlChar *)"Standby", (const xmlChar *)temp_time);
    if (policy->ksk->manual_rollover == 1)
    {
        (void) xmlNewTextChild(ksk_node, NULL, (const xmlChar *)"ManualRollover", NULL);
    }
    if (policy->ksk->rfc5011 == 1)
    {
        (void) xmlNewTextChild(ksk_node, NULL, (const xmlChar *)"RFC5011", NULL);
    }
/*    if (policy->ksk->rollover_scheme != 0)
    {
        (void) xmlNewTextChild(ksk_node, NULL, (const xmlChar *)"RolloverScheme", (const xmlChar *) KsmKeywordRollValueToName(policy->ksk->rollover_scheme));
    }*/

    /* ZSK */
    zsk_node = xmlNewTextChild(keys_node, NULL, (const xmlChar *)"ZSK", NULL);
    snprintf(temp_time, 32, "%d", policy->zsk->algorithm);
    zsk_alg_node = xmlNewTextChild(zsk_node, NULL, (const xmlChar *)"Algorithm", (const xmlChar *)temp_time);
    snprintf(temp_time, 32, "%d", policy->zsk->bits);
    (void) xmlNewProp(zsk_alg_node, (const xmlChar *)"length", (const xmlChar *)temp_time);
    snprintf(temp_time, 32, "PT%dS", policy->zsk->lifetime);
    (void) xmlNewTextChild(zsk_node, NULL, (const xmlChar *)"Lifetime", (const xmlChar *)temp_time);
    (void) xmlNewTextChild(zsk_node, NULL, (const xmlChar *)"Repository", (const xmlChar *)policy->zsk->sm_name);
    snprintf(temp_time, 32, "%d", policy->zsk->standby_keys);
    (void) xmlNewTextChild(zsk_node, NULL, (const xmlChar *)"Standby", (const xmlChar *)temp_time);
    if (policy->zsk->manual_rollover == 1)
    {
        (void) xmlNewTextChild(zsk_node, NULL, (const xmlChar *)"ManualRollover", NULL);
    }

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

    return(0);
}

/*
 *  Delete a policy node from kasp.xml
 */
xmlDocPtr del_policy_node(const char *docname,
                        const char *policy_name)
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
    if (xmlStrcmp(root->name, (const xmlChar *) "KASP")) {
        fprintf(stderr,"document of the wrong type, root node != %s", "KASP");
        xmlFreeDoc(doc);
        return (NULL);
    }


    /* Policy nodes are children of the root */
    for(cur = root->children; cur != NULL; cur = cur->next)
    {
        /* is this the zone we are looking for? */
        if (xmlStrcmp( xmlGetProp(cur, (xmlChar *) "name"), (const xmlChar *) policy_name) == 0)
        {
            xmlUnlinkNode(cur);

            cur = root->children; /* May pass through multiple times, but will remove all instances of the policy */
        }
    }
    xmlFreeNode(cur);

    return(doc);
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

/*+
 * ListKeys - Output a list of Keys
 *
 *
 * Arguments:
 *
 *      int zone_id
 *          ID of the zone (-1 for all)
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int ListKeys(int zone_id)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    char        stringval[KSM_INT_STR_SIZE];  /* For Integer to String conversion */
    DB_RESULT	result;         /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */
    int         done_row = 0;   /* Have we printed a row this loop? */

    char*       temp_zone = NULL;   /* place to store zone name returned */
    int         temp_type = 0;      /* place to store key type returned */
    int         temp_state = 0;     /* place to store key state returned */
    char*       temp_publish = NULL;/* place to store publish date returned*/
    char*       temp_ready = NULL;  /* place to store ready date returned */
    char*       temp_active = NULL; /* place to store active date returned */
    char*       temp_retire = NULL; /* place to store retire date returned */
    char*       temp_dead = NULL;   /* place to store dead date returned */
    char*       temp_loc = NULL;    /* place to store location returned */
    char*       temp_hsm = NULL;    /* place to store hsm returned */
    int         temp_alg = 0;       /* place to store algorithm returned */
    int         temp_size = 0;      /* place to store size returned */
    int         temp_rfc5011 = 0;   /* place to store 5011 switch returned */
    int         temp_revoked = 0;   /* place to store revoked switch returned */

    bool bool_temp_zone = false;    /* temp_zone was NULL or not */
    int state_id = -1;
    int keytype_id = KSM_TYPE_KSK;
    char *case_keystate = NULL;
    char *case_keytype = NULL;

    /* Key information */
    hsm_key_t *key = NULL;
    ldns_rr *dnskey_rr = NULL;
    hsm_sign_params_t *sign_params = NULL;
    hsm_ctx_t* ctx = NULL;

    if (verbose_flag) {
        /* connect to the HSM */
        status = hsm_open(config, hsm_prompt_pin);
        ctx = hsm_create_context();
        if (status) {
            hsm_print_error(NULL);
            return(-1);
        }
    }

    /* check --keystate and --all option cannot be given together */
    if ( all_flag && o_keystate != NULL) {    	
        printf("Error: --keystate and --all option cannot be given together\n");
        return(-1);
    }
	
    /* Select rows */
    StrAppend(&sql, "select z.name, k.keytype, k.state, k.ready, k.active, k.retire, k.dead, k.location, s.name, k.algorithm, k.size, k.publish, k.rfc5011, k.revoked from securitymodules s, KEYDATA_VIEW k left join zones z on k.zone_id = z.id where s.id = k.securitymodule_id ");
    if (zone_id != -1) {
        StrAppend(&sql, "and zone_id = ");
        snprintf(stringval, KSM_INT_STR_SIZE, "%d", zone_id);
        StrAppend(&sql, stringval);
    }
	
    /* check keystate  */
    if (o_keystate != NULL) {
        case_keystate = StrStrdup(o_keystate);
        (void) StrToUpper(case_keystate);
        if (strncmp(case_keystate, "GENERATE", 8) == 0 || strncmp(o_keystate, "1", 1) == 0) {
            state_id =  KSM_STATE_GENERATE;
        }
        else if (strncmp(case_keystate, "KEYPUBLISH", 10) == 0 || strncmp(o_keystate, "10", 2) == 0) {
            state_id =  KSM_STATE_KEYPUBLISH;
        }
        else if (strncmp(case_keystate, "PUBLISH", 7) == 0 || strncmp(o_keystate, "2", 1) == 0) {
            state_id =  KSM_STATE_PUBLISH;
        }
        else if (strncmp(case_keystate, "READY", 5) == 0 || strncmp(o_keystate, "3", 1) == 0) {
            state_id =  KSM_STATE_READY;
        }
        else if (strncmp(case_keystate, "ACTIVE", 6) == 0 || strncmp(o_keystate, "4", 1) == 0) {
            state_id =  KSM_STATE_ACTIVE;
        }
        else if (strncmp(case_keystate, "RETIRE", 6) == 0 || strncmp(o_keystate, "5", 1) == 0) {
            state_id =  KSM_STATE_RETIRE;
        }
        else if (strncmp(case_keystate, "DEAD", 4) == 0 || strncmp(o_keystate, "6", 1) == 0) {
            state_id =  KSM_STATE_DEAD;
        }
        else if (strncmp(case_keystate, "DSSUB", 5) == 0 || strncmp(o_keystate, "7", 1) == 0) {
            state_id =  KSM_STATE_DSSUB;
        }
        else if (strncmp(case_keystate, "DSPUBLISH", 9) == 0 || strncmp(o_keystate, "8", 1) == 0) {
            state_id =  KSM_STATE_DSPUBLISH;
        }
        else if (strncmp(case_keystate, "DSREADY", 7) == 0 || strncmp(o_keystate, "9", 1) == 0) {
            state_id =  KSM_STATE_DSREADY;
        }
        else {
            printf("Error: Unrecognised state %s; should be one of GENERATE, PUBLISH, READY, ACTIVE, RETIRE, DEAD, DSSUB, DSPUBLISH, DSREADY or KEYPUBLISH\n", o_keystate);
            StrFree(case_keystate);
            return(-1);
        }
		
        /* key generate command will generate keys which keystate propetry is null */
        if (state_id != -1){
            if (state_id == KSM_STATE_GENERATE){
                StrAppend(&sql, " and (state = ");
                snprintf(stringval, KSM_INT_STR_SIZE, "%d", state_id);
                StrAppend(&sql, stringval);
                StrAppend(&sql, " or state is NULL) ");
            }else {
                StrAppend(&sql, " and state = ");
                snprintf(stringval, KSM_INT_STR_SIZE, "%d", state_id);
                StrAppend(&sql, stringval);	
            }
        }
        StrFree(case_keystate);
    }

    /* Check keytype */
    if (o_keytype != NULL) {
        case_keytype = StrStrdup(o_keytype);
        (void) StrToUpper(case_keytype);
        if (strncmp(case_keytype, "KSK", 3) == 0 || strncmp(o_keytype, "257", 3) == 0) {
            keytype_id = KSM_TYPE_KSK;
        }
        else if (strncmp(case_keytype, "ZSK", 3) == 0 || strncmp(o_keytype, "256", 3) == 0) {
            keytype_id = KSM_TYPE_ZSK;
        }
        else {
            printf("Error: Unrecognised keytype %s; should be one of KSK or ZSK\n", o_keytype);
            StrFree(case_keytype);
            return(-1);
        }
        StrAppend(&sql, " and keytype = ");
        snprintf(stringval, KSM_INT_STR_SIZE, "%d", keytype_id);
        StrAppend(&sql, stringval);
        StrFree(case_keytype);
    }		
    StrAppend(&sql, " order by zone_id");
    DusEnd(&sql);

    status = DbExecuteSql(DbHandle(), sql, &result);
    if (status == 0) {
        status = DbFetchRow(result, &row);
        if (verbose_flag == 1) {
            printf("Zone:                           Keytype:      State:    Date of next transition (to):  Size:   Algorithm:  CKA_ID:                           Repository:                       Keytag:\n");
        }
        else {
            printf("Zone:                           Keytype:      State:    Date of next transition:\n");
        }
        while (status == 0) {
            /* Got a row, print it */
            DbString(row, 0, &temp_zone);
            DbInt(row, 1, &temp_type);
            DbInt(row, 2, &temp_state);
            DbString(row, 3, &temp_ready);
            DbString(row, 4, &temp_active);
            DbString(row, 5, &temp_retire);
            DbString(row, 6, &temp_dead);
            DbString(row, 7, &temp_loc);
            DbString(row, 8, &temp_hsm);
            DbInt(row, 9, &temp_alg);
            DbInt(row, 10, &temp_size);
            DbString(row, 11, &temp_publish);
            DbInt(row, 12, &temp_rfc5011);
            DbInt(row, 13, &temp_revoked);
            if (temp_zone == NULL){
                bool_temp_zone = true;
                temp_zone = "NOT ALLOCATED";
            }else{
                bool_temp_zone = false;
            }
            done_row = 0;
			/* key generate command will generate keys which keystate propetry is null */
            if (!temp_state){
                if (all_flag || o_keystate != NULL) {
                    printf("%-31s %-13s %-9s %-20s", temp_zone, "", "generate", "(not scheduled)");
                    if (verbose_flag) {
                        printf("(publish)  ");
                    }
                    done_row = 1;
                }
            }
            else if (temp_state == KSM_STATE_GENERATE){
                if (all_flag || o_keystate != NULL) {
                    printf("%-31s %-13s %-9s %-20s", temp_zone, (temp_type == KSM_TYPE_KSK) ? "KSK" : "ZSK", KsmKeywordStateValueToName(temp_state), (temp_publish== NULL) ? "(not scheduled)" : temp_publish);
                    if (verbose_flag) {
                        printf("(publish)  ");
                    }
                    done_row = 1;
                }
            }
            else if (temp_state == KSM_STATE_PUBLISH) {
                printf("%-31s %-13s %-9s %-20s", temp_zone, (temp_type == KSM_TYPE_KSK) ? "KSK" : "ZSK", KsmKeywordStateValueToName(temp_state), (temp_ready == NULL) ? "(not scheduled)" : temp_ready);
				if (verbose_flag) {
                    if (!temp_rfc5011) {
                        printf("(ready)    ");
                    } else {
                        printf("(active)   ");
                    }
				}
                done_row = 1;
            }
            else if (temp_state == KSM_STATE_READY) {
                printf("%-31s %-13s %-9s %-20s", temp_zone, (temp_type == KSM_TYPE_KSK) ? "KSK" : "ZSK", KsmKeywordStateValueToName(temp_state), (temp_type == KSM_TYPE_KSK) ? "waiting for ds-seen" : "next rollover");
				if (verbose_flag) {
					printf("(active)   ");
				}
                done_row = 1;
            }
            else if (temp_state == KSM_STATE_ACTIVE) {
                printf("%-31s %-13s %-9s %-20s", temp_zone, (temp_type == KSM_TYPE_KSK) ? "KSK" : "ZSK", KsmKeywordStateValueToName(temp_state), (temp_retire == NULL) ? "(not scheduled)" : temp_retire);
				if (verbose_flag) {
					printf("(retire)   ");
				}
                done_row = 1;
            }
            else if (temp_state == KSM_STATE_RETIRE) {
                const char *state = temp_revoked? "revoke" : KsmKeywordStateValueToName(temp_state);
                printf("%-31s %-13s %-9s %-20s", temp_zone, (temp_type == KSM_TYPE_KSK) ? "KSK" : "ZSK", state, (temp_dead == NULL) ? "(not scheduled)" : temp_dead);
				if (verbose_flag) {
					printf("(dead)     ");
				}
                done_row = 1;
            }
            else if (temp_state == KSM_STATE_DEAD) {
                if (all_flag || o_keystate != NULL) {
                    printf("%-31s %-13s %-9s %-20s", temp_zone, (temp_type == KSM_TYPE_KSK) ? "KSK" : "ZSK", KsmKeywordStateValueToName(temp_state), "to be deleted");
					if (verbose_flag) {
						printf("(deleted)  ");
					}
                    done_row = 1;
                }
            }
            else if (temp_state == KSM_STATE_DSSUB) {
                printf("%-31s %-13s %-9s %-20s", temp_zone, "KSK", KsmKeywordStateValueToName(temp_state), "waiting for ds-seen");
				if (verbose_flag) {
					printf("(dspub)    ");
				}
                done_row = 1;
            }
            else if (temp_state == KSM_STATE_DSPUBLISH) {
                printf("%-31s %-13s %-9s %-20s", temp_zone, "KSK", KsmKeywordStateValueToName(temp_state), (temp_ready == NULL) ? "(not scheduled)" : temp_ready);
				if (verbose_flag) {
					printf("(dsready)  ");
				}
                done_row = 1;
            }
            else if (temp_state == KSM_STATE_DSREADY) {
                printf("%-31s %-13s %-9s %-20s", temp_zone, "KSK", KsmKeywordStateValueToName(temp_state), "When required");
				if (verbose_flag) {
					printf("(keypub)   ");
				}
                done_row = 1;
            }
            else if (temp_state == KSM_STATE_KEYPUBLISH) {
                printf("%-31s %-13s %-9s %-20s", temp_zone, "KSK", KsmKeywordStateValueToName(temp_state), (temp_active == NULL) ? "(not scheduled)" : temp_active);
				if (verbose_flag) {
					printf("(active)   ");
				}
                done_row = 1;
            }

            if (done_row == 1 && verbose_flag == 1) {
				printf("%-7d %-12d", temp_size, temp_alg);
                key = hsm_find_key_by_id(ctx, temp_loc);
                if (!key) {
                    printf("%-33s %s NOT IN repository\n", temp_loc, temp_hsm);
                } else if (bool_temp_zone == true){
                    printf("%-33s %s\n",temp_loc,temp_hsm);
                } else{
                    sign_params = hsm_sign_params_new();
                    sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, temp_zone);
                    sign_params->algorithm = temp_alg;
                    sign_params->flags = LDNS_KEY_ZONE_KEY;
                    if (temp_type == KSM_TYPE_KSK) {
                        sign_params->flags += LDNS_KEY_SEP_KEY;
                        if (temp_revoked) sign_params->flags |= 1<<7;
                    }
                    dnskey_rr = hsm_get_dnskey(ctx, key, sign_params);
                    sign_params->keytag = ldns_calc_keytag(dnskey_rr);

                    printf("%-33s %-33s %d\n", temp_loc, temp_hsm, sign_params->keytag);

                    hsm_sign_params_free(sign_params);
                    hsm_key_free(key);
                }
            }
            else if (done_row == 1) {
                printf("\n");
            }
            
            status = DbFetchRow(result, &row);
        }

        /* Convert EOF status to success */

        if (status == -1) {
            status = 0;
        }

        DbFreeResult(result);
    }

    DusFree(sql);
    DbFreeRow(row);
    if (bool_temp_zone == false){
        DbStringFree(temp_zone);
    }
    DbStringFree(temp_ready);
    DbStringFree(temp_active);
    DbStringFree(temp_retire);
    DbStringFree(temp_dead);
    DbStringFree(temp_loc);
    DbStringFree(temp_hsm);

    if (dnskey_rr != NULL) {
        ldns_rr_free(dnskey_rr);
    }

    if (verbose_flag) {
                hsm_destroy_context(ctx);
		hsm_close();
    }

    return status;
}

/*+
 * PurgeKeys - Purge dead Keys
 *
 *
 * Arguments:
 *
 *      int zone_id
 *          ID of the zone 
 *
 *      int policy_id
 *          ID of the policy
 *
 * N.B. Only one of the arguments should be set, the other should be -1
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int PurgeKeys(int zone_id, int policy_id)
{
    char*       sql = NULL;     /* SQL query */
    char*       sql1 = NULL;     /* SQL query */
    char*       sql2 = NULL;    /* SQL query */
    char*       sql3 = NULL;    /* SQL query */
    int         status = 0;     /* Status return */
    char        stringval[KSM_INT_STR_SIZE];  /* For Integer to String conversion */
    DB_RESULT	result;         /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */

    int         temp_id = -1;       /* place to store the key id returned */
    char*       temp_loc = NULL;    /* place to store location returned */
    int         count = 0;          /* How many keys don't match the purge */

    int         done_something = 0; /* have we done anything? */

    /* Key information */
    hsm_key_t *key = NULL;
    hsm_ctx_t* ctx;

    if ((zone_id == -1 && policy_id == -1) || 
            (zone_id != -1 && policy_id != -1)){
        printf("Please provide either a zone OR a policy to key purge\n");
        usage_keypurge();
        return(1);
    }

    /* connect to the HSM */
    status = hsm_open(config, hsm_prompt_pin);
    if (status) {
        hsm_print_error(NULL);
        return(-1);
    }
    ctx = hsm_create_context();

    /* Select rows */
    StrAppend(&sql, "select distinct id, location from KEYDATA_VIEW where state = 6 ");
    if (zone_id != -1) {
        StrAppend(&sql, "and zone_id = ");
        snprintf(stringval, KSM_INT_STR_SIZE, "%d", zone_id);
        StrAppend(&sql, stringval);
    }
    if (policy_id != -1) {
        StrAppend(&sql, "and policy_id = ");
        snprintf(stringval, KSM_INT_STR_SIZE, "%d", policy_id);
        StrAppend(&sql, stringval);
    }
    DusEnd(&sql);

    status = DbExecuteSql(DbHandle(), sql, &result);

    if (status == 0) {
        status = DbFetchRow(result, &row);
        while (status == 0) {
            /* Got a row, check it */
            DbInt(row, 0, &temp_id);
            DbString(row, 1, &temp_loc);

            sql1 = DqsCountInit("dnsseckeys");
            DdsConditionInt(&sql1, "keypair_id", DQS_COMPARE_EQ, temp_id, 0);
            DdsConditionInt(&sql1, "state", DQS_COMPARE_NE, KSM_STATE_DEAD, 1);
            DqsEnd(&sql1);

            status = DbIntQuery(DbHandle(), &count, sql1);
            DqsFree(sql1);

            if (status != 0) {
                printf("SQL failed: %s\n", DbErrmsg(DbHandle()));
                DbStringFree(temp_loc);
                DbFreeRow(row);
				DusFree(sql);
                                hsm_destroy_context(ctx);
				hsm_close();
                return status;
            }

            /* If the count is zero then there is no reason not to purge this key */
            if (count == 0) {

                done_something = 1;

                /* Delete from dnsseckeys */
                sql2 = DdsInit("dnsseckeys");
                DdsConditionInt(&sql2, "keypair_id", DQS_COMPARE_EQ, temp_id, 0);
                DdsEnd(&sql2);

                status = DbExecuteSqlNoResult(DbHandle(), sql2);
                DdsFree(sql2);
                if (status != 0)
                {
                    printf("SQL failed: %s\n", DbErrmsg(DbHandle()));
                    DbStringFree(temp_loc);
                    DbFreeRow(row);
					DusFree(sql);
                                        hsm_destroy_context(ctx);
					hsm_close();
                    return status;
                }

                /* Delete from keypairs */
                sql3 = DdsInit("keypairs");
                DdsConditionInt(&sql3, "id", DQS_COMPARE_EQ, temp_id, 0);
                DdsEnd(&sql3);

                status = DbExecuteSqlNoResult(DbHandle(), sql3);
                DdsFree(sql3);
                if (status != 0)
                {
                    printf("SQL failed: %s\n", DbErrmsg(DbHandle()));
                    DbStringFree(temp_loc);
                    DbFreeRow(row);
					DusFree(sql);
                                        hsm_destroy_context(ctx);
					hsm_close();
                    return status;
                }

                /* Delete from the HSM */
                key = hsm_find_key_by_id(ctx, temp_loc);

                if (!key) {
                    printf("Key not found: %s\n", temp_loc);
                    DbStringFree(temp_loc);
                    DbFreeRow(row);
					DusFree(sql);
                                        hsm_destroy_context(ctx);
					hsm_close();
                    return -1;
                }

                status = hsm_remove_key(ctx, key);

                hsm_key_free(key);

                if (!status) {
                    printf("Key remove successful: %s\n", temp_loc);
                } else {
                    printf("Key remove failed: %s\n", temp_loc);
                    DbStringFree(temp_loc);
                    DbFreeRow(row);
					DusFree(sql);
                                        hsm_destroy_context(ctx);
					hsm_close();
                    return -1;
                }
            }

            /* NEXT! */ 
            status = DbFetchRow(result, &row);
        }

        /* Convert EOF status to success */

        if (status == -1) {
            status = 0;
        }

        DbFreeResult(result);
    }

    if (done_something == 0) {
        printf("No keys to purge.\n");
    }

    DusFree(sql);
    DbFreeRow(row);

    DbStringFree(temp_loc);

        hsm_destroy_context(ctx);
	hsm_close();

    return status;
}

int cmd_genkeys()
{
    int status = 0;

    int interval = -1;

    KSM_POLICY* policy;
    hsm_ctx_t *ctx;

    char *rightnow;
    int i = 0;
    char *id;
    hsm_key_t *key = NULL;
    char *hsm_error_message = NULL;
    DB_ID ignore = 0;
    int ksks_needed = 0;    /* Total No of ksks needed before next generation run */
    int zsks_needed = 0;    /* Total No of zsks needed before next generation run */
    int ksks_in_queue = 0;  /* number of unused keys */
    int zsks_in_queue = 0;  /* number of unused keys */
    int new_ksks = 0;       /* number of keys required */
    int new_zsks = 0;       /* number of keys required */
    unsigned int current_count = 0;  /* number of keys already in HSM */

    DB_RESULT result; 
    int zone_count = 0;     /* Number of zones on policy */

    int same_keys = 0;      /* Do ksks and zsks look the same ? */
    int ksks_created = 0;   /* Were any KSKs created? */

        /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */

	/* We will ask if the user is sure once we have counted keys */
	int user_certain;

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

    policy = KsmPolicyAlloc();
    if (policy == NULL) {
        printf("Malloc for policy struct failed\n");
        db_disconnect(lock_fd);
        exit(1);
    }

    if (o_policy == NULL) {
        printf("Please provide a policy name with the --policy option\n");
        db_disconnect(lock_fd);
        KsmPolicyFree(policy);
        return(1);
    }
    if (o_interval == NULL) {
        printf("Please provide an interval with the --interval option\n");
        db_disconnect(lock_fd);
        KsmPolicyFree(policy);
        return(1);
    }

    SetPolicyDefaults(policy, o_policy);
  
    status = KsmPolicyExists(o_policy);
    if (status == 0) {
        /* Policy exists */
        status = KsmPolicyRead(policy);
        if(status != 0) {
            printf("Error: unable to read policy %s from database\n", o_policy);
            db_disconnect(lock_fd);
            KsmPolicyFree(policy);
            return status;
        }
    } else {
        printf("Error: policy %s doesn't exist in database\n", o_policy);
        db_disconnect(lock_fd);
        KsmPolicyFree(policy);
        return status;
    }

    if  (policy->shared_keys == 1 ) {
        printf("Key sharing is On\n");
    } else {
        printf("Key sharing is Off\n");
    }

    status = DtXMLIntervalSeconds(o_interval, &interval);
    if (status > 0) {
        printf("Error: unable to convert Interval %s to seconds, error: ", o_interval);
        switch (status) {
            case 1: /* This has gone away, will now return 2 */
                printf("invalid interval-type.\n");
                break;
            case 2:
                printf("unable to translate string.\n");
                break;
            case 3:
                printf("interval too long to be an int. E.g. Maximum is ~68 years on a system with 32-bit integers.\n");
                break;
            case 4:
                printf("invalid pointers or text string NULL.\n");
                break;
            default:
                printf("unknown\n");
        }
        db_disconnect(lock_fd);
        KsmPolicyFree(policy);
        return status;
    }
    else if (status == -1) {
        printf("Info: converting %s to seconds; M interpreted as 31 days, Y interpreted as 365 days\n", o_interval);
    }

    /* Connect to the hsm */
    status = hsm_open(config, hsm_prompt_pin);
    if (status) {
        hsm_error_message = hsm_get_error(NULL);
        if (hsm_error_message) {
            printf("%s\n", hsm_error_message);
            free(hsm_error_message);
        } else {
            /* decode the error code ourselves 
               TODO find if there is a better way to do this (and can all of these be returned? are there others?) */
            switch (status) {
                case HSM_ERROR:
                    printf("hsm_open() result: HSM error\n");
                    break;
                case HSM_PIN_INCORRECT:
                    printf("hsm_open() result: incorrect PIN\n");
                    break;
                case HSM_CONFIG_FILE_ERROR:
                    printf("hsm_open() result: config file error\n");
                    break;
                case HSM_REPOSITORY_NOT_FOUND:
                    printf("hsm_open() result: repository not found\n");
                    break;
                case HSM_NO_REPOSITORIES:
                    printf("hsm_open() result: no repositories\n");
                    break;
                default:
                    printf("hsm_open() result: %d", status);
            }
        }
        db_disconnect(lock_fd);
        KsmPolicyFree(policy);
        exit(1);
    }
    printf("HSM opened successfully.\n");
    ctx = hsm_create_context();

    rightnow = DtParseDateTimeString("now");

    /* Check datetime in case it came back NULL */
    if (rightnow == NULL) {
        printf("Couldn't turn \"now\" into a date, quitting...\n");
        db_disconnect(lock_fd);
        KsmPolicyFree(policy);
                hsm_destroy_context(ctx);
		hsm_close();
        exit(1);
    }

    if (policy->ksk->sm == policy->zsk->sm && policy->ksk->bits == policy->zsk->bits && policy->ksk->algorithm == policy->zsk->algorithm) {
        same_keys = 1;
    } else {
        same_keys = 0;
    }

    /* How many zones on this policy */ 
    status = KsmZoneCountInit(&result, policy->id); 
    if (status == 0) { 
        status = KsmZoneCount(result, &zone_count); 
    } 
    DbFreeResult(result); 

    if (status != 0) {
        printf("Could not count zones on policy %s\n", policy->name);
        db_disconnect(lock_fd);
                hsm_destroy_context(ctx);
		hsm_close();
		KsmPolicyFree(policy);
        return status; 
    }
    printf("Info: %d zone(s) found on policy \"%s\"\n", zone_count, policy->name);

	/* If the zone total has been specified manually then use this 
	instead but report how it differs from the actual number of zones*/
    if (o_zonetotal) {
	  /* Check the value is numeric*/
      if (StrIsDigits(o_zonetotal)) {
        status = StrStrtoi(o_zonetotal, &zone_count);
        if (status != 0) {
            printf("Error: Unable to convert zonetotal \"%s\"; to an integer\n", o_zonetotal);
            db_disconnect(lock_fd);
            KsmPolicyFree(policy);
                        hsm_destroy_context(ctx);
			hsm_close();
            exit(1);
        }
      } else {
          printf("Error: zonetotal \"%s\"; should be numeric only\n", o_zonetotal);
          db_disconnect(lock_fd);
          KsmPolicyFree(policy);
                  hsm_destroy_context(ctx);
		  hsm_close();
          exit(1);
      }
      /* Check the value is greater than 0*/
      if (zone_count < 1) { 
          printf("Error: zonetotal parameter value of %d is invalid - the value must be greater than 0\n", zone_count);
	      db_disconnect(lock_fd);
          KsmPolicyFree(policy);
                  hsm_destroy_context(ctx);
		  hsm_close();
          exit(1); 
      }
	  printf("Info: Keys will actually be generated for a total of %d zone(s) as specified by zone total parameter\n", zone_count);
	}
	else {
        /* make sure that we have at least one zone */ 
        if (zone_count == 0) { 
            printf("No zones on policy %s, skipping...\n", policy->name);
	    	db_disconnect(lock_fd);
                    hsm_destroy_context(ctx);
		    hsm_close();
            KsmPolicyFree(policy);
            return status; 
        } 
	}

    /* Find out how many ksk keys are needed for the POLICY */
    status = KsmKeyPredict(policy->id, KSM_TYPE_KSK, policy->shared_keys, interval, &ksks_needed, policy->ksk->rollover_scheme, zone_count);
    if (status != 0) {
        printf("Could not predict ksk requirement for next interval for %s\n", policy->name);
                hsm_destroy_context(ctx);
		hsm_close();
        db_disconnect(lock_fd);
        KsmPolicyFree(policy);
		return(1);
    }
    /* Find out how many suitable keys we have */
    status = KsmKeyCountStillGood(policy->id, policy->ksk->sm, policy->ksk->bits, policy->ksk->algorithm, interval, rightnow, &ksks_in_queue, KSM_TYPE_KSK);
    if (status != 0) {
        printf("Could not count current ksk numbers for policy %s\n", policy->name);
                hsm_destroy_context(ctx);
		hsm_close();
        db_disconnect(lock_fd);
        KsmPolicyFree(policy);
		return(1);
    }
    /* Don't have to adjust the queue for shared keys as the prediction has already taken care of that.*/

    new_ksks = ksks_needed - ksks_in_queue;
	printf("%d new KSK(s) (%d bits) need to be created for policy %s: keys_to_generate(%d) = keys_needed(%d) - keys_available(%d).\n", new_ksks, policy->ksk->bits, policy->name, new_ksks, ksks_needed, ksks_in_queue);


    /* Find out how many ZSKs are needed for the POLICY */
    status = KsmKeyPredict(policy->id, KSM_TYPE_ZSK, policy->shared_keys, interval, &zsks_needed, 0, zone_count);
    if (status != 0) {
        printf("Could not predict zsk requirement for next interval for %s\n", policy->name);
                hsm_destroy_context(ctx);
		hsm_close();
        db_disconnect(lock_fd);
        KsmPolicyFree(policy);
		return(1);
    }
    /* Find out how many suitable keys we have */
    status = KsmKeyCountStillGood(policy->id, policy->zsk->sm, policy->zsk->bits, policy->zsk->algorithm, interval, rightnow, &zsks_in_queue, KSM_TYPE_ZSK);
    if (status != 0) {
        printf("Could not count current zsk numbers for policy %s\n", policy->name);
                hsm_destroy_context(ctx);
		hsm_close();
        db_disconnect(lock_fd);
        KsmPolicyFree(policy);
		return(1);
    }
	/* Don't have to adjust the queue for shared keys as the prediction has already taken care of that.*/
    /* Need to account for how many ksks will be taken from the queue*/
    if (same_keys) {
	 	/* If we need to generate any new ksks then there aren't enough keys on the queue to meet the demand for ksks.
	 	   So we can't use any keys in the queue for zsks therefore we set the number available to 0 */
		if (new_ksks >= 0) {
			zsks_in_queue = 0;
		} else {
		 	/* Otherwise we can use any _not_ required for the ksks as zsk.
		       So we set the number availble to equal those left over after we have taken all the ksk. */
        	zsks_in_queue -= ksks_needed;
		}
     }

    new_zsks = zsks_needed - zsks_in_queue;
	printf("%d new ZSK(s) (%d bits) need to be created for policy %s: keys_to_generate(%d) = keys_needed(%d) - keys_available(%d).\n", new_zsks, policy->zsk->bits, policy->name, new_zsks, zsks_needed, zsks_in_queue);

	
    /* Check capacity of HSM will not be exceeded */
	if (policy->ksk->sm == policy->zsk->sm) {
		/* One HSM, One check */
		if (policy->ksk->sm_capacity != 0 && (new_ksks + new_zsks) > 0) {
			current_count = hsm_count_keys_repository(ctx, policy->ksk->sm_name);
			if (current_count >= policy->ksk->sm_capacity) {
				printf("Repository %s is full, cannot create more keys for policy %s\n", policy->ksk->sm_name, policy->name);
				return (1);
			}
			else if (current_count + new_ksks >  policy->ksk->sm_capacity) {
				printf("Repository %s is nearly full, will create %lu KSKs for policy %s (reduced from %d)\n", policy->ksk->sm_name, policy->ksk->sm_capacity - current_count, policy->name, new_ksks);
				new_ksks = policy->ksk->sm_capacity - current_count;
			}
			else if (current_count + new_ksks + new_zsks >  policy->ksk->sm_capacity) {
				printf("Repository %s is nearly full, will create %lu ZSKs for policy %s (reduced from %d)\n", policy->ksk->sm_name, policy->ksk->sm_capacity - current_count, policy->name, new_ksks);
				new_zsks = policy->ksk->sm_capacity - current_count - new_ksks;
			}

		}
	} else {
		/* Two HSMs, Two checks */
		/* KSKs */
		if (policy->ksk->sm_capacity != 0 && new_ksks > 0) {
			current_count = hsm_count_keys_repository(ctx, policy->ksk->sm_name);
			if (current_count >= policy->ksk->sm_capacity) {
				printf("Repository %s is full, cannot create more KSKs for policy %s\n", policy->ksk->sm_name, policy->name);
				new_ksks = 0;
			}
			else if (current_count + new_ksks >  policy->ksk->sm_capacity) {
				printf("Repository %s is nearly full, will create %lu KSKs for policy %s (reduced from %d)\n", policy->ksk->sm_name, policy->ksk->sm_capacity - current_count, policy->name, new_ksks);
				new_ksks = policy->ksk->sm_capacity - current_count;
			}
		}

		/* ZSKs */
		if (policy->zsk->sm_capacity != 0 && new_zsks > 0) {
			current_count = hsm_count_keys_repository(ctx, policy->zsk->sm_name);
			if (current_count >= policy->zsk->sm_capacity) {
				printf("Repository %s is full, cannot create more ZSKs for policy %s\n", policy->zsk->sm_name, policy->name);
				new_zsks = 0;
			}
			else if (current_count + new_zsks >  policy->zsk->sm_capacity) {
				printf("Repository %s is nearly full, will create %lu ZSKs for policy %s (reduced from %d)\n", policy->zsk->sm_name, policy->zsk->sm_capacity - current_count, policy->name, new_zsks);
				new_zsks = policy->zsk->sm_capacity - current_count;
			}
		}
	}

	/* If there is no work to do exit here */
	if (new_ksks <= 0 && new_zsks <= 0) {
		printf("No keys need to be created, quitting...\n");
    
		hsm_destroy_context(ctx);
		hsm_close();
		printf("all done!\n");
        db_disconnect(lock_fd);
        KsmPolicyFree(policy);
		return(status);		
	}

	/* Make sure that the user is happy */
	if (!auto_accept_flag) {
		printf("*WARNING* This will create %d KSKs (%d bits) and %d ZSKs (%d bits)\nAre you sure? [y/N] \n", new_ksks >= 0 ? new_ksks : 0, policy->ksk->bits, new_zsks >= 0 ? new_zsks : 0, policy->zsk->bits);

		user_certain = getchar();
		if (user_certain != 'y' && user_certain != 'Y') {
			printf("Okay, quitting...\n");
			
			hsm_destroy_context(ctx);
			hsm_close();
			printf("all done!\n");
	        db_disconnect(lock_fd);
	        KsmPolicyFree(policy);
			return(status);
		}
	}
	
    /* Create the required keys */
    for (i=new_ksks ; i > 0 ; i--){
        if (hsm_supported_algorithm(policy->ksk->algorithm) == 0) {
            /* NOTE: for now we know that libhsm only supports RSA keys */
            key = hsm_generate_rsa_key(ctx, policy->ksk->sm_name, policy->ksk->bits);
            if (key) {
                if (verbose_flag) {
                    printf("Created key in repository %s\n", policy->ksk->sm_name);
                }
            } else {
                printf("Error creating key in repository %s\n", policy->ksk->sm_name);
                hsm_error_message = hsm_get_error(ctx);
                if (hsm_error_message) {
                    printf("%s\n", hsm_error_message);
                    free(hsm_error_message);
                }
                db_disconnect(lock_fd);
                KsmPolicyFree(policy);
                hsm_destroy_context(ctx);
		hsm_close();
                exit(1);
            }
            id = hsm_get_key_id(ctx, key);
            hsm_key_free(key);
            status = KsmKeyPairCreate(policy->id, id, policy->ksk->sm, policy->ksk->bits, policy->ksk->algorithm, rightnow, &ignore);
            if (status != 0) {
                printf("Error creating key in Database\n");
                hsm_error_message = hsm_get_error(ctx);
                if (hsm_error_message) {
                    printf("%s\n", hsm_error_message);
                    free(hsm_error_message);
                }
                db_disconnect(lock_fd);
                KsmPolicyFree(policy);
                                hsm_destroy_context(ctx);
				hsm_close();
                exit(1);
            }
            printf("Created KSK size: %i, alg: %i with id: %s in repository: %s and database.\n", policy->ksk->bits,
                    policy->ksk->algorithm, id, policy->ksk->sm_name);
            free(id);
        } else {
            printf("Key algorithm %d unsupported by libhsm.\n", policy->ksk->algorithm);
            db_disconnect(lock_fd);
            KsmPolicyFree(policy);
                        hsm_destroy_context(ctx);
			hsm_close();
            exit(1);
        }
    }
    ksks_created = new_ksks;

    /* Create the required ZSKs */
    for (i = new_zsks ; i > 0 ; i--) {
        if (hsm_supported_algorithm(policy->zsk->algorithm) == 0) {
            /* NOTE: for now we know that libhsm only supports RSA keys */
            key = hsm_generate_rsa_key(ctx, policy->zsk->sm_name, policy->zsk->bits);
            if (key) {
                if (verbose_flag) {
                    printf("Created key in repository %s\n", policy->zsk->sm_name);
                }
            } else {
                printf("Error creating key in repository %s\n", policy->zsk->sm_name);
                hsm_error_message = hsm_get_error(ctx);
                if (hsm_error_message) {
                    printf("%s\n", hsm_error_message);
                    free(hsm_error_message);
                }
                db_disconnect(lock_fd);
                KsmPolicyFree(policy);
                                hsm_destroy_context(ctx);
				hsm_close();
                exit(1);
            }
            id = hsm_get_key_id(ctx, key);
            hsm_key_free(key);
            status = KsmKeyPairCreate(policy->id, id, policy->zsk->sm, policy->zsk->bits, policy->zsk->algorithm, rightnow, &ignore);
            if (status != 0) {
                printf("Error creating key in Database\n");
                hsm_error_message = hsm_get_error(ctx);
                if (hsm_error_message) {
                    printf("%s\n", hsm_error_message);
                    free(hsm_error_message);
                }
                db_disconnect(lock_fd);
                KsmPolicyFree(policy);
                                hsm_destroy_context(ctx);
				hsm_close();
                exit(1);
            }
            printf("Created ZSK size: %i, alg: %i with id: %s in repository: %s and database.\n", policy->zsk->bits,
                    policy->zsk->algorithm, id, policy->zsk->sm_name);
            free(id);
        } else {
            printf("Key algorithm %d unsupported by libhsm.\n", policy->zsk->algorithm);
            db_disconnect(lock_fd);
            KsmPolicyFree(policy);
                        hsm_destroy_context(ctx);
			hsm_close();
            exit(1);
        }
    }
    StrFree(rightnow);

    /* Log if a backup needs to be run for these keys */
    if (ksks_created > 0 && policy->ksk->require_backup) {
        printf("NOTE: keys generated in repository %s will not become active until they have been backed up\n", policy->ksk->sm_name);
    }
    if (new_ksks > 0 && policy->zsk->require_backup && (policy->zsk->sm != policy->ksk->sm)) {
        printf("NOTE: keys generated in repository %s will not become active until they have been backed up\n", policy->zsk->sm_name);
    }

    /*
     * Destroy HSM context
     */
    hsm_destroy_context(ctx);
    hsm_close();
    printf("all done!\n");

    KsmPolicyFree(policy);
    
    /* Release sqlite lock file (if we have it) */
    db_disconnect(lock_fd);

    return status;
}

int cmd_delkey()
{
    int status = 0;
    int user_certain;           /* Continue ? */
	int key_state = -1;
	int keypair_id = -1;

    /* Database connection details */
    DB_HANDLE	dbhandle;
    FILE* lock_fd = NULL;   /* This is the lock file descriptor for a SQLite DB */
    char*       sql = NULL;     /* SQL query */
    char*       sql2 = NULL;    /* SQL query */

    /* Key information */
    hsm_key_t *key = NULL;
    hsm_ctx_t* ctx;

	/* Check that we have either a keytag or a cka_id */
    if (o_cka_id == NULL) {
        printf("Please provide a CKA_ID for the key to delete\n");
        usage_keydelete();
        return(-1);
    }

	/* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, 1);
    if (status != 0) {
        printf("Failed to connect to database\n");
        db_disconnect(lock_fd);
        return(1);
    }

	
	/* Find the key and check its state */
	status = GetKeyState(o_cka_id, &key_state, &keypair_id);
    if (status != 0 || key_state == -1) {
        printf("Failed to determine the state of the key\n");
        db_disconnect(lock_fd);
        return(1);
    }

	/* If state == GENERATE or force_flag == 1 Remove the key from the database */
	if (key_state != KSM_STATE_GENERATE && key_state != KSM_STATE_DEAD) {
		if (force_flag == 1) {
			printf("*WARNING* This will delete a key that the enforcer believes is in use; are you really sure? [y/N] ");

			user_certain = getchar();
			if (user_certain != 'y' && user_certain != 'Y') {
				printf("Okay, quitting...\n");
				exit(0);
			}
		}
		else {
			printf("The enforcer believes that this key is in use, quitting...\n");
			exit(0);
		}
	}

	/* Okay, do it */
	/* Delete from dnsseckeys */
	sql = DdsInit("dnsseckeys");
	DdsConditionInt(&sql, "keypair_id", DQS_COMPARE_EQ, keypair_id, 0);
	DdsEnd(&sql);

	status = DbExecuteSqlNoResult(DbHandle(), sql);
	DdsFree(sql);
	if (status != 0)
	{
		printf("SQL failed: %s\n", DbErrmsg(DbHandle()));
		return status;
	}

	/* Delete from keypairs */
	sql2 = DdsInit("keypairs");
	DdsConditionInt(&sql2, "id", DQS_COMPARE_EQ, keypair_id, 0);
	DdsEnd(&sql2);

	status = DbExecuteSqlNoResult(DbHandle(), sql2);
	DdsFree(sql2);
	if (status != 0)
	{
		printf("SQL failed: %s\n", DbErrmsg(DbHandle()));
		return status;
	}

	/* If hsm_flag == 1 Remove from the HSM */
	if (hsm_flag == 1) {
		/* connect to the HSM */
		status = hsm_open(config, hsm_prompt_pin);
		if (status) {
			hsm_print_error(NULL);
			return(-1);
		}
                ctx = hsm_create_context();

		/* Delete from the HSM */
		key = hsm_find_key_by_id(ctx, o_cka_id);

		if (!key) {
			printf("Key not found in HSM: %s\n", o_cka_id);
                        hsm_destroy_context(ctx);
			hsm_close();
			return -1;
		}

		status = hsm_remove_key(ctx, key);

		hsm_key_free(key);
                hsm_destroy_context(ctx);
		hsm_close();
	}

	if (!status) {
		printf("Key delete successful: %s\n", o_cka_id);
	} else {
		printf("Key delete failed: %s\n", o_cka_id);
		return -1;
	}

	return status;
}

/* Make sure (if we can) that the permissions on a file are correct for the user/group in conf.xml */

int fix_file_perms(const char *dbschema)
{
    struct stat stat_ret;
    
    int status = 0;

    xmlDocPtr doc = NULL;
    xmlDocPtr rngdoc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlRelaxNGParserCtxtPtr rngpctx = NULL;
    xmlRelaxNGValidCtxtPtr rngctx = NULL;
    xmlRelaxNGPtr schema = NULL;
    xmlChar *user_expr = (unsigned char*) "//Configuration/Enforcer/Privileges/User";
    xmlChar *group_expr = (unsigned char*) "//Configuration/Enforcer/Privileges/Group";

    char* filename = OPENDNSSEC_CONFIG_FILE;
    char* rngfilename = OPENDNSSEC_SCHEMA_DIR "/conf.rng";
    char* temp_char = NULL;

    struct passwd *pwd;
    struct group  *grp;

    int uid = -1;
    int gid = -1;
    char *username = NULL;
    char *groupname = NULL;

    printf("fixing permissions on file %s\n", dbschema);
    /* First see if we are running as root, if not then return */
    if (geteuid() != 0) {
        return 0;
    }

    /* Now see if the file exists, if it does not then return */
    if (stat(dbschema, &stat_ret) != 0) {
        printf("cannot stat file %s: %s", dbschema, strerror(errno));
        return -1;
    }

    /* OKAY... read conf.xml for the user and group */
    /* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        printf("Error: unable to parse file \"%s\"", filename);
        return(-1);
    }

    /* Load rng document */
    rngdoc = xmlParseFile(rngfilename);
    if (rngdoc == NULL) {
        printf("Error: unable to parse file \"%s\"", rngfilename);
        return(-1);
    }

    /* Create an XML RelaxNGs parser context for the relax-ng document. */
    rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);
    if (rngpctx == NULL) {
        printf("Error: unable to create XML RelaxNGs parser context");
        return(-1);
    }

    /* parse a schema definition resource and build an internal XML Shema struture which can be used to validate instances. */
    schema = xmlRelaxNGParse(rngpctx);
    if (schema == NULL) {
        printf("Error: unable to parse a schema definition resource");
        return(-1);
    }

    /* Create an XML RelaxNGs validation context based on the given schema */
    rngctx = xmlRelaxNGNewValidCtxt(schema);
    if (rngctx == NULL) {
        printf("Error: unable to create RelaxNGs validation context based on the schema");
        return(-1);
    }

    /* Validate a document tree in memory. */
    status = xmlRelaxNGValidateDoc(rngctx,doc);
    if (status != 0) {
        printf("Error validating file \"%s\"", filename);
        return(-1);
    }

    /* Now parse a value out of the conf */
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        printf("Error: unable to create new XPath context");
        xmlFreeDoc(doc);
        return(-1);
    }

    /* Set the group if specified */
    xpathObj = xmlXPathEvalExpression(group_expr, xpathCtx);
    if(xpathObj == NULL) {
        printf("Error: unable to evaluate xpath expression: %s", group_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }
    if (xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
        temp_char = (char*) xmlXPathCastToString(xpathObj);
        StrAppend(&groupname, temp_char);
        StrFree(temp_char);
        xmlXPathFreeObject(xpathObj);
    } else {
        groupname = NULL;
    }

    /* Set the user to drop to if specified */
    xpathObj = xmlXPathEvalExpression(user_expr, xpathCtx);
    if(xpathObj == NULL) {
        printf("Error: unable to evaluate xpath expression: %s", user_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }
    if (xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
        temp_char = (char*) xmlXPathCastToString(xpathObj);
        StrAppend(&username, temp_char);
        StrFree(temp_char);
        xmlXPathFreeObject(xpathObj);
    } else {
        username = NULL;
    }

    /* Free up the xml stuff, we are done with it */
    xmlXPathFreeContext(xpathCtx);
    xmlRelaxNGFree(schema);
    xmlRelaxNGFreeValidCtxt(rngctx);
    xmlRelaxNGFreeParserCtxt(rngpctx);
    xmlFreeDoc(doc);
    xmlFreeDoc(rngdoc);

    /* Set uid and gid if required */
    if (username != NULL) {
        /* Lookup the user id in /etc/passwd */
        if ((pwd = getpwnam(username)) == NULL) {
            printf("user '%s' does not exist. cannot chown %s...\n", username, dbschema);
            return(1);
        } else {
            uid = pwd->pw_uid;
        }
        endpwent();
    }
    if (groupname) {
        /* Lookup the group id in /etc/groups */
        if ((grp = getgrnam(groupname)) == NULL) {
            printf("group '%s' does not exist. cannot chown %s...\n", groupname, dbschema);
            exit(1);
        } else {
            gid = grp->gr_gid;
        }
        endgrent();
    }

    /* Change ownership of the db file */
    if (chown(dbschema, uid, gid) == -1) {
        printf("cannot chown(%u,%u) %s: %s",
                (unsigned) uid, (unsigned) gid, dbschema, strerror(errno));
        return -1;
    }

    /* and change ownership of the lock file */
    temp_char = NULL;
    StrAppend(&temp_char, dbschema);
    StrAppend(&temp_char, ".our_lock");

    if (chown(temp_char, uid, gid) == -1) {
        printf("cannot chown(%u,%u) %s: %s",
                (unsigned) uid, (unsigned) gid, temp_char, strerror(errno));
        StrFree(temp_char);
        return -1;
    }

    StrFree(temp_char);

    return 0;
}

/*+
 * CountKeys - Find how many Keys match our criteria
 *
 *
 * Arguments:
 *
 *      int zone_id
 *          ID of the zone (-1 for all)
 *
 *      int keytag
 *          keytag provided (-1 if not specified)
 *
 *      const char * cka_id
 *          cka_id provided (NULL if not)
 *
 *      int * key_count (returned)
 *          count of keys matching the information specified
 *
 *      char ** temp_cka_id (returned)
 *          cka_id of key found
 *
 *      int * temp_key_state (returned)
 *          What state is the key in (only used if _one_ key returned)
 *
 *      int * temp_keypair_id (returned)
 *          ID of the key found (only used if _one_ key returned)
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int CountKeys(int *zone_id, int keytag, const char *cka_id, int *key_count, char **temp_cka_id, int *temp_key_state, int *temp_keypair_id)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    char        stringval[KSM_INT_STR_SIZE];  /* For Integer to String conversion */
    DB_RESULT	result;         /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */

    char    buffer[256];    /* For constructing part of the command */
    size_t  nchar;          /* Number of characters written */

    int         done_row = 0;   /* Have we found a key this loop? */

    int         temp_zone_id = 0;   /* place to store zone_id returned */
    char*       temp_loc = NULL;    /* place to store location returned */
    int         temp_alg = 0;       /* place to store algorithm returned */
    int         temp_state = 0;     /* place to store state returned */
    int         temp_keypair = 0;   /* place to store id returned */

    int         temp_count = 0;     /* Count of keys found */

    /* Key information */
    hsm_key_t *key = NULL;
    ldns_rr *dnskey_rr = NULL;
    hsm_sign_params_t *sign_params = NULL;
    hsm_ctx_t* ctx;

    /* connect to the HSM */
    status = hsm_open(config, hsm_prompt_pin);
    if (status) {
        hsm_print_error(NULL);
        return(-1);
    }
    ctx = hsm_create_context();

    /* Select rows */
    nchar = snprintf(buffer, sizeof(buffer), "(%d, %d, %d, %d)",
        KSM_STATE_READY, KSM_STATE_ACTIVE, KSM_STATE_DSSUB, KSM_STATE_RETIRE);
    if (nchar >= sizeof(buffer)) {
        printf("Error: Overran buffer in CountKeys\n");
                hsm_destroy_context(ctx);
		hsm_close();
        return(-1);
    }

    /* TODO do I need to use the view */
    StrAppend(&sql, "select k.zone_id, k.location, k.algorithm, k.state, k.id from KEYDATA_VIEW k where state in ");
    StrAppend(&sql, buffer);
    StrAppend(&sql, " and zone_id is not null and k.keytype = 257");

    if (*zone_id != -1) {
        StrAppend(&sql, " and zone_id = ");
        snprintf(stringval, KSM_INT_STR_SIZE, "%d", *zone_id);
        StrAppend(&sql, stringval);
    }
    if (cka_id != NULL) {
        StrAppend(&sql, " and k.location = '");
        StrAppend(&sql, cka_id);
        StrAppend(&sql, "'");
    }
    /* where location is unique? */
    StrAppend(&sql, " group by location");

    DusEnd(&sql);

    status = DbExecuteSql(DbHandle(), sql, &result);

    /* loop round printing out the cka_id of any key that matches
     * if only one does then we are good, if not then we will write a 
     * message asking for further clarification */
    /* Note that we only need to do each key, not each instance of a key */
    if (status == 0) {
        status = DbFetchRow(result, &row);
        while (status == 0) {
            /* Got a row, process it */
            DbInt(row, 0, &temp_zone_id);
            DbString(row, 1, &temp_loc);
            DbInt(row, 2, &temp_alg);
            DbInt(row, 3, &temp_state);
            DbInt(row, 4, &temp_keypair);

            done_row = 0;

            if (keytag == -1 && cka_id == NULL)
            {
                *temp_key_state = temp_state;
            }

            key = hsm_find_key_by_id(ctx, temp_loc);
            if (!key) {
                printf("cka_id %-33s in DB but NOT IN repository\n", temp_loc);
            } else if (keytag != -1) {
                sign_params = hsm_sign_params_new();
                sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, "temp_zone");
                sign_params->algorithm = temp_alg;
                sign_params->flags = LDNS_KEY_ZONE_KEY;
                sign_params->flags += LDNS_KEY_SEP_KEY;

                dnskey_rr = hsm_get_dnskey(ctx, key, sign_params);
                sign_params->keytag = ldns_calc_keytag(dnskey_rr);

                /* Have we matched our keytag? */
                if (keytag == sign_params->keytag) {
                    temp_count++;
                    done_row = 1;
                    *temp_cka_id = NULL;
                    StrAppend(temp_cka_id, temp_loc);
                    *zone_id = temp_zone_id;
                    *temp_key_state = temp_state;
                    *temp_keypair_id = temp_keypair;
                    printf("Found key with CKA_ID %s\n", temp_loc);
                }

                hsm_sign_params_free(sign_params);
            }
            if (key && cka_id != NULL && strncmp(cka_id, temp_loc, strlen(temp_loc)) == 0) {
                /* Or have we matched a provided cka_id */
                if (done_row == 0) {
                    temp_count++;
                    *temp_cka_id = NULL;
                    StrAppend(temp_cka_id, temp_loc);
                    *zone_id = temp_zone_id;
                    *temp_key_state = temp_state;
                    *temp_keypair_id = temp_keypair;
                    printf("Found key with CKA_ID %s\n", temp_loc);
                }
            }

            if (key) {
                hsm_key_free(key);
            }
            
            status = DbFetchRow(result, &row);
        }

        /* Convert EOF status to success */

        if (status == -1) {
            status = 0;
        }

        DbFreeResult(result);
    }

    *key_count = temp_count;

    DusFree(sql);
    DbFreeRow(row);

    DbStringFree(temp_loc);

    if (dnskey_rr != NULL) {
        ldns_rr_free(dnskey_rr);
    }

        hsm_destroy_context(ctx);
	hsm_close();

    return status;
}

/* Simpler version of the above function */
int GetKeyState(const char *cka_id, int *temp_key_state, int *temp_keypair_id) {
	int			status = 0;
    char		sql[256];    	/* For constructing the command */
    size_t		nchar;          /* Number of characters written */

    DB_RESULT	result;         /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */
    int         temp_state = 0;     /* place to store state returned */
    int         temp_keypair = 0;   /* place to store id returned */

	nchar = snprintf(sql, sizeof(sql), "select k.id, k.state from KEYDATA_VIEW k where k.location = '%s'", cka_id);
    if (nchar >= sizeof(sql)) {
        printf("Error: Overran buffer in CountKeys\n");
        return(-1);
    }

	status = DbExecuteSql(DbHandle(), sql, &result);

	/* loop round until we find a key not in the GENERATE or DEAD state */
    if (status == 0) {
        status = DbFetchRow(result, &row);
        while (status == 0) {
            /* Got a row, process it */
            DbInt(row, 0, &temp_keypair);
            DbInt(row, 1, &temp_state);

			/* Note that GENERATE == {null} in this view so state will be 0 */
			if (temp_state == 0) {
				temp_state = KSM_STATE_GENERATE;
			}

			*temp_key_state = temp_state;
			*temp_keypair_id = temp_keypair;

			if (temp_state != KSM_STATE_GENERATE && temp_state != KSM_STATE_DEAD) {
				DbFreeRow(row);
				return(0);
            }

			status = DbFetchRow(result, &row);
        }
	}

    DbFreeRow(row);
	return(0);
}

/*+
 * MarkDSSeen - Indicate that the DS record has been observed:
 *              Change the state of the key to ACTIVE
 *
 * Arguments:
 *
 *      const char * cka_id
 *          cka_id of key to make active
 *
 *      int zone_id
 *          ID of the zone
 *
 *      int policy_id
 *          ID of the policy
 *
 *      const char * datetime
 *          when this is happening
 *
 *      int key_state
 *          state that the key is in
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int MarkDSSeen(int keypair_id, int zone_id, int policy_id, const char *datetime, int key_state)
{
    char*       sql1 = NULL;    /* SQL query */
    int         status = 0;     /* Status return */

    char            buffer[KSM_SQL_SIZE];    /* Long enough for any statement */
    
    KSM_PARCOLL         collection;     /* Collection of parameters for zone */
    int deltat;     /* Time interval */

    (void)      zone_id;

    /* Set collection defaults */
    KsmCollectionInit(&collection);

    /* Get the values of the parameters */
    status = KsmParameterCollection(&collection, policy_id);
    if (status != 0) {
        printf("Error: failed to read policy\n");
        return status;
    }

/* 0) Start a transaction */
    status = DbBeginTransaction();
    if (status != 0) {
        /* Something went wrong */

        MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
    }

    /* 1) Change the state of the selected Key */
    if (key_state == KSM_STATE_READY) {
        /* We are making a key active */

        /* Set the interval until Retire */
        deltat = collection.ksklife;

		/* Generate the SQL to express this interval */
		status = DbDateDiff(datetime, deltat, 1, buffer, KSM_SQL_SIZE);
		if (status != 0) {
			printf("DbDateDiff failed\n");
			return status;
		}

        sql1 = DusInit("dnsseckeys");
        DusSetInt(&sql1, "STATE", KSM_STATE_ACTIVE, 0);
        DusSetString(&sql1, KsmKeywordStateValueToName(KSM_STATE_ACTIVE), datetime, 1);
        StrAppend(&sql1, ", RETIRE = ");
        StrAppend(&sql1, buffer);
        StrAppend(&sql1, " ");

        DusConditionInt(&sql1, "KEYPAIR_ID", DQS_COMPARE_EQ, keypair_id, 0);
        DusConditionInt(&sql1, "ZONE_ID", DQS_COMPARE_EQ, zone_id, 1);
        DusEnd(&sql1);
    }
    else {
        /* We are making a standby key DSpublish */

        /* Set the interval until DSReady */
        deltat = collection.kskttl + collection.kskpropdelay + 
            collection.pub_safety;

		/* Generate the SQL to express this interval */
		status = DbDateDiff(datetime, deltat, 1, buffer, KSM_SQL_SIZE);
		if (status != 0) {
			printf("DbDateDiff failed\n");
			return status;
		}

        sql1 = DusInit("dnsseckeys");
        DusSetInt(&sql1, "STATE", KSM_STATE_DSPUBLISH, 0);
        DusSetString(&sql1, KsmKeywordStateValueToName(KSM_STATE_PUBLISH), datetime, 1);
        StrAppend(&sql1, ", READY = ");
        StrAppend(&sql1, buffer);
        StrAppend(&sql1, " ");

        DusConditionInt(&sql1, "KEYPAIR_ID", DQS_COMPARE_EQ, keypair_id, 0);
        DusConditionInt(&sql1, "ZONE_ID", DQS_COMPARE_EQ, zone_id, 1);
        DusEnd(&sql1);
    }

    status = DbExecuteSqlNoResult(DbHandle(), sql1);
    DusFree(sql1);

    /* Report any errors */
    if (status != 0) {
        status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        DbRollback();
        return status;
    }

    /* 3) Commit */
    /* Everything worked by the looks of it */
    DbCommit();

    return 0;
}

/*+
 * RetireOldKey - Retire the old KSK
 *
 *
 * Arguments:
 *
 *      int zone_id
 *          ID of the zone
 *
 *      int policy_id
 *          ID of the policy
 *
 *      const char * datetime
 *          when this is happening
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int RetireOldKey(int zone_id, int policy_id, const char *datetime)
{
    char*       sql2 = NULL;    /* SQL query */
    int         status = 0;     /* Status return */
    char*       where_clause = NULL;
    int         id = -1;        /* ID of key to retire */

    char        stringval[KSM_INT_STR_SIZE];  /* For Integer to String conversion */
    char            buffer[KSM_SQL_SIZE];    /* Long enough for any statement */
    
    KSM_PARCOLL         collection;     /* Collection of parameters for zone */
    int deltat;     /* Time interval */

    /* Set collection defaults */
    KsmCollectionInit(&collection);

    /* Get the values of the parameters */
    status = KsmParameterCollection(&collection, policy_id);
    if (status != 0) {
        printf("Error: failed to read policy\n");
        return status;
    }

/* 0) Start a transaction */
    status = DbBeginTransaction();
    if (status != 0) {
        /* Something went wrong */

        MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
    }

    /* 1) Retire the oldest active key, and set its deadtime */
    /* work out which key */
    snprintf(stringval, KSM_INT_STR_SIZE, "%d", zone_id);
    StrAppend(&where_clause, "select id from KEYDATA_VIEW where state = 4 and keytype = 257 and zone_id = ");
    StrAppend(&where_clause, stringval);
    StrAppend(&where_clause, " order by retire limit 1");

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), &id, where_clause);
    StrFree(where_clause);
    if (status != 0)
    {
        printf("Error: failed to find ID of key to retire\n");
        DbRollback();
        return status;
	}

    /* work out what its deadtime should become */
    deltat = collection.dsttl + collection.kskpropdelay + collection.ret_safety;

	/* Generate the SQL to express this interval */
	status = DbDateDiff(datetime, deltat, 1, buffer, KSM_SQL_SIZE);
	if (status != 0) {
		printf("DbDateDiff failed\n");
        DbRollback();
		return status;
	}

    sql2 = DusInit("dnsseckeys");
    DusSetInt(&sql2, "STATE", KSM_STATE_RETIRE, 0);
    DusSetString(&sql2, KsmKeywordStateValueToName(KSM_STATE_RETIRE), datetime, 1);
    StrAppend(&sql2, ", DEAD = ");
    StrAppend(&sql2, buffer);
    DusConditionInt(&sql2, "keypair_id", DQS_COMPARE_EQ, id, 0);
    DusConditionInt(&sql2, "ZONE_ID", DQS_COMPARE_EQ, zone_id, 1);

    status = DbExecuteSqlNoResult(DbHandle(), sql2);
    DusFree(sql2);

    /* Report any errors */
    if (status != 0) {
        status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        DbRollback();
        return status;
    }

    /* 2) Commit */
    /* Everything worked by the looks of it */
    DbCommit();

    return 0;
}

/*+
 * RevokeOldKey - Revoke the old KSK
 *
 *
 * Arguments:
 *
 *      int zone_id
 *          ID of the zone
 *
 *      int policy_id
 *          ID of the policy
 *
 *      const char * datetime
 *          when this is happening
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */
int RevokeOldKey(int zone_id, int policy_id, const char *datetime)
{
    char*       sql2 = NULL;    /* SQL query */
    int         status = 0;     /* Status return */
    char*       where_clause = NULL;
    int         id = -1;        /* ID of key to retire */

    char        stringval[KSM_INT_STR_SIZE];  /* For Integer to String conversion */
    
    KSM_PARCOLL         collection;     /* Collection of parameters for zone */

    /* Set collection defaults */
    KsmCollectionInit(&collection);

    /* Get the values of the parameters */
    status = KsmParameterCollection(&collection, policy_id);
    if (status != 0) {
        printf("Error: failed to read policy\n");
        return status;
    }

/* 0) Start a transaction */
    status = DbBeginTransaction();
    if (status != 0) {
        /* Something went wrong */

        MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
    }

    /* 1) Revoke the oldest retired key, and set its deadtime */
    /* work out which key */
    snprintf(stringval, KSM_INT_STR_SIZE, "%d", zone_id);
    /* KSM_STATE_RETIRE = 5 */
    StrAppend(&where_clause, "select id from KEYDATA_VIEW where state = 5 and keytype = 257 and zone_id = ");
    StrAppend(&where_clause, stringval);
    StrAppend(&where_clause, " order by dead limit 1");

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), &id, where_clause);
    StrFree(where_clause);
    if (status != 0)
    {
        printf("Error: failed to find ID of key to revoke\n");
        DbRollback();
        return status;
	}

    sql2 = DusInit("dnsseckeys");
    DusSetInt(&sql2, "revoked", 1, 0);
    DusSetString(&sql2, KsmKeywordStateValueToName(KSM_STATE_DEAD), datetime, 1);
    DusConditionInt(&sql2, "keypair_id", DQS_COMPARE_EQ, id, 0);
    DusConditionInt(&sql2, "ZONE_ID", DQS_COMPARE_EQ, zone_id, 1);

    status = DbExecuteSqlNoResult(DbHandle(), sql2);
    DusFree(sql2);

    if (!status) {
        sql2 = DusInit("keypairs");
        DusSetInt(&sql2, "fixedDate", 1, 0);
        DusConditionInt(&sql2, "id", DQS_COMPARE_EQ, id, 0);
        status = DbExecuteSqlNoResult(DbHandle(), sql2);
        DusFree(sql2);
    }

    /* Report any errors */
    if (status != 0) {
        status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        DbRollback();
        return status;
    }

    /* 2) Commit */
    /* Everything worked by the looks of it */
    DbCommit();

    return 0;
}

/*
 * CountKeysInState - Count Keys in given state
 *
 * Description:
 *      Counts the number of keys in the given state.
 *
 * Arguments:
 *      int keytype
 *          Either KSK or ZSK, depending on the key type
 *
 *      int keystate
 *          State of keys to count
 *
 *      int* count
 *          Number of keys meeting the condition.
 *
 *      int zone_id
 *          ID of zone that we are looking at (-1 == all zones)
 *
 * Returns:
 *      int
 *          Status return. 0 => success, Other => error, in which case a message
 *          will have been output.
-*/

int CountKeysInState(int keytype, int keystate, int* count, int zone_id)
{
    int     clause = 0;     /* Clause counter */
    char*   sql = NULL;     /* SQL command */
    int     status;         /* Status return */

    sql = DqsCountInit("KEYDATA_VIEW");
    DqsConditionInt(&sql, "KEYTYPE", DQS_COMPARE_EQ, keytype, clause++);
    DqsConditionInt(&sql, "STATE", DQS_COMPARE_EQ, keystate, clause++);
    if (zone_id != -1) {
        DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, clause++);
    }
    DqsEnd(&sql);

    status = DbIntQuery(DbHandle(), count, sql);
    DqsFree(sql);

    if (status != 0) {
        printf("Error in CountKeysInState\n");
    }

    return status;
}

/*+
 * ChangeKeyState - Change the state of the specified key
 *
 * Arguments:
 *
 *      int keytype
 *          type of key we are dealing with
 *
 *      const char * cka_id
 *          cka_id of key to change
 *
 *      int zone_id
 *          ID of the zone
 *
 *      int policy_id
 *          ID of the policy
 *
 *      const char * datetime
 *          when this is happening
 *
 *      int keystate
 *          state that the key should be moved to
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 *
 *  TODO take keytimings out of here
 */

int ChangeKeyState(int keytype, const char *cka_id, int zone_id, int policy_id, const char *datetime, int keystate)
{
    char*       sql1 = NULL;    /* SQL query */
    int         status = 0;     /* Status return */

    int     count = 0;      /* Count of keys whose date will be set */
    char*   sql = NULL;     /* For creating the SQL command */
    int     where = 0;      /* For the SQL selection */
    int     i = 0;          /* A counter */
    int     j = 0;          /* Another counter */
    char*   insql = NULL;   /* SQL "IN" clause */
    int*    keyids;         /* List of IDs of keys to promote */
    DB_RESULT    result;    /* List result set */
    KSM_KEYDATA  data;      /* Data for this key */

    char            buffer[KSM_SQL_SIZE];    /* Long enough for any statement */
    
    KSM_PARCOLL         collection;     /* Collection of parameters for zone */
    int deltat = 0;     /* Time interval */

    (void)      zone_id;

    /* Set collection defaults */
    KsmCollectionInit(&collection);

    /* Get the values of the parameters */
    status = KsmParameterCollection(&collection, policy_id);
    if (status != 0) {
        printf("Error: failed to read policy\n");
        return status;
    }

    /* Count how many keys will have their state changed */

    sql = DqsCountInit("KEYDATA_VIEW");
    DqsConditionString(&sql, "location", DQS_COMPARE_EQ, cka_id, where++);
    if (zone_id != -1) {
        DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, where++);
    }
    DqsEnd(&sql);

    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);

    if (status != 0) {
        status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
    }

    if (count == 0) {
        /* Nothing to do, error? */
        return status;
    }

    /* Allocate space for the list of key IDs */
    keyids = MemMalloc(count * sizeof(int));

    /* Get the list of IDs */

    where = 0;
    sql = DqsSpecifyInit("KEYDATA_VIEW", DB_KEYDATA_FIELDS);
    DqsConditionString(&sql, "location", DQS_COMPARE_EQ, cka_id, where++);
    if (zone_id != -1) {
        DqsConditionInt(&sql, "ZONE_ID", DQS_COMPARE_EQ, zone_id, where++);
    }
    DqsEnd(&sql);

    status = KsmKeyInitSql(&result, sql);
    DqsFree(sql);

    if (status == 0) {
        while (status == 0) {
            status = KsmKey(result, &data);
            if (status == 0) {
                keyids[i] = data.keypair_id;
                i++;
            }
        }

        /* Convert EOF status to success */

        if (status == -1) {
            status = 0;
        } else {
            status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
            StrFree(keyids);
            return status;
        }

        KsmKeyEnd(result);

    } else {
        status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        StrFree(keyids);
		return status;
	}
    
    /*
     * Now construct the "IN" statement listing the IDs of the keys we
     * are planning to change the state of.
     */

    StrAppend(&insql, "(");
    for (j = 0; j < i; ++j) {
        if (j != 0) {
            StrAppend(&insql, ",");
        }
        snprintf(buffer, sizeof(buffer), "%d", keyids[j]);
        StrAppend(&insql, buffer);
    }
    StrAppend(&insql, ")");

/* 0) Start a transaction */
    status = DbBeginTransaction();
    if (status != 0) {
        /* Something went wrong */

        MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
		StrFree(keyids);
        return status;
    }

    /* 1) Change the state of the selected Key */
    if (keystate == KSM_STATE_ACTIVE) {
        /* We are making a key active */

        /* Set the interval until Retire */
        deltat = collection.ksklife;

		/* Generate the SQL to express this interval */
		status = DbDateDiff(datetime, deltat, 1, buffer, KSM_SQL_SIZE);
		if (status != 0) {
			printf("DbDateDiff failed\n");
			StrFree(keyids);
			return status;
		}

        sql1 = DusInit("dnsseckeys");
        DusSetInt(&sql1, "STATE", KSM_STATE_ACTIVE, 0);
        DusSetString(&sql1, KsmKeywordStateValueToName(KSM_STATE_ACTIVE), datetime, 1);
        StrAppend(&sql1, ", RETIRE = ");
        StrAppend(&sql1, buffer);

        DusConditionKeyword(&sql1, "KEYPAIR_ID", DQS_COMPARE_IN, insql, 0);
        if (zone_id != -1) {
            DusConditionInt(&sql1, "ZONE_ID", DQS_COMPARE_EQ, zone_id, 1);
        }
        DusEnd(&sql1);
    }
    else if (keystate == KSM_STATE_RETIRE) {
        /* We are making a key retired */

        /* Set the interval until Dead */
        if (keytype == KSM_TYPE_ZSK) {
            deltat = collection.zsksiglife + collection.propdelay + collection.ret_safety;
        }
        else if (keytype == KSM_TYPE_KSK) {
            deltat = collection.kskttl + collection.kskpropdelay + 
                collection.ret_safety; /* Ipp */
        }

		/* Generate the SQL to express this interval */
		status = DbDateDiff(datetime, deltat, 1, buffer, KSM_SQL_SIZE);
		if (status != 0) {
			printf("DbDateDiff failed\n");
			StrFree(keyids);
			return status;
		}

        sql1 = DusInit("dnsseckeys");
        DusSetInt(&sql1, "STATE", KSM_STATE_RETIRE, 0);
        DusSetString(&sql1, KsmKeywordStateValueToName(KSM_STATE_RETIRE), datetime, 1);
        StrAppend(&sql1, ", DEAD = ");
        StrAppend(&sql1, buffer);

        DusConditionKeyword(&sql1, "KEYPAIR_ID", DQS_COMPARE_IN, insql, 0);
        if (zone_id != -1) {
            DusConditionInt(&sql1, "ZONE_ID", DQS_COMPARE_EQ, zone_id, 1);
        }
        DusEnd(&sql1);
    }
    else if (keystate == KSM_STATE_DSPUBLISH) {
        /* Set the interval until DSReady */
        deltat = collection.kskttl + collection.kskpropdelay + 
            collection.pub_safety;

		/* Generate the SQL to express this interval */
		status = DbDateDiff(datetime, deltat, 1, buffer, KSM_SQL_SIZE);
		if (status != 0) {
			printf("DbDateDiff failed\n");
			StrFree(keyids);
			return status;
		}

        sql1 = DusInit("dnsseckeys");
        DusSetInt(&sql1, "STATE", KSM_STATE_DSPUBLISH, 0);
        DusSetString(&sql1, KsmKeywordStateValueToName(KSM_STATE_PUBLISH), datetime, 1);
        StrAppend(&sql1, ", READY = ");
        StrAppend(&sql1, buffer);

        DusConditionKeyword(&sql1, "KEYPAIR_ID", DQS_COMPARE_IN, insql, 0);
        if (zone_id != -1) {
            DusConditionInt(&sql1, "ZONE_ID", DQS_COMPARE_EQ, zone_id, 1);
        }
        DusEnd(&sql1);
    }
    else {
        printf("Moving to keystate %s not implemented yet\n", KsmKeywordStateValueToName(keystate));
		StrFree(keyids);
        return -1;
    }

    status = DbExecuteSqlNoResult(DbHandle(), sql1);
    DusFree(sql1);

    StrFree(insql);
    StrFree(keyids);
    
    /* Report any errors */
    if (status != 0) {
        status = MsgLog(KME_SQLFAIL, DbErrmsg(DbHandle()));
        DbRollback();
        return status;
    }

    /* 3) Commit */
    /* It actually can't be anything else */
    DbCommit();

    return status;
}

static int restart_enforcerd()
{
	/* ToDo: This should really be rewritten so that it will read
	   OPENDNSSEC_ENFORCER_PIDFILE and send a SIGHUP itself */
	return system(ODS_EN_NOTIFY);
}

/* 
 *  Read the conf.xml file, we will not validate as that was done as we read the database.
 *  Instead we just extract the RepositoryList into the database and also learn the 
 *  location of the zonelist.
 */
int get_conf_key_info(int* interval, int* man_key_gen)
{
    int status = 0;
    int mysec = 0;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    char* temp_char = NULL;

    xmlChar *iv_expr = (unsigned char*) "//Configuration/Enforcer/Interval";
    xmlChar *mk_expr = (unsigned char*) "//Configuration/Enforcer/ManualKeyGeneration";

    /* Load XML document */
    doc = xmlParseFile(config);
    if (doc == NULL) {
        printf("Error: unable to parse file \"%s\"\n", config);
        return(-1);
    }

    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        printf("Error: unable to create new XPath context\n");
        xmlFreeDoc(doc);
        return(-1);
    }
    
    /* Evaluate xpath expression for interval */
    xpathObj = xmlXPathEvalExpression(iv_expr, xpathCtx);
    if(xpathObj == NULL) {
        printf("Error: unable to evaluate xpath expression: %s", iv_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    temp_char = (char *)xmlXPathCastToString(xpathObj);
    status = DtXMLIntervalSeconds(temp_char, &mysec);
    if (status > 0) {
        printf("Error: unable to convert Interval %s to seconds, error: %i\n", temp_char, status);
        StrFree(temp_char);
        return status;
    }
    else if (status == -1) {
        printf("Info: converting %s to seconds; M interpreted as 31 days, Y interpreted as 365 days\n", temp_char);
    }
    *interval = mysec;
    StrFree(temp_char);
    xmlXPathFreeObject(xpathObj);

    /* Evaluate xpath expression for Manual key generation */
    xpathObj = xmlXPathEvalExpression(mk_expr, xpathCtx);
    if(xpathObj == NULL) {
        printf("Error: unable to evaluate xpath expression: %s\n", mk_expr);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(-1);
    }

    if (xpathObj->nodesetval != NULL && xpathObj->nodesetval->nodeNr > 0) {
        /* Manual key generation tag is present */
        *man_key_gen = 1;
    }
    else {
        /* Tag absent */
        *man_key_gen = 0;
    }
    xmlXPathFreeObject(xpathObj);

    if (xpathCtx) {
        xmlXPathFreeContext(xpathCtx);
    }
    if (doc) {
        xmlFreeDoc(doc);
    }

    return 0;
}

/* TODO put this fn and the one below somewhere that we can call it from here and the enforcer */
 /*+
 * LinkKeys - Create required entries in Dnsseckeys table for zones added to policies
 *                      (i.e. when keysharing is turned on)
 *
 * Description:
 *      Allocates a key in the database.
 *
 * Arguments:
 *      const char* zone_name
 *          name of zone
 *
 *      int policy_id
 *          ID of policy which the zone is on
 *
 *      int interval
 *          Enforcer run interval
 *
 *      int man_key_gen
 *          Manual Key Generation flag
 *
 * Returns:
 *      int
 *          Status return.  0=> Success, non-zero => error.
-*/

int LinkKeys(const char* zone_name, int policy_id)
{
    int status = 0;

    int interval = -1;          /* Enforcer interval */
    int man_key_gen = -1;       /* Manual key generation flag */

    int             zone_id = 0;    /* id of zone supplied */ 
    KSM_POLICY* policy;

    /* Unused parameter */
    (void)policy_id;

    /* Get some info from conf.xml */
    status = get_conf_key_info(&interval, &man_key_gen);
    if (status != 0) {
        printf("Failed to Link Keys to zone\n");
        return(1);
    }

    status = KsmZoneIdFromName(zone_name, &zone_id);
    if (status != 0) {
        return(status);
    }

    policy = KsmPolicyAlloc();
    if (policy == NULL) {
        printf("Malloc for policy struct failed\n");
        exit(1);
    }
    SetPolicyDefaults(policy, o_policy);

    status = KsmPolicyExists(o_policy);
    if (status == 0) {
        /* Policy exists */
        status = KsmPolicyRead(policy);
        if(status != 0) {
            printf("Error: unable to read policy %s from database\n", o_policy);
            KsmPolicyFree(policy);
            return status;
        }
    } else {
        printf("Error: policy %s doesn't exist in database\n", o_policy);
        KsmPolicyFree(policy);
        return status;
    }

    /* Make sure that enough keys are allocated to this zone */
    status = allocateKeysToZone(policy, KSM_TYPE_ZSK, zone_id, interval, zone_name, man_key_gen, 0);
    if (status != 0) {
        printf("Error allocating zsks to zone %s", zone_name);
        KsmPolicyFree(policy);
        return(status);
    }
    status = allocateKeysToZone(policy, KSM_TYPE_KSK, zone_id, interval, zone_name, man_key_gen, policy->ksk->rollover_scheme);
    if (status != 0) {
        printf("Error allocating ksks to zone %s", zone_name);
        KsmPolicyFree(policy);
        return(status);
    }

    KsmPolicyFree(policy);
    return 0;
}

/* allocateKeysToZone
 *
 * Description:
 *      Allocates existing keys to zones
 *
 * Arguments:
 *      policy
 *          policy that the keys were created for
 *      key_type
 *          KSK or ZSK
 *      zone_id
 *          ID of zone in question
 *      interval
 *          time before next run
 *      zone_name
 *          just in case we need to log something
 *      man_key_gen
 *          lack of keys may be an issue for the user to fix
 *      int rollover_scheme
 *          KSK rollover scheme in use
 *
 * Returns:
 *      int
 *          Status return.  0=> Success, non-zero => error.
 *          1 == error with input
 *          2 == not enough keys to satisfy policy
 *          3 == database error
 -*/


int allocateKeysToZone(KSM_POLICY *policy, int key_type, int zone_id, uint16_t interval, const char* zone_name, int man_key_gen, int rollover_scheme)
{
    int status = 0;
    int keys_needed = 0;
    int keys_in_queue = 0;
    int keys_pending_retirement = 0;
    int new_keys = 0;
    int key_pair_id = 0;
    int i = 0;
    DB_ID ignore = 0;
    KSM_PARCOLL collection; /* Parameters collection */
    char*   datetime = DtParseDateTimeString("now");

    /* Check datetime in case it came back NULL */
    if (datetime == NULL) {
        printf("Couldn't turn \"now\" into a date, quitting...");
        exit(1);
    }

    if (policy == NULL) {
        printf("NULL policy sent to allocateKeysToZone");
        StrFree(datetime);
        return 1;
    }

    if (key_type != KSM_TYPE_KSK && key_type != KSM_TYPE_ZSK) {
        printf("Unknown keytype: %i in allocateKeysToZone", key_type);
        StrFree(datetime);
        return 1;
    }

    /* Get list of parameters */
    status = KsmParameterCollection(&collection, policy->id);
    if (status != 0) {
        StrFree(datetime);
        return status;
    }

    /* Make sure that enough keys are allocated to this zone */
    /* How many do we need ? (set sharing to 1 so that we get the number needed for a single zone on this policy */
    status = KsmKeyPredict(policy->id, key_type, 1, interval, &keys_needed, rollover_scheme, 1);
    if (status != 0) {
        printf("Could not predict key requirement for next interval for %s", zone_name);
        StrFree(datetime);
        return 3;
    }

    /* How many do we have ? TODO should this include the currently active key?*/
    status = KsmKeyCountQueue(key_type, &keys_in_queue, zone_id);
    if (status != 0) {
        printf("Could not count current key numbers for zone %s", zone_name);
        StrFree(datetime);
        return 3;
    }

    /* or about to retire */
    status = KsmRequestPendingRetireCount(key_type, datetime, &collection, &keys_pending_retirement, zone_id, interval);
    if (status != 0) {
        printf("Could not count keys which may retire before the next run (for zone %s)", zone_name);
        StrFree(datetime);
        return 3;
    }

    StrFree(datetime);
    new_keys = keys_needed - (keys_in_queue - keys_pending_retirement);

    /* TODO: add check that new_keys is more than 0 */
    /*log_msg(NULL, LOG_DEBUG, "%s key allocation for zone %s: keys_to_allocate(%d) = keys_needed(%d) - (keys_available(%d) - keys_pending_retirement(%d))\n", key_type == KSM_TYPE_KSK ? "KSK" : "ZSK", zone_name, new_keys, keys_needed, keys_in_queue, keys_pending_retirement); */

    /* Allocate keys */
    for (i=0 ; i < new_keys ; i++){
        key_pair_id = 0;
        if (key_type == KSM_TYPE_KSK) {
            status = KsmKeyGetUnallocated(policy->id, policy->ksk->sm, policy->ksk->bits, policy->ksk->algorithm, zone_id, policy->keys->share_keys, &key_pair_id);
            if (status == -1 || key_pair_id == 0) {
                if (man_key_gen == 0) {
                    printf("Not enough keys to satisfy ksk policy for zone: %s. keys_to_allocate(%d) = keys_needed(%d) - (keys_available(%d) - keys_pending_retirement(%d))\n", zone_name, new_keys, keys_needed, keys_in_queue, keys_pending_retirement);
					printf("Tried to allocate %d keys, failed on allocating key number %d", new_keys, i+1);
                   	printf("ods-enforcerd will create some more keys on its next run");
                }
                else {
                    printf("Not enough keys to satisfy ksk policy for zone: %s. keys_to_allocate(%d) = keys_needed(%d) - (keys_available(%d) - keys_pending_retirement(%d))\n", zone_name, new_keys, keys_needed, keys_in_queue, keys_pending_retirement);
					printf("Tried to allocate %d keys, failed on allocating key number %d", new_keys, i+1);
                    printf("please use \"ods-ksmutil key generate\" to create some more keys.");
                }
                return 2;
            }
            else if (status != 0) {
                printf("Could not get an unallocated ksk for zone: %s", zone_name);
                return 3;
            }
        } else {
            status = KsmKeyGetUnallocated(policy->id, policy->zsk->sm, policy->zsk->bits, policy->zsk->algorithm, zone_id, policy->keys->share_keys, &key_pair_id);
            if (status == -1 || key_pair_id == 0) {
                if (man_key_gen == 0) {
                    printf("Not enough keys to satisfy zsk policy for zone: %s. keys_to_allocate(%d) = keys_needed(%d) - (keys_available(%d) - keys_pending_retirement(%d))\n", zone_name, new_keys, keys_needed, keys_in_queue, keys_pending_retirement);
					printf("Tried to allocate %d keys, failed on allocating key number %d", new_keys, i+1);
                    printf("ods-enforcerd will create some more keys on its next run");
                }
                else {
                    printf("Not enough keys to satisfy zsk policy for zone: %s. keys_to_allocate(%d) = keys_needed(%d) - (keys_available(%d) - keys_pending_retirement(%d))\n", zone_name, new_keys, keys_needed, keys_in_queue, keys_pending_retirement);
					printf("Tried to allocate %d keys, failed on allocating key number %d", new_keys, i+1);
                    printf("please use \"ods-ksmutil key generate\" to create some more keys.");
                }
                return 2;
            }
            else if (status != 0) {
                printf("Could not get an unallocated zsk for zone: %s", zone_name);
                return 3;
            }
        }
        if(key_pair_id > 0) {
            status = KsmDnssecKeyCreate(zone_id, key_pair_id, key_type,
                KSM_STATE_GENERATE, policy->ksk->rfc5011, datetime,
                NULL, &ignore);
            /* fprintf(stderr, "comm(%d) %s: allocated keypair id %d\n", key_type, zone_name, key_pair_id); */
        } else {
            /* This shouldn't happen */
            printf("KsmKeyGetUnallocated returned bad key_id %d for zone: %s; exiting...", key_pair_id, zone_name);
            exit(1);
        }
    }
	printf("%s key allocation for zone %s: %d key(s) allocated\n", key_type == KSM_TYPE_KSK ? "KSK" : "ZSK", zone_name, new_keys);

    return status;
}


/* keyRoll
 *
 * Description:
 *      Rolls keys far enough for the enforcer to take over
 *
 * Arguments:
 *      zone_id
 *          ID of zone in question (-1 == all)
 *      policy_id
 *          policy that should be rolled (-1 == all)
 *      key_type
 *          KSK or ZSK (-1 == all)
 *
 * Returns:
 *      int
 *          Status return.  0=> Success, non-zero => error.
 -*/

int keyRoll(int zone_id, int policy_id, int key_type)
{

    int status = 0;
    int size = -1;

    char*       sql = NULL;     /* SQL query */
    char*       sql1 = NULL;    /* SQL query */
    char        sql2[KSM_SQL_SIZE];
    DB_RESULT	result1;        /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */
    int         temp_id = -1;   /* place to store the key id returned */
    int         temp_type = -1; /* place to store the key type returned */
    int         temp_zone_id = -1;   /* place to store the zone id returned */
    int         where = 0;
    int         j = 0;
    DB_RESULT	result2;        /* Result of the query */
    DB_RESULT	result3;        /* Result of the query */
    DB_ROW      row2 = NULL;    /* Row data */
    char*       insql1 = NULL;  /* SQL query */
    char*       insql2 = NULL;  /* SQL query */
    char        buffer[32];     /* For integer conversion */
    
    char*   datetime = DtParseDateTimeString("now");

    /* Check datetime in case it came back NULL */
    if (datetime == NULL) {
        printf("Couldn't turn \"now\" into a date, quitting...\n");
        StrFree(datetime);
        exit(1);
    }

    /* retire the active key(s) */
    /* Find the key ID */
    sql = DqsSpecifyInit("KEYDATA_VIEW","id, keytype");
    if (zone_id != -1) {
        DqsConditionInt(&sql, "zone_id", DQS_COMPARE_EQ, zone_id, where++);
    }
    if (policy_id != -1) {
        DqsConditionInt(&sql, "policy_id", DQS_COMPARE_EQ, policy_id, where++);
    }
    DqsConditionInt(&sql, "state", DQS_COMPARE_EQ, KSM_STATE_ACTIVE, where++);
    if (key_type != -1) {
        DqsConditionInt(&sql, "keytype", DQS_COMPARE_EQ, key_type, where++);
    }
    DqsEnd(&sql);

    status = DbExecuteSql(DbHandle(), sql, &result1);

    if (status == 0) {
        status = DbFetchRow(result1, &row);
        while (status == 0) {
            /* Got a row, deal with it */
            DbInt(row, 0, &temp_id);
            DbInt(row, 1, &temp_type);

            sql1 = DusInit("keypairs");
            DusSetInt(&sql1, "fixedDate", 1, 0);
            DusSetInt(&sql1, "compromisedflag", 1, 1);

            DusConditionInt(&sql1, "id", DQS_COMPARE_EQ, temp_id, 0);
            DusEnd(&sql1);
            status = DbExecuteSqlNoResult(DbHandle(), sql1);
            DusFree(sql1);

            /* Report any errors */
            if (status != 0) {
                printf("SQL failed: %s\n", DbErrmsg(DbHandle()));
                DbFreeRow(row);
                return status;
            }

            /* Loop over instances of this key: */
            /* active-> set retire time */
            sql1 = DusInit("dnsseckeys");
            DusSetString(&sql1, "RETIRE", datetime, 0);

            DusConditionInt(&sql1, "keypair_id", DQS_COMPARE_EQ, temp_id, 0);
            DusConditionInt(&sql1, "state", DQS_COMPARE_EQ, KSM_STATE_ACTIVE, 1);
            DusEnd(&sql1);
            status = DbExecuteSqlNoResult(DbHandle(), sql1);
            DusFree(sql1);

            /* Report any errors */
            if (status != 0) {
                printf("SQL failed: %s\n", DbErrmsg(DbHandle()));
                DbFreeRow(row);
                return status;
            }

            /* other-> move to dead */
            sql1 = DusInit("dnsseckeys");
            DusSetString(&sql1, "DEAD", datetime, 0);
            DusSetInt(&sql1, "state", KSM_STATE_DEAD, 1);

            DusConditionInt(&sql1, "keypair_id", DQS_COMPARE_EQ, temp_id, 0);
            DusConditionInt(&sql1, "state", DQS_COMPARE_NE, KSM_STATE_ACTIVE, 1);
            DusEnd(&sql1);
            status = DbExecuteSqlNoResult(DbHandle(), sql1);
            DusFree(sql1);

            /* Report any errors */
            if (status != 0) {
                printf("SQL failed: %s\n", DbErrmsg(DbHandle()));
                DbFreeRow(row);
                return status;
            }
           
            /* Promote any standby keys if we need to, i.e. we retired a KSK 
               and there is nothing able to take over from it */
            if (temp_type == KSM_TYPE_KSK) {
                /* find each zone in turn */
                /* Depressingly MySQL can't run the following sql; so we need 
                   to build it by parts... There has to be a better way to do 
                   this.
                size = snprintf(sql2, KSM_SQL_SIZE, "update dnsseckeys set state = %d where state = %d and zone_id in (select zone_id from dnsseckeys where retire = \"%s\" and keypair_id = %d) and zone_id not in (select zone_id from KEYDATA_VIEW where policy_id = %d and keytype = %d and state in (%d,%d))", KSM_STATE_KEYPUBLISH, KSM_STATE_DSREADY, datetime, temp_id, policy_id, KSM_TYPE_KSK, KSM_STATE_PUBLISH, KSM_STATE_READY); */

                /* First INSQL: select zone_id from dnsseckeys where retire = "DATETIME" and keypair_id = temp_id*/

                size = snprintf(sql2, KSM_SQL_SIZE, "select zone_id from dnsseckeys where retire = \"%s\" and keypair_id = %d", datetime, temp_id);
                status = DbExecuteSql(DbHandle(), sql2, &result2);
                if (status == 0) {
                    status = DbFetchRow(result2, &row2);
                    while (status == 0) {
                        /* Got a row, print it */
                        DbInt(row2, 0, &temp_zone_id);

                        if (j != 0) {
                            StrAppend(&insql1, ",");
                        }
                        snprintf(buffer, sizeof(buffer), "%d", temp_zone_id);
                        StrAppend(&insql1, buffer);
                        j++;

                        status = DbFetchRow(result2, &row2);
                    }

                    /* Convert EOF status to success */

                    if (status == -1) {
                        status = 0;
                    }

                    DbFreeResult(result2);
                }

                /* Second INSQL: select zone_id from KEYDATA_VIEW where policy_id = policy_id and keytype = KSK and state in (publish,ready) */

                size = snprintf(sql2, KSM_SQL_SIZE, "select zone_id from KEYDATA_VIEW where policy_id = %d and keytype = %d and state in (%d,%d)", policy_id, KSM_TYPE_KSK, KSM_STATE_PUBLISH, KSM_STATE_READY);
                j=0;
                status = DbExecuteSql(DbHandle(), sql2, &result3);
                if (status == 0) {
                    status = DbFetchRow(result3, &row2);
                    while (status == 0) {
                        /* Got a row, print it */
                        DbInt(row2, 0, &temp_zone_id);

                        if (j != 0) {
                            StrAppend(&insql2, ",");
                        }
                        snprintf(buffer, sizeof(buffer), "%d", temp_zone_id);
                        StrAppend(&insql2, buffer);
                        j++;

                        status = DbFetchRow(result3, &row2);
                    }

                    /* Convert EOF status to success */

                    if (status == -1) {
                        status = 0;
                    }

                    DbFreeResult(result3);
                }
                DbFreeRow(row2);

                /* Finally we can do the update */
                size = snprintf(sql2, KSM_SQL_SIZE, "update dnsseckeys set state = %d where state = %d and zone_id in (%s) and zone_id not in (%s)", KSM_STATE_KEYPUBLISH, KSM_STATE_DSREADY, insql1, insql2);

                /* Quick check that we didn't run out of space */
                if (size < 0 || size >= KSM_SQL_SIZE) {
                    printf("Couldn't construct SQL to promote standby key\n");
					StrFree(datetime);
					DbFreeRow(row);
					DqsFree(sql);
					DqsFree(insql1);
					DqsFree(insql2);
                    return -1;
                }

                status = DbExecuteSqlNoResult(DbHandle(), sql2);

                /* Report any errors */
                if (status != 0) {
                    printf("SQL failed: %s\n", DbErrmsg(DbHandle()));
					StrFree(datetime);
					DbFreeRow(row);
					DqsFree(sql);
					DqsFree(insql1);
					DqsFree(insql2);
                    return status;
                }
            }

            /* NEXT KEY */ 
            status = DbFetchRow(result1, &row);
        }

        /* Convert EOF status to success */
        if (status == -1) {
            status = 0;
        }
        DbFreeResult(result1);
    }
    DqsFree(sql);
    DbFreeRow(row);

    StrFree(datetime);
    
    return status;
}

int get_policy_name_from_id(KSM_ZONE *zone)
{
    int     where = 0;          /* WHERE clause value */
    char*   sql = NULL;         /* SQL query */
    DB_RESULT       result;     /* Handle converted to a result object */
    DB_ROW      row = NULL;            /* Row data */
    int     status = 0;         /* Status return */

    /* Construct the query */

    sql = DqsSpecifyInit("policies","id, name");
    DqsConditionInt(&sql, "ID", DQS_COMPARE_EQ, zone->policy_id, where++);
    DqsOrderBy(&sql, "id");

    /* Execute query and free up the query string */
    status = DbExecuteSql(DbHandle(), sql, &result);
    DqsFree(sql);
    
    if (status != 0)
    {
        printf("SQL failed: %s\n", DbErrmsg(DbHandle()));
        DbFreeResult(result);
        return status;
	}

    /* Get the next row from the data */
    status = DbFetchRow(result, &row);
    if (status == 0) {
        DbStringBuffer(row, DB_POLICY_NAME, zone->policy_name, KSM_NAME_LENGTH*sizeof(char));
    }
    else if (status == -1) {}
        /* No rows to return (but no error) */
	else {
        printf("SQL failed: %s\n", DbErrmsg(DbHandle()));
        return status;
	}

    DbFreeRow(row);
    DbFreeResult(result);
    return status;
}

int append_zone(xmlDocPtr doc, KSM_ZONE *zone)
{
    xmlNodePtr root;
    xmlNodePtr zone_node;
    xmlNodePtr adapters_node;
    xmlNodePtr input_node;
    xmlNodePtr in_ad_node;
    xmlNodePtr output_node;
    xmlNodePtr out_ad_node;

    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        fprintf(stderr,"empty document\n");
        return(1);
    }
    if (xmlStrcmp(root->name, (const xmlChar *) "ZoneList")) {
        fprintf(stderr,"document of the wrong type, root node != %s", "ZoneList");
        return(1);
    }

    zone_node = xmlNewTextChild(root, NULL, (const xmlChar *)"Zone", NULL);
    (void) xmlNewProp(zone_node, (const xmlChar *)"name", (const xmlChar *)zone->name);

    /* Policy */
    (void) xmlNewTextChild(zone_node, NULL, (const xmlChar *)"Policy", (const xmlChar *)zone->policy_name);

    /* SignConf */
    (void) xmlNewTextChild(zone_node, NULL, (const xmlChar *)"SignerConfiguration", (const xmlChar *)zone->signconf);

    /* Adapters */
    adapters_node = xmlNewTextChild(zone_node, NULL, (const xmlChar *)"Adapters", NULL);
    /* Input */
    input_node = xmlNewTextChild(adapters_node, NULL, (const xmlChar *)"Input", NULL);
    in_ad_node = xmlNewTextChild (input_node, NULL, (const xmlChar *)"Adapter", (const xmlChar *)zone->input);
	/* Default type is "File" */
	if (zone->in_type[0] == '\0') { /* Default to "File" */
		(void) xmlNewProp(in_ad_node, (const xmlChar *)"type", (const xmlChar *)"File");
	} else {
		(void) xmlNewProp(in_ad_node, (const xmlChar *)"type", (const xmlChar *)zone->in_type);
	}

    /* Output */
    output_node = xmlNewTextChild(adapters_node, NULL, (const xmlChar *)"Output", NULL);
    out_ad_node = xmlNewTextChild (output_node, NULL, (const xmlChar *)"Adapter", (const xmlChar *)zone->output);
	/* Default type is "File" */
	if (zone->out_type[0] == '\0') {
		(void) xmlNewProp(out_ad_node, (const xmlChar *)"type", (const xmlChar *)"File");
	} else {
		(void) xmlNewProp(out_ad_node, (const xmlChar *)"type", (const xmlChar *)zone->out_type);
	}

    return(0);
}

int ShellQuoteString(const char* string, char* buffer, size_t buflen)
{
    size_t i;           /* Loop counter */
    size_t j = 0;       /* Counter for new string */
	
	size_t len = 0;

    if (string) {
		len = strlen(string);

        for (i = 0; i < len; ++i) {
            if (string[i] == '\'') {
                buffer[j++] = '\'';
                buffer[j++] = '\\';
                buffer[j++] = '\'';
            }
			buffer[j++] = string[i];
        }
    }
	buffer[j] = '\0';
    return ( (j <= buflen) ? 0 : 1);
}

int rename_signconf(const char* zonelist_filename, const char* o_zone) {
	int status = 0;
	char* signconf = NULL;
	char* moved_signconf = NULL;
	char* zone_name = NULL;
	int i = 0;
	
	/* All of the XML stuff */
    xmlDocPtr doc = NULL;
    xmlNode *curNode;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;

	xmlChar *node_expr = (unsigned char*) "//Zone";
/* Load XML document */
    doc = xmlParseFile(zonelist_filename);
    if (doc == NULL) {
        printf("Error: unable to parse file \"%s\"\n", zonelist_filename);
        return(-1);
    }
/* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        xmlFreeDoc(doc);
        return(1);
    }

	/* Evaluate xpath expression */
    xpathObj = xmlXPathEvalExpression(node_expr, xpathCtx);
    if(xpathObj == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return(1);
    }

	if (xpathObj->nodesetval) {
        for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {

            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            zone_name = (char *) xmlGetProp(xpathObj->nodesetval->nodeTab[i], (const xmlChar *)"name");

			if (all_flag || (strlen(zone_name) == strlen(o_zone) &&
					strncmp(zone_name, o_zone, strlen(zone_name)) == 0)) {
				
				while (curNode) {

					if (xmlStrEqual(curNode->name, (const xmlChar *)"SignerConfiguration")) {
						StrAppend(&signconf, (char *) xmlNodeGetContent(curNode));
						StrAppend(&moved_signconf, signconf);
						StrAppend(&moved_signconf, ".ZONE_DELETED");
						/* Do the move */
						status = rename(signconf, moved_signconf);
						if (status != 0 && errno != ENOENT)
						{
							/* cope with initial condition of files not existing */
							printf("Could not rename: %s -> %s", signconf, moved_signconf);
							StrFree(signconf);
							StrFree(moved_signconf);
							return(1);
						}
						StrFree(signconf);
						StrFree(moved_signconf);
						break;
					}

					curNode = curNode->next;
				}

				if (!all_flag) {
					break;
				}
			}
		}
	}
	
	return 0;
}

/*+
 * ListDS - List DS records currently involved with rollovers
 *
 *
 * Arguments:
 *
 *      int zone_id
 *          -1 for all zones
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int ListDS(int zone_id) {

	int 		status = 0;
	char* 		sql = NULL;
    char        stringval[KSM_INT_STR_SIZE];  /* For Integer to String conversion */
    DB_RESULT	result;         /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */

    char*       temp_zone = NULL;   	/* place to store zone name returned */
    int         temp_policy = 0;    	/* place to store policy id returned */
    char*       temp_location = NULL;   /* place to store location returned */
    int         temp_algo = 0;     		/* place to store algorithm returned */
	
	int 		rrttl = -1;				/* TTL to put into DS record */
	int 		param_id = -1; 			/* unused */

	/* Key information */
    hsm_key_t *key = NULL;
    ldns_rr *dnskey_rr = NULL;
    hsm_sign_params_t *sign_params = NULL;
	int			i = 0;

	/* Output strings */
    char*   ds_buffer = NULL;   /* Contents of DS records */
    hsm_ctx_t* ctx;

	/* connect to the HSM */
	status = hsm_open(config, hsm_prompt_pin);
	if (status) {
		hsm_print_error(NULL);
		return(1);
	}
        ctx = hsm_create_context();

	StrAppend(&sql,
			"select name, kv.policy_id, location, algorithm from KEYDATA_VIEW kv, zones z where keytype = 257 and state in (3,7) and zone_id = z.id ");
	if (zone_id != -1) {
		StrAppend(&sql, "and zone_id = ");
		snprintf(stringval, KSM_INT_STR_SIZE, "%d", zone_id);
		StrAppend(&sql, stringval);
	}
	StrAppend(&sql, " order by zone_id");

	DusEnd(&sql);

	status = DbExecuteSql(DbHandle(), sql, &result);

	if (status == 0) {
		status = DbFetchRow(result, &row);
        while (status == 0) {
            /* Got a row, print it */
            DbString(row, 0, &temp_zone);
            DbInt(row, 1, &temp_policy);
            DbString(row, 2, &temp_location);
            DbInt(row, 3, &temp_algo);

			/* Code to output the DNSKEY record  (stolen from hsmutil) */
			key = hsm_find_key_by_id(ctx, temp_location);

            if (!key) {
                printf("Key %s in DB but not repository.", temp_location);
				DbFreeRow(row);
				DbStringFree(temp_location);
				DbStringFree(temp_zone);
                StrFree(sql);
                                hsm_destroy_context(ctx);
				hsm_close();
                return status;
            }

			printf("\n*** Found DNSKEY RECORD involved with rollover:\n");

            sign_params = hsm_sign_params_new();
            sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, temp_zone);
            sign_params->algorithm = temp_algo;
            sign_params->flags = LDNS_KEY_ZONE_KEY;
            sign_params->flags += LDNS_KEY_SEP_KEY;
            dnskey_rr = hsm_get_dnskey(ctx, key, sign_params);

			/* Use this to get the TTL parameter value */
			status = KsmParameterValue(KSM_PAR_KSKTTL_STRING, KSM_PAR_KSKTTL_CAT, &rrttl, temp_policy, &param_id);
			if (status == 0) {
				ldns_rr_set_ttl(dnskey_rr, rrttl);
			}

            ds_buffer = ldns_rr2str(dnskey_rr);
            ldns_rr_free(dnskey_rr);

            /* Replace tab with white-space */
            for (i = 0; ds_buffer[i]; ++i) {
                if (ds_buffer[i] == '\t') {
                    ds_buffer[i] = ' ';
                }
            }

			/* Print it */
            printf("%s", ds_buffer);
			printf("\nOnce the DS record for this DNSKEY is seen in DNS you can issue the ds-seen command for zone %s with the cka_id %s\n", temp_zone, temp_location);

            StrFree(ds_buffer);
			DbStringFree(temp_location);
			DbStringFree(temp_zone);
            temp_location = NULL;
            temp_zone = NULL;

            hsm_sign_params_free(sign_params);
            hsm_key_free(key);

            status = DbFetchRow(result, &row);
		}
		/* Convert EOF status to success */
        if (status == -1) {
            status = 0;
        }

	}

	DbFreeRow(row);
    StrFree(sql);
        hsm_destroy_context(ctx);
	hsm_close();

	return status;
}
