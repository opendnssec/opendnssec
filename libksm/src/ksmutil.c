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

#include <ksm/ksmutil.h>
#include <ksm/ksm.h>
#include <ksm/config.h>
#include <ksm/database.h>
#include <ksm/datetime.h>
#include <ksm/string_util.h>
#include <ksm/string_util2.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>
#include <libxml/xmlreader.h>

/* Some value type flags */
#define INT_TYPE 0
#define DURATION_TYPE 1
#define BOOL_TYPE 2
#define STR_BOOL_TYPE 3
#define REPO_TYPE 4
#define SERIAL_TYPE 5

extern char *optarg;
char *progname = "ksmutil";
char *config = (char *) CONFIGDIR;

void
usage_setup ()
{
    fprintf(stderr,
        "usage: %s [-f config_dir] setup [path_to_kasp.xml]\n\tImport config_dir into a database (deletes current contents)\n",
        progname);
}

void
usage_update ()
{
    fprintf(stderr,
        "usage: %s [-f config_dir] update [path_to_kasp.xml]\n\tUpdate database from config_dir\n",
        progname);
}

void
usage_addzone ()
{
    fprintf(stderr,
        "usage: %s [-f config_dir] addzone zone [policy] [path_to_signerconf.xml] [input] [output]\n\tAdd a zone to the config_dir and database\n",
        progname);
}

void
usage_delzone ()
{
    fprintf(stderr,
        "usage: %s [-f config_dir] delzone zone\n\tDelete a zone from the config_dir and database\n",
        progname);
}

void
usage_rollzone ()
{
    fprintf(stderr,
        "usage: %s [-f config_dir] rollzone zone [KSK|ZSK]\n\tRollover a zone (may roll all zones on that policy)\n",
        progname);
}

void
usage_rollpolicy ()
{
    fprintf(stderr,
        "usage: %s [-f config_dir] rollpolicy policy [KSK|ZSK]\n\tRollover all zones on a policy\n",
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

/* 
 * Do initial import of config files into database
 */
int
cmd_setup (int argc, char *argv[])
{

    /* TODO put an "are you sure?" here */
    printf("command not yet implemented\n");
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
    int status = 0;

    /* try to connect to the database */
    status = db_connect(&dbhandle, &lock_fd, &lock_filename);
    if (status != 0) {
        printf("Failed to connect to database\n");
        return(1);
    }

    /* 
     *  Now we will read the conf.xml file again, but this time we will not validate.
     *  Instead we just extract the RepositoryList into the database and also learn the 
     *  location of the zonelist.
     */
    status = update_repositories(&zone_list_filename);
    if (status != 0) {
        printf("Failed to update repositories\n");
        return(1);
    }

    /*
     * Now read the kasp.xml which should be in the same directory.
     * This lists all of the policies.
     */
    status = update_policies();
    if (status != 0) {
        printf("Failed to update policies\n");
        return(1);
    }

    /*
     * Take the zonelist we learnt above and read it, updating or inserting zone records
     * in the database as we go.
     */
    status = update_zones(zone_list_filename);
    if (status != 0) {
        printf("Failed to update zones\n");
        return(1);
    }

    /* Release sqlite lock file (if we have it) */
    if (DbFlavour() == SQLITE_DB) {
        status = release_lite_lock(lock_fd);
        if (status != 0) {
            printf("Error releasing db lock");
            return(1);
        }
        fclose(lock_fd);
    }

    return 0;
}

/* 
 * Add a zone to the config and database
 */
int
cmd_addzone (int argc, char *argv[])
{
    printf("command not yet implemented\n");
    return 0;
}

/*
 * Delete a zone from the config and database
 */
int
cmd_delzone (int argc, char *argv[])
{
    printf("command not yet implemented\n");
    return 0;
}

/*
 * To rollover a zone (or all zones on a policy if keys are shared)
 */
int
cmd_rollzone (int argc, char *argv[])
{
    printf("command not yet implemented\n");
    return 0;
}

/*
 * To rollover all zones on a policy
 */
int
cmd_rollpolicy (int argc, char *argv[])
{
    printf("command not yet implemented\n");
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

    if (!strncasecmp(argv[0], "setup", 5)) {
        argc --;
        argv ++;
        result = cmd_setup(argc, argv);
    } else if (!strncasecmp(argv[0], "update", 6)) {
        argc --;
        argv ++;
        result = cmd_update(argc, argv);
    } else if (!strncasecmp(argv[0], "addzone", 7)) {
        argc --;
        argv ++;
        result = cmd_addzone(argc, argv);
    } else if (!strncasecmp(argv[0], "delzone", 7)) {
        argc --;
        argv ++;
        result = cmd_delzone(argc, argv);
    } else if (!strncasecmp(argv[0], "rollzone", 8)) {
        argc --;
        argv ++;
        result = cmd_rollzone(argc, argv);
    } else if (!strncasecmp(argv[0], "rollpolicy", 10)) {
        argc --;
        argv ++;
        result = cmd_rollpolicy(argc, argv);
    } else {
        printf("Unknown command: %s\n", argv[0]);
        usage();
        result = -1;
    }

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

    /* Some files, the xml and rng */
    char* filename = NULL;
    char* rngfilename = NULL;

    StrAppend(&filename, config);
    StrAppend(&filename, "/conf.xml");

    StrAppend(&rngfilename, config);
    StrAppend(&rngfilename, "/conf.rng");

    /* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        printf("Error: unable to parse file \"%s\"\n", filename);
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
        printf("Error validating file \"%s\"\n", filename);
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

    if(*xmlXPathCastToString(xpathObj) != '\0') {
        db_found = SQLITE_DB;
		    dbschema = StrStrdup( (char *)xmlXPathCastToString(xpathObj) );
		    printf("SQLite database set to: %s\n", dbschema);
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
		    if( *xmlXPathCastToString(xpathObj) != '\0') {
           db_found = MYSQL_DB;
        }
        host = StrStrdup( (char *)xmlXPathCastToString(xpathObj) );
        printf("MySQL database host set to: %s\n", host);

        /* PORT */
        xpathObj = xmlXPathEvalExpression(mysql_port, xpathCtx);
        if(xpathObj == NULL) {
		        printf("Error: unable to evaluate xpath expression: %s\n", mysql_port);
		        xmlXPathFreeContext(xpathCtx);
		        xmlFreeDoc(doc);
		        return(-1);
		    }
		    if( *xmlXPathCastToString(xpathObj) == '\0') {
            db_found = 0;
        }
        port = StrStrdup( (char *)xmlXPathCastToString(xpathObj) );
        printf("MySQL database port set to: %s\n", port);

        /* SCHEMA */
        xpathObj = xmlXPathEvalExpression(mysql_db, xpathCtx);
        if(xpathObj == NULL) {
		        printf("Error: unable to evaluate xpath expression: %s\n", mysql_db);
		        xmlXPathFreeContext(xpathCtx);
		        xmlFreeDoc(doc);
		        return(-1);
		    }
		    if( *xmlXPathCastToString(xpathObj) == '\0') {
            db_found = 0;
        }
        dbschema = StrStrdup( (char *)xmlXPathCastToString(xpathObj) );
        printf("MySQL database schema set to: %s\n", dbschema);

        /* DB USER */
        xpathObj = xmlXPathEvalExpression(mysql_user, xpathCtx);
        if(xpathObj == NULL) {
		        printf("Error: unable to evaluate xpath expression: %s\n", mysql_user);
		        xmlXPathFreeContext(xpathCtx);
		        xmlFreeDoc(doc);
		        return(-1);
		    }
		    if( *xmlXPathCastToString(xpathObj) == '\0') {
            db_found = 0;
        }
        user = StrStrdup( (char *)xmlXPathCastToString(xpathObj) );
        printf("MySQL database user set to: %s\n", user);

        /* DB PASSWORD */
        xpathObj = xmlXPathEvalExpression(mysql_pass, xpathCtx);
        if(xpathObj == NULL) {
		        printf("Error: unable to evaluate xpath expression: %s\n", mysql_pass);
		        xmlXPathFreeContext(xpathCtx);
		        xmlFreeDoc(doc);
		        return(-1);
		    }
		    /* password may be blank */
        
        password = StrStrdup( (char *)xmlXPathCastToString(xpathObj) );
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
            return(1);
        }
    }

    /* Finally we can do what we came here to do, connect to the database */
    status = DbConnect(dbhandle, dbschema, host, password, user);
    
    /* Cleanup */
    /* TODO: some other frees are needed */
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);
    xmlRelaxNGFree(schema);
    xmlRelaxNGFreeValidCtxt(rngctx);
    xmlRelaxNGFreeParserCtxt(rngpctx);
    xmlFreeDoc(rngdoc);

    return(status);
}

/* To overcome the potential differences in sqlite compile flags assume that it is not
   happy with multiple connections.

   The following 2 functions take out a lock and release it
*/

int get_lite_lock(char *lock_filename, FILE* lock_fd)
{
    struct flock fl = { F_WRLCK, SEEK_SET, 0,       0,     0 };
    struct timeval tv;
  
    fl.l_pid = getpid();
    
    while (fcntl(fileno(lock_fd), F_SETLK, &fl) == -1) {
        if (errno == EACCES || errno == EAGAIN) {
            printf("%s already locked, sleep\n", lock_filename);

            /* sleep for 10 seconds TODO make this configurable? */
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            select(0, NULL, NULL, NULL, &tv);

        } else {
            printf("couldn't get lock on %s, error\n", lock_filename);
            return 1;
        }
    }

    return 0;

}

int release_lite_lock(FILE* lock_fd)
{
    struct flock fl = { F_UNLCK, SEEK_SET, 0,       0,     0 };

    if (lock_fd == NULL) {
        return 1;
    }
    
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
int update_repositories(char** zone_list_filename)
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

    xmlChar *name_expr = (unsigned char*) "name";
    xmlChar *capacity_expr = (unsigned char*) "//Repository/Capacity";
    xmlChar *zonelist_expr = (unsigned char*) "//Signer/ZoneListFile";

    StrAppend(&filename, config);
    StrAppend(&filename, "/conf.xml");
    /* Start reading the file; we will be looking for "Repository" tags */ 
    reader = xmlNewTextReaderFilename(filename);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            /* Found <Repository> */
            if (strncmp((char*) xmlTextReaderLocalName(reader), "Repository", 10) == 0 
                    && strncmp((char*) xmlTextReaderLocalName(reader), "RepositoryList", 14) != 0
                    && xmlTextReaderNodeType(reader) == 1) {
                /* Get the repository name */
                repo_name = NULL;
                StrAppend(&repo_name, (char*) xmlTextReaderGetAttribute(reader, name_expr));
                /* Make sure that we got something */
                if (repo_name == NULL) {
                    /* error */
                    printf("Error extracting repository name from %s\n", filename);
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
                StrAppend(&repo_capacity, (char*) xmlXPathCastToString(xpathObj));
                printf("Capacity set to %s.\n", repo_capacity);

                /*
                 * Now we have all the information update/insert this repository
                 */
                status = KsmImportRepository(repo_name, repo_capacity);
                if (status != 0) {
                    printf("Error Importing Repository %s", repo_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
            }
            /* Found <Signer> */
            else if (strncmp((char*) xmlTextReaderLocalName(reader), "Signer", 6) == 0 
                    && strncmp((char*) xmlTextReaderLocalName(reader), "SignerThreads", 13) != 0
                    && xmlTextReaderNodeType(reader) == 1) {

                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                doc = xmlTextReaderCurrentDoc(reader);
                if (doc == NULL) {
                    printf("Error: can not read Signer section\n");
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                xpathCtx = xmlXPathNewContext(doc);
                if(xpathCtx == NULL) {
                    printf("Error: can not create XPath context for Signer section\n");
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
                StrAppend(zone_list_filename, (char*) xmlXPathCastToString(xpathObj));
                printf("zonelist filename set to %s.\n", *zone_list_filename);
            }
            /* Read the next line */
            ret = xmlTextReaderRead(reader);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            printf("%s : failed to parse\n", filename);
        }
    } else {
        printf("Unable to open %s\n", filename);
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
int update_policies()
{
    int status;

    /* what we will read from the file */
    char *policy_name;
    char *policy_description;

    /* All of the XML stuff */
    int ret = 0; /* status of the XML parsing */
    xmlDocPtr doc = NULL;
    xmlDocPtr rngdoc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlRelaxNGParserCtxtPtr rngpctx = NULL;
    xmlRelaxNGValidCtxtPtr rngctx = NULL;
    xmlRelaxNGPtr schema = NULL;
    xmlTextReaderPtr reader = NULL;

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
    
    KSM_POLICY *policy;

    /* Some files, the xml and rng */
    char* filename = NULL;
    char* rngfilename = NULL;

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
    policy->name = (char *)calloc(KSM_NAME_LENGTH, sizeof(char));
    /* Let's check all of those mallocs, or should we use MemMalloc ? */
    if (policy->signer == NULL || policy->signature == NULL || policy->keys == NULL ||
            policy->zone == NULL || policy->parent == NULL || 
            policy->ksk == NULL || policy->zsk == NULL || 
            policy->denial == NULL || policy->enforcer == NULL) {
        printf("Malloc for policy struct failed\n");
        exit(1);
    }

    StrAppend(&filename, config);
    StrAppend(&filename, "/kasp.xml");

    StrAppend(&rngfilename, config);
    StrAppend(&rngfilename, "/kasp.rng");

    /* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        printf("Error: unable to parse file \"%s\"\n", filename);
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
        printf("Error validating file \"%s\"\n", filename);
        return(-1);
    }

    /* Switch to the XmlTextReader API so that we can consider each policy separately */
    reader = xmlNewTextReaderFilename(filename);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            /* Found <Policy> */
            if (strncmp((char*) xmlTextReaderLocalName(reader), "Policy", 6) == 0 
                    && xmlTextReaderNodeType(reader) == 1) {
                /* Get the policy name */
                policy_name = NULL;
                StrAppend(&policy_name, (char*) xmlTextReaderGetAttribute(reader, name_expr));
                /* Make sure that we got something */
                if (policy_name == NULL) {
                    /* error */
                    printf("Error extracting policy name from %s\n", filename);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                printf("Policy %s found\n", policy_name);

                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                doc = xmlTextReaderCurrentDoc(reader);
                if (doc == NULL) {
                    printf("Error: can not read policy \"%s\"; skipping\n", policy_name);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                xpathCtx = xmlXPathNewContext(doc);
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
                StrAppend(&policy_description, (char*) xmlXPathCastToString(xpathObj));

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
                        return status;
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
                        return status;
                    }
                }

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
                if ( SetParamOnPolicy(xpathCtx, keys_share_expr, "zones_share_keys", "keys", policy->keys->share_keys, policy->id, STR_BOOL_TYPE) != 0) {
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

            } /* End of <Policy> */
            /* Read the next line */
            ret = xmlTextReaderRead(reader);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            printf("%s : failed to parse\n", filename);
        }
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

    free(policy->enforcer);
	free(policy->denial);
	free(policy->keys);
	free(policy->zsk);
	free(policy->ksk);
	free(policy->signature);
	free(policy->signer);
	free(policy);

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
    int policy_id = 0;

    xmlChar *name_expr = (unsigned char*) "name";
    xmlChar *policy_expr = (unsigned char*) "//Zone/Policy";

    /* TODO validate the file ? */

    /* Start reading the file; we will be looking for "Repository" tags */ 
    reader = xmlNewTextReaderFilename(zone_list_filename);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            /* Found <Zone> */
            if (strncmp((char*) xmlTextReaderLocalName(reader), "Zone", 4) == 0 
                    && strncmp((char*) xmlTextReaderLocalName(reader), "ZoneList", 8) != 0
                    && xmlTextReaderNodeType(reader) == 1) {
                /* Get the repository name */
                zone_name = NULL;
                StrAppend(&zone_name, (char*) xmlTextReaderGetAttribute(reader, name_expr));
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
                    if(xpathObj == NULL) {
                        printf("Error: unable to evaluate xpath expression: %s; skipping zone\n", policy_expr);
                        /* Don't return? try to parse the rest of the zones? */
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }

                    policy_name = NULL;
                    StrAppend(&policy_name, (char*) xmlXPathCastToString(xpathObj));
                    printf("Policy set to %s.\n", policy_name);
                    
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
                }
            /* Read the next line */
            ret = xmlTextReaderRead(reader);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            printf("%s : failed to parse\n", zone_list_filename);
        }
    } else {
        printf("Unable to open %s\n", zone_list_filename);
    }
    if (xpathCtx) {
        xmlXPathFreeContext(xpathCtx);
    }
    if (doc) {
        xmlFreeDoc(doc);
    }

    return 0;
}

/* 
 * This encapsulates all of the steps needed to insert/update a parameter value
 * evaluate the xpath expression and try to update the policy value, if it has changed
 */
int SetParamOnPolicy(xmlXPathContextPtr xpathCtx, const xmlChar* xpath_expr, const char* name, const char* category, int current_value, int policy_id, int value_type)
{
    int status = 0;
    int value = 0;
    xmlXPathObjectPtr xpathObj = NULL;

    /* Evaluate xpath expression */
    xpathObj = xmlXPathEvalExpression(xpath_expr, xpathCtx);
    if(xpathObj == NULL) {
        printf("Error: unable to evaluate xpath expression: %s; skipping policy\n", xpath_expr);
        return -1;
    }

    /* extract the value into an int */
    if (value_type == DURATION_TYPE) {
        status = DtXMLIntervalSeconds((char *)xmlXPathCastToString(xpathObj), &value);
        if (status > 0) {
            printf("Error: unable to convert interval %s to seconds, error: %i\n", xmlXPathCastToString(xpathObj), status);
            return status;
        }
        else if (status == -1) {
            printf("Warning: converting %s to seconds may not give what you expect\n", xmlXPathCastToString(xpathObj));
        }
    }
    else if (value_type == BOOL_TYPE) {
        /* Do we have an empty tag or no tag? */
        if (xpathObj->nodesetval->nodeNr > 0) {
            value = 1;
        } else {
            value = 0;
        }
    }
    else if (value_type == STR_BOOL_TYPE) {
        if (strncasecmp((char *)xmlXPathCastToString(xpathObj), "true", 4) == 0) {
            value = 1;
        } else {
            value = 0;
        }
    }
    else if (value_type == REPO_TYPE) {
        /* We need to convert the repository name into an id */
        status = KsmSmIdFromName((char *)xmlXPathCastToString(xpathObj), &value);
        if (status != 0) {
            printf("Error: unable to find repository %s\n", xmlXPathCastToString(xpathObj));
            return status;
        }
    }
    else if (value_type == SERIAL_TYPE) {
        /* We need to convert the repository name into an id */
        status = KsmSerialIdFromName((char *)xmlXPathCastToString(xpathObj), &value);
        if (status != 0) {
            printf("Error: unable to find serial type %s\n", xmlXPathCastToString(xpathObj));
            return status;
        }
    }
    else {
        status = StrStrtoi((char *)xmlXPathCastToString(xpathObj), &value);
        if (status != 0) {
            printf("Error: unable to convert %s to int\n", xmlXPathCastToString(xpathObj));
            return status;
        }
    }

    /* Now update the policy with what we found, if it is different */
    if (value != current_value) {
        status = KsmParameterSet(name, category, value, policy_id);
        if (status != 0) {
            printf("Error: unable to insert/update %s for policy\n", name);
            return status;
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

	if(name) policy->name = name;

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
}
