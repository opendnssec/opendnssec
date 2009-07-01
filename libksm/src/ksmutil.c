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
#include <ksm/string_util.h>
#include <ksm/string_util2.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>
#include <libxml/xmlreader.h>

extern char *optarg;
char *progname = "ksmutil";
char *config = (char *) CONFIGDIR;

void
usage_setup ()
{
    fprintf(stderr,
        "To import config_dir into a database (deletes current contents)\n\tusage: %s [-f config] setup [path_to_kasp.xml]\n",
        progname);
}

void
usage_update ()
{
    fprintf(stderr,
        "To update database from config_dir\n\tusage: %s [-f config] update [path_to_kasp.xml]\n",
        progname);
}

void
usage_addzone ()
{
    fprintf(stderr,
        "To add a zone to the config_dir and database\n\tusage: %s [-f config] addzone zone [policy] [path_to_signerconf.xml] [input] [output]\n",
        progname);
}

void
usage_delzone ()
{
    fprintf(stderr,
        "To delete a zone from the config_dir and database\n\tusage: %s [-f config] delzone zone\n",
        progname);
}

void
usage_rollzone ()
{
    fprintf(stderr,
        "To rollover a zone (may roll all zones on that policy)\n\tusage: %s [-f config_dir] rollzone zone [KSK|ZSK]\n",
        progname);
}

void
usage_rollpolicy ()
{
    fprintf(stderr,
        "To rollover all zones on a policy\n\tusage: %s [-f config_dir] rollpolicy policy [KSK|ZSK]\n",
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
    char *dbschema;
    char *host;
    char *port;
    char *user;
    char *password;
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
                /* Get the repository name (TODO what if this is null?) */
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

int update_policies()
{
    return 0;
}

int update_zones(char* zone_list_filename)
{
    return 0;
}
