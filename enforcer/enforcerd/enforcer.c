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
 *
 */

/* 
 * enforcer.c code implements the server_main
 * function needed by daemon.c
 *
 * The bit that makes the daemon do something useful
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>

#include <libxml/xmlreader.h>
#include <libxml/xpath.h>

#include "config.h"

#include "daemon.h"
#include "daemon_util.h"
#include "enforcer.h"
#include "kaspaccess.h"

#include "ksm/ksm.h"
#include "ksm/memory.h"
#include "ksm/string_util.h"
#include "ksm/string_util2.h"
#include "ksm/datetime.h"

#include "libhsm.h"
#include "libhsmdns.h"

    int
server_init(DAEMONCONFIG *config)
{
    if (config == NULL) {
        log_msg(NULL, LOG_ERR, "Error in server_init, no config provided");
        exit(1);
    }

    /* set the default pidfile if nothing was provided on the command line*/
    if (config->pidfile == NULL) {
        config->pidfile = ENFORCER_PIDFILE;
    }

    return 0;
}

/*
 * Main loop of enforcerd server
 */
    void
server_main(DAEMONCONFIG *config)
{
    DB_RESULT handle;
    DB_HANDLE dbhandle;
    int status = 0;
    struct timeval tv;
    KSM_POLICY *policy;
    int result;
    hsm_ctx_t *ctx = NULL;
    char *hsm_error_message = NULL;

    FILE *lock_fd = NULL;  /* for sqlite file locking */
    char *lock_filename = NULL;

    if (config == NULL) {
        log_msg(NULL, LOG_ERR, "Error in server_main, no config provided");
        exit(1);
    }

    policy = KsmPolicyAlloc();
    if (policy == NULL) {
        log_msg(config, LOG_ERR, "Malloc for policy struct failed");
        unlink(config->pidfile);
        exit(1);
    }
    kaspSetPolicyDefaults(policy, NULL);

    /* Read the config file */
    status = ReadConfig(config , 0);
    if (status != 0) {
        log_msg(config, LOG_ERR, "Error reading config");
        unlink(config->pidfile);
        exit(1);
    }

    /* If we are doing key generation then connect to the hsm */
    if (config->manualKeyGeneration == 0) {
        /* We keep the HSM connection open for the lifetime of the daemon */
        if (config->configfile != NULL) {
            result = hsm_open(config->configfile, hsm_prompt_pin, NULL);
        } else {
            result = hsm_open(CONFIG_FILE, hsm_prompt_pin, NULL);
        }
        if (result) {
            hsm_error_message = hsm_get_error(ctx);
            if (hsm_error_message) {
                log_msg(config, LOG_ERR, hsm_error_message);
                free(hsm_error_message);
            } else {
                /* decode the error code ourselves 
                   TODO find if there is a better way to do this (and can all of these be returned? are there others?) */
                switch (result) {
                    case HSM_ERROR:
                        log_msg(config, LOG_ERR, "hsm_open() result: HSM error");
                        break;
                    case HSM_PIN_INCORRECT:
                        log_msg(config, LOG_ERR, "hsm_open() result: incorrect PIN");
                        break;
                    case HSM_CONFIG_FILE_ERROR:
                        log_msg(config, LOG_ERR, "hsm_open() result: config file error");
                        break;
                    case HSM_REPOSITORY_NOT_FOUND:
                        log_msg(config, LOG_ERR, "hsm_open() result: repository not found");
                        break;
                    case HSM_NO_REPOSITORIES:
                        log_msg(config, LOG_ERR, "hsm_open() result: no repositories");
                        break;
                    default:
                        log_msg(config, LOG_ERR, "hsm_open() result: %d", result);
                }
            }
            exit(1);
        }
        log_msg(config, LOG_INFO, "HSM opened successfully.");
        ctx = hsm_create_context();
    }

    while (1) {

        /* Read the config file */
        status = ReadConfig(config, 1);
        if (status != 0) {
            log_msg(config, LOG_ERR, "Error reading config");
            unlink(config->pidfile);
            exit(1);
        }
        /* If we are in sqlite mode then take a lock out on a file to
           prevent multiple access (not sure that we can be sure that sqlite is
           safe for multiple processes to access). */
        if (DbFlavour() == SQLITE_DB) {

            /* set up lock filename (it may have changed?) */
            lock_filename = NULL;
            StrAppend(&lock_filename, (char *)config->schema);
            StrAppend(&lock_filename, ".our_lock");

            lock_fd = fopen(lock_filename, "w");
            status = get_lite_lock(lock_filename, lock_fd);
            StrFree(lock_filename);
            if (status != 0) {
                log_msg(config, LOG_ERR, "Error getting db lock");
                unlink(config->pidfile);
                exit(1);
            }
        }

        log_msg(config, LOG_INFO, "Connecting to Database...");
        kaspConnect(config, &dbhandle);

        /* Read all policies */
        status = KsmPolicyInit(&handle, NULL);
        if (status == 0) {
            /* get the first policy */
            status = KsmPolicy(handle, policy);
            while (status == 0) {
                log_msg(config, LOG_INFO, "Policy %s found.", policy->name);
                /* Clear the policy struct */
                kaspSetPolicyDefaults(policy, NULL);

                /* Read the parameters for that policy */
                status = kaspReadPolicy(policy);

                /* Update the salt if it is not up to date */
                if (policy->denial->version == 3)
                {
                    status = KsmPolicyUpdateSalt(policy);
                    if (status != 0) {
                        /* Don't return? */
                        log_msg(config, LOG_ERR, "Error (%d) updating salt for %s", status, policy->name);
                    }
                }

                /* Do keygen stuff if required */
                if (config->manualKeyGeneration == 0) {
                    status = do_keygen(config, policy, ctx);
                }

                /* TODO move communicated stuff here eventually */
                /* Find all zones and do communication stuff */

                /* Purge dead keys if we are asked to in this policy */
                if (policy->keys->purge != -1) {
                    status = do_purge(policy->keys->purge, policy->id);
                }

                /* get next policy */
                status = KsmPolicy(handle, policy);
            }
        } else {
            log_msg(config, LOG_ERR, "Error querying KASP DB for policies.");
            unlink(config->pidfile);
            exit(1);
        }

        /* Communicate zones to the signer */
        do_communication(config, policy);
        

        DbFreeResult(handle);

        /* Disconnect from DB in case we are asleep for a long time */
        log_msg(config, LOG_INFO, "Disconnecting from Database...");
        kaspDisconnect(&dbhandle);

        /* Release sqlite lock file (if we have it) */
        if (DbFlavour() == SQLITE_DB) {
            status = release_lite_lock(lock_fd);
            if (status != 0) {
                log_msg(config, LOG_ERR, "Error releasing db lock");
                unlink(config->pidfile);
                exit(1);
            }
            fclose(lock_fd);
        }

        if (config->once == true ){
            log_msg(config, LOG_INFO, "Running once only, exiting...");
            break;
        }

        /* If we have been sent a SIGTERM then it is time to exit */
        if (config->term == 1 ){
            log_msg(config, LOG_INFO, "Received SIGTERM, exiting...");
            break;
        }
        /* Or SIGINT */
        if (config->term == 2 ){
            log_msg(config, LOG_INFO, "Received SIGINT, exiting...");
            break;
        }

        /* sleep for the interval */
        tv.tv_sec = config->interval;
        tv.tv_usec = 0;
        log_msg(config, LOG_INFO, "Sleeping for %i seconds.",config->interval);
        select(0, NULL, NULL, NULL, &tv);

        /* If we have been sent a SIGTERM then it is time to exit */
        if (config->term == 1 ){
            log_msg(config, LOG_INFO, "Received SIGTERM, exiting...");
            break;
        }
        /* Or SIGINT */
        if (config->term == 2 ){
            log_msg(config, LOG_INFO, "Received SIGINT, exiting...");
            break;
        }
    }

    /*
     * Destroy HSM context
     */
    if (ctx) {
        hsm_destroy_context(ctx);
    }

    result = hsm_close();
    log_msg(config, LOG_INFO, "all done! hsm_close result: %d", result);

    KsmPolicyFree(policy);

    unlink(config->pidfile);

    xmlCleanupParser();

}

int do_keygen(DAEMONCONFIG *config, KSM_POLICY* policy, hsm_ctx_t *ctx)
{
    int status = 0;

    char *rightnow;
    int i = 0;
    char *id;
    hsm_key_t *key = NULL;
    char *hsm_error_message = NULL;
    DB_ID ignore = 0;
    int ksks_needed = 0;    /* Total No of ksks needed before next generation run */
    int zsks_needed = 0;    /* Total No of zsks needed before next generation run */
    int keys_in_queue = 0;  /* number of unused keys */
    int new_keys = 0;       /* number of keys required */
    unsigned int current_count = 0;  /* number of keys already in HSM */

    int same_keys = 0;      /* Do ksks and zsks look the same ? */
    int ksks_created = 0;   /* Were any KSKs created? */

    if  (policy->shared_keys == 1 ) {
        log_msg(config, LOG_INFO, "Key sharing is On");
    } else {
        log_msg(config, LOG_INFO, "Key sharing is Off.");
    }

    rightnow = DtParseDateTimeString("now");

    /* Check datetime in case it came back NULL */
    if (rightnow == NULL) {
        log_msg(config, LOG_DEBUG, "Couldn't turn \"now\" into a date, quitting...");
        exit(1);
    }

    if (policy->ksk->sm == policy->zsk->sm && policy->ksk->bits == policy->zsk->bits && policy->ksk->algorithm == policy->zsk->algorithm) {
        same_keys = 1;
    } else {
        same_keys = 0;
    }
    /* Find out how many ksk keys are needed for the POLICY */
    status = KsmKeyPredict(policy->id, KSM_TYPE_KSK, policy->shared_keys, config->interval, &ksks_needed);
    if (status != 0) {
        log_msg(NULL, LOG_ERR, "Could not predict ksk requirement for next interval for %s", policy->name);
        /* TODO exit? continue with next policy? */
    }
    /* Find out how many suitable keys we have */
    status = KsmKeyCountStillGood(policy->id, policy->ksk->sm, policy->ksk->bits, policy->ksk->algorithm, config->interval, rightnow, &keys_in_queue);
    if (status != 0) {
        log_msg(NULL, LOG_ERR, "Could not count current ksk numbers for policy %s", policy->name);
        /* TODO exit? continue with next policy? */
    }

    new_keys = ksks_needed - keys_in_queue;
    /* fprintf(stderr, "keygen(ksk): new_keys(%d) = keys_needed(%d) - keys_in_queue(%d)\n", new_keys, ksks_needed, keys_in_queue); */

    /* Check capacity of HSM will not be exceeded */
    if (policy->ksk->sm_capacity != 0) {
        current_count = hsm_count_keys_repository(ctx, policy->ksk->sm_name);
        if (current_count >= policy->ksk->sm_capacity) {
            log_msg(config, LOG_ERR, "Repository %s is full, cannot create more KSKs for policy %s\n", policy->ksk->sm_name, policy->name);
            new_keys = 0;
        }
        else if (current_count + new_keys >  policy->ksk->sm_capacity) {
            log_msg(config, LOG_WARNING, "Repository %s is nearly full, will create %lu KSKs for policy %s (reduced from %d)\n", policy->ksk->sm_name, policy->ksk->sm_capacity - current_count, policy->name, new_keys);
            new_keys = policy->ksk->sm_capacity - current_count;
        }
    }

    /* Create the required keys */
    for (i=new_keys ; i > 0 ; i--){
        if (hsm_supported_algorithm(policy->ksk->algorithm) == 0) {
            /* NOTE: for now we know that libhsm only supports RSA keys */
            key = hsm_generate_rsa_key(ctx, policy->ksk->sm_name, policy->ksk->bits);
            if (key) {
                log_msg(config, LOG_DEBUG, "Created key in repository %s", policy->ksk->sm_name);
            } else {
                log_msg(config, LOG_ERR, "Error creating key in repository %s", policy->ksk->sm_name);
                hsm_error_message = hsm_get_error(ctx);
                if (hsm_error_message) {
                    log_msg(config, LOG_ERR, hsm_error_message);
                    free(hsm_error_message);
                }
                unlink(config->pidfile);
                exit(1);
            }
            id = hsm_get_key_id(ctx, key);
            hsm_key_free(key);
            status = KsmKeyPairCreate(policy->id, id, policy->ksk->sm, policy->ksk->bits, policy->ksk->algorithm, rightnow, &ignore);
            if (status != 0) {
                log_msg(config, LOG_ERR,"Error creating key in Database");
                hsm_error_message = hsm_get_error(ctx);
                if (hsm_error_message) {
                    log_msg(config, LOG_ERR, hsm_error_message);
                    free(hsm_error_message);
                }
                unlink(config->pidfile);
                exit(1);
            }
            log_msg(config, LOG_INFO, "Created KSK size: %i, alg: %i with id: %s in repository: %s and database.", policy->ksk->bits,
                    policy->ksk->algorithm, id, policy->ksk->sm_name);
            free(id);
        } else {
            log_msg(config, LOG_ERR, "Key algorithm %d unsupported by libhsm, exiting...", policy->ksk->algorithm);
            unlink(config->pidfile);
            exit(1);
        }
    }
    ksks_created = new_keys;

    /* Find out how many zsk keys are needed */
    keys_in_queue = 0;
    new_keys = 0;
    current_count = 0;

    /* Find out how many zsk keys are needed for the POLICY */
    status = KsmKeyPredict(policy->id, KSM_TYPE_ZSK, policy->shared_keys, config->interval, &zsks_needed);
    if (status != 0) {
        log_msg(NULL, LOG_ERR, "Could not predict zsk requirement for next intervalfor %s", policy->name);
        /* TODO exit? continue with next policy? */
    }
    /* Find out how many suitable keys we have */
    status = KsmKeyCountStillGood(policy->id, policy->zsk->sm, policy->zsk->bits, policy->zsk->algorithm, config->interval, rightnow, &keys_in_queue);
    if (status != 0) {
        log_msg(NULL, LOG_ERR, "Could not count current zsk numbers for policy %s", policy->name);
        /* TODO exit? continue with next policy? */
    }
    /* Might have to account for ksks */
    if (same_keys) {
        keys_in_queue -= ksks_needed;
    }

    new_keys = zsks_needed - keys_in_queue;
    /* fprintf(stderr, "keygen(zsk): new_keys(%d) = keys_needed(%d) - keys_in_queue(%d)\n", new_keys, zsks_needed, keys_in_queue); */

    /* Check capacity of HSM will not be exceeded */
    if (policy->zsk->sm_capacity != 0) {
        current_count = hsm_count_keys_repository(ctx, policy->zsk->sm_name);
        if (current_count >= policy->zsk->sm_capacity) {
            log_msg(config, LOG_ERR, "Repository %s is full, cannot create more ZSKs for policy %s\n", policy->zsk->sm_name, policy->name);
            new_keys = 0;
        }
        else if (current_count + new_keys >  policy->zsk->sm_capacity) {
            log_msg(config, LOG_WARNING, "Repository %s is nearly full, will create %lu ZSKs for policy %s (reduced from %d)\n", policy->zsk->sm_name, policy->zsk->sm_capacity - current_count, policy->name, new_keys);
            new_keys = policy->zsk->sm_capacity - current_count;
        }
    }

    /* Create the required keys */
    for (i = new_keys ; i > 0 ; i--) {
        if (hsm_supported_algorithm(policy->zsk->algorithm) == 0) {
            /* NOTE: for now we know that libhsm only supports RSA keys */
            key = hsm_generate_rsa_key(ctx, policy->zsk->sm_name, policy->zsk->bits);
            if (key) {
                log_msg(config, LOG_DEBUG, "Created key in repository %s", policy->zsk->sm_name);
            } else {
                log_msg(config, LOG_ERR, "Error creating key in repository %s", policy->zsk->sm_name);
                hsm_error_message = hsm_get_error(ctx);
                if (hsm_error_message) {
                    log_msg(config, LOG_ERR, hsm_error_message);
                    free(hsm_error_message);
                }
                unlink(config->pidfile);
                hsm_key_free(key);
                exit(1);
            }
            id = hsm_get_key_id(ctx, key);
            hsm_key_free(key);
            status = KsmKeyPairCreate(policy->id, id, policy->zsk->sm, policy->zsk->bits, policy->zsk->algorithm, rightnow, &ignore);
            if (status != 0) {
                log_msg(config, LOG_ERR,"Error creating key in Database");
                hsm_error_message = hsm_get_error(ctx);
                if (hsm_error_message) {
                    log_msg(config, LOG_ERR, hsm_error_message);
                    free(hsm_error_message);
                }
                unlink(config->pidfile);
                exit(1);
            }
            log_msg(config, LOG_INFO, "Created ZSK size: %i, alg: %i with id: %s in repository: %s and database.", policy->zsk->bits,
                    policy->zsk->algorithm, id, policy->zsk->sm_name);
            free(id);
        } else {
            log_msg(config, LOG_ERR, "Key algorithm %d unsupported by libhsm, exiting...", policy->zsk->algorithm);
            unlink(config->pidfile);
            exit(1);
        }
    }
    StrFree(rightnow);

    /* Log if a backup needs to be run for these keys */
    if (ksks_created && policy->ksk->require_backup) {
        log_msg(config, LOG_INFO, "NOTE: keys generated in repository %s will not become active until they have been backed up", policy->ksk->sm_name);
    }
    if (new_keys && policy->zsk->require_backup && (policy->zsk->sm != policy->ksk->sm)) {
        log_msg(config, LOG_INFO, "NOTE: keys generated in repository %s will not become active until they have been backed up", policy->zsk->sm_name);
    }

    return status;
}

int do_communication(DAEMONCONFIG *config, KSM_POLICY* policy)
{
    int status = 0;
    int status2 = 0;

    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;

    int ret = 0; /* status of the XML parsing */
    char* zonelist_filename = NULL;
    char* zone_name;
    char* current_policy;
    char* current_filename;
    char *tag_name;
    int zone_id = -1;
    int signer_flag = 1; /* Is the signer responding? (1 == yes) */
    char* ksk_expected = NULL;  /* When is the next ksk rollover expected? */

    xmlChar *name_expr = (unsigned char*) "name";
    xmlChar *policy_expr = (unsigned char*) "//Zone/Policy";
    xmlChar *filename_expr = (unsigned char*) "//Zone/SignerConfiguration";

    char* temp_char = NULL;

    /* Stuff to see if we need to log an "impending rollover" warning */
    char* datetime = NULL;
    int roll_time = 0;

    /* Let's find our zonelist from the conf.xml */
    if (config->configfile != NULL) {
        status = read_zonelist_filename(config->configfile, &zonelist_filename);
    } else {
        status = read_zonelist_filename(CONFIG_FILE, &zonelist_filename);
    }
    
    if (status != 0) {
        log_msg(NULL, LOG_ERR, "couldn't read zonelist filename");
        unlink(config->pidfile);
        exit(1);
    }

    /* In case zonelist is huge use the XmlTextReader API so that we don't hold the whole file in memory */
    reader = xmlNewTextReaderFilename(zonelist_filename);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            tag_name = (char*) xmlTextReaderLocalName(reader);
            /* Found <Zone> */
            if (strncmp(tag_name, "Zone", 4) == 0 
                    && strncmp(tag_name, "ZoneList", 8) != 0
                    && xmlTextReaderNodeType(reader) == 1) {
                /* Get the zone name (TODO what if this is null?) */
                zone_name = NULL;
                temp_char = (char*) xmlTextReaderGetAttribute(reader, name_expr);
                StrAppend(&zone_name, temp_char);
                StrFree(temp_char);
                /* Make sure that we got something */
                if (zone_name == NULL) {
                    /* error */
                    log_msg(NULL, LOG_ERR, "Error extracting zone name from %s", zonelist_filename);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }


                log_msg(config, LOG_INFO, "Zone %s found.", zone_name);

                /* Get zone ID from name (or skip if it doesn't exist) */
                status = KsmZoneIdFromName(zone_name, &zone_id);
                if (status != 0 || zone_id == -1)
                {
                    /* error */
                    log_msg(NULL, LOG_ERR, "Error looking up zone \"%s\" in database (maybe it doesn't exist?)", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                doc = xmlTextReaderCurrentDoc(reader);
                if (doc == NULL) {
                    log_msg(config, LOG_ERR, "Error: can not read zone \"%s\"; skipping", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* TODO should we validate here? Or should we validate the whole document? */

                xpathCtx = xmlXPathNewContext(doc);
                if(xpathCtx == NULL) {
                    log_msg(config, LOG_ERR,"Error: can not create XPath context for \"%s\"; skipping zone", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* Extract the Policy name and signer configuration filename for this zone */
                /* Evaluate xpath expression for policy */
                xpathObj = xmlXPathEvalExpression(policy_expr, xpathCtx);
                if(xpathObj == NULL) {
                    log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s; skipping zone", policy_expr);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                current_policy = NULL;
                temp_char = (char*) xmlXPathCastToString(xpathObj);
                StrAppend(&current_policy, temp_char);
                StrFree(temp_char);
                log_msg(config, LOG_INFO, "Policy for %s set to %s.", zone_name, current_policy);
                xmlXPathFreeObject(xpathObj);

                if (strcmp(current_policy, policy->name) != 0) {
                    /* Read new Policy */ 
                    kaspSetPolicyDefaults(policy, current_policy);

                    status2 = KsmPolicyRead(policy);
                    if (status2 != 0) {
                        /* Don't return? try to parse the rest of the zones? */
                        log_msg(config, LOG_ERR, "Error reading policy");
                        ret = xmlTextReaderRead(reader);
                        continue;
                    }
                    log_msg(config, LOG_INFO, "Policy %s found in DB.", policy->name);

                } else {
                    /* Policy is same as previous zone, do not re-read */
                }

                StrFree(current_policy);

                /* Evaluate xpath expression for signer configuration filename */
                xpathObj = xmlXPathEvalExpression(filename_expr, xpathCtx);
                xmlXPathFreeContext(xpathCtx);

                if(xpathObj == NULL) {
                    log_msg(config, LOG_ERR, "Error: unable to evaluate xpath expression: %s; skipping zone", policy_expr);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                current_filename = NULL;
                temp_char = (char*)xmlXPathCastToString(xpathObj);
                StrAppend(&current_filename, temp_char);
                StrFree(temp_char);
                log_msg(config, LOG_INFO, "Config will be output to %s.", current_filename);
                xmlXPathFreeObject(xpathObj);
                /* TODO should we check that we have not written to this file in this run?*/
                /* Make sure that enough keys are allocated to this zone */
                status2 = allocateKeysToZone(policy, KSM_TYPE_ZSK, zone_id, config->interval, zone_name);
                if (status2 != 0) {
                    log_msg(config, LOG_ERR, "Error allocating zsks to zone %s", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                status2 = allocateKeysToZone(policy, KSM_TYPE_KSK, zone_id, config->interval, zone_name);
                if (status2 != 0) {
                    log_msg(config, LOG_ERR, "Error allocating ksks to zone %s", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* turn this zone and policy into a file */
                status2 = commGenSignConf(zone_name, zone_id, current_filename, policy, &signer_flag, config->interval);
                if (status2 == -2) {
                    log_msg(config, LOG_ERR, "Signconf not written for %s", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                else if (status2 != 0) {
                    log_msg(config, LOG_ERR, "Error writing signconf for %s", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* See if we need to send a warning about an impending rollover */
                if (config->rolloverNotify != -1) {
                    datetime = DtParseDateTimeString("now");

                    /* Check datetime in case it came back NULL */
                    if (datetime == NULL) {
                        log_msg(config, LOG_DEBUG, "Couldn't turn \"now\" into a date, quitting...");
                        exit(1);
                    }

                    /* First the KSK */
                    status2 = KsmCheckNextRollover(KSM_TYPE_KSK, zone_id, &ksk_expected);
                    if (status2 != 0) {
                        log_msg(config, LOG_ERR, "Error checking for impending rollover for %s", zone_name);
                        /* TODO should we quit or continue? */
                    }
                    status2 = DtDateDiff(ksk_expected, datetime, &roll_time);
                    if (status2 != 0) {
                        log_msg(config, LOG_ERR, "Error checking for impending rollover for %s", zone_name);
                    }

                    if (roll_time <= config->rolloverNotify) {
                        log_msg(config, LOG_INFO, "Rollover of KSK expected at %s for %s", ksk_expected, zone_name);
                    }
                    StrFree(datetime);
                    StrFree(ksk_expected);
                }

                StrFree(current_filename);
                StrFree(zone_name);
            }
            /* Read the next line */
            ret = xmlTextReaderRead(reader);
            StrFree(tag_name);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            log_msg(config, LOG_ERR, "%s : failed to parse", zonelist_filename);
        }
    } else {
        log_msg(config, LOG_ERR, "Unable to open %s", zonelist_filename);
    }

    xmlFreeDoc(doc);
    StrFree(zonelist_filename);

    return status;
}

/*
 *  generate the configuration file for the signer

 *  returns 0 on success and -1 if something went wrong
 *                           -2 if the RequestKeys call failed
 */
int commGenSignConf(char* zone_name, int zone_id, char* current_filename, KSM_POLICY *policy, int* signer_flag, int run_interval)
{
    int status = 0;
    FILE *file, *file2;
    int char1, char2;      /* for the comparison between 2 files */
    int same = 0;
    char *temp_filename;    /* In case this fails we write to a temp file and only overwrite
                               the current file when we are finished */
    char *old_filename;     /* Keep a copy of the previous version, just in case! (Also gets
                               round potentially different behaviour of rename over existing
                               file.) */
    char *signer_command;   /* how we will call the signer */
    char*   datetime = DtParseDateTimeString("now");

    /* Check datetime in case it came back NULL */
    if (datetime == NULL) {
        log_msg(NULL, LOG_DEBUG, "Couldn't turn \"now\" into a date, quitting...");
        exit(1);
    }

    if (zone_name == NULL || current_filename == NULL || policy == NULL)
    {
        /* error */
        log_msg(NULL, LOG_ERR, "commGenSignConf, NULL policy or zone provided");
        MemFree(datetime);
        return -1;
    }

    old_filename = NULL;
    StrAppend(&old_filename, current_filename);
    StrAppend(&old_filename, ".OLD");

    temp_filename = NULL;
    StrAppend(&temp_filename, current_filename);
    StrAppend(&temp_filename, ".tmp");

    file = fopen(temp_filename, "w");

    if (file == NULL)
    {
        /* error */
        log_msg(NULL, LOG_ERR, "Could not open: %s", temp_filename);
        MemFree(datetime);
        StrFree(temp_filename);
        StrFree(old_filename);
        return -1;
    }

    fprintf(file, "<SignerConfiguration>\n");
    fprintf(file, "\t<Zone name=\"%s\">\n", zone_name);

    fprintf(file, "\t\t<Signatures>\n");
    fprintf(file, "\t\t\t<Resign>PT%dS</Resign>\n", policy->signature->resign);
    fprintf(file, "\t\t\t<Refresh>PT%dS</Refresh>\n", policy->signer->refresh);
    fprintf(file, "\t\t\t<Validity>\n");
    fprintf(file, "\t\t\t\t<Default>PT%dS</Default>\n", policy->signature->valdefault);
    fprintf(file, "\t\t\t\t<Denial>PT%dS</Denial>\n", policy->signature->valdenial);
    fprintf(file, "\t\t\t</Validity>\n");
    fprintf(file, "\t\t\t<Jitter>PT%dS</Jitter>\n", policy->signer->jitter);
    fprintf(file, "\t\t\t<InceptionOffset>PT%dS</InceptionOffset>\n", policy->signature->clockskew);
    fprintf(file, "\t\t</Signatures>\n");

    fprintf(file, "\n");

    fprintf(file, "\t\t<Denial>\n");
    if (policy->denial->version == 3)
    {
        fprintf(file, "\t\t\t<NSEC3>\n");
        if (policy->denial->optout == 1)
        {
            fprintf(file, "\t\t\t\t<OptOut />\n");
        }
        fprintf(file, "\t\t\t\t<Hash>\n");
        fprintf(file, "\t\t\t\t\t<Algorithm>%d</Algorithm>\n", policy->denial->algorithm);
        fprintf(file, "\t\t\t\t\t<Iterations>%d</Iterations>\n", policy->denial->iteration);
        fprintf(file, "\t\t\t\t\t<Salt>%s</Salt>\n", policy->denial->salt);
        fprintf(file, "\t\t\t\t</Hash>\n");
        fprintf(file, "\t\t\t</NSEC3>\n");
    } else {
        fprintf(file, "\t\t\t<NSEC />\n");
    }

    fprintf(file, "\t\t</Denial>\n");

    fprintf(file, "\n");

    /* start of keys section */ 
    fprintf(file, "\t\t<Keys>\n");
    fprintf(file, "\t\t\t<TTL>PT%dS</TTL>\n", policy->ksk->ttl);

    status = KsmRequestKeys(0, 0, datetime, commKeyConfig, file, policy->id, zone_id, run_interval);
    if (status != 0) {
        /* 
         * Something went wrong (it should have been logged) stop this zone.
         * Clean up the files, don't call the signer and move on to the next zone.
         */
        log_msg(NULL, LOG_ERR, "KsmRequestKeys returned: %d", status);

        status = fclose(file);
        unlink(temp_filename);
        MemFree(datetime);
        StrFree(temp_filename);
        StrFree(old_filename);
        return -2;
    }

    fprintf(file, "\t\t</Keys>\n");

    fprintf(file, "\n");

    fprintf(file, "\t\t<SOA>\n");
    fprintf(file, "\t\t\t<TTL>PT%dS</TTL>\n", policy->signer->soattl);
    fprintf(file, "\t\t\t<Minimum>PT%dS</Minimum>\n", policy->signer->soamin);
    fprintf(file, "\t\t\t<Serial>%s</Serial>\n", KsmKeywordSerialValueToName( policy->signer->serial) );
    fprintf(file, "\t\t</SOA>\n");

    if (strncmp(policy->audit, "NULL", 4) != 0) {
        fprintf(file, "\n");
        fprintf(file, "\t\t<Audit>%s</Audit>\n", policy->audit);
        fprintf(file, "\n");
    }

    fprintf(file, "\t</Zone>\n");
    fprintf(file, "</SignerConfiguration>\n");

    /* Force flush of stream to disc cache and then onto disc proper
     * Do we need to do this? It might be significant on ext4
     * NOTE though that there may be a significant overhead associated with it
     * ALSO, if we do lose power maybe we should disregard any files when we come
     *       back as we won't know if they are now too old? */
    /* 
       if (fflush(file) != 0) {
       MemFree(datetime);
       return -1;
       }

       if (fsync(fileno(file)) != 0) {
       MemFree(datetime);
       return -1;
       }
     */

    status = fclose(file);
    MemFree(datetime);

    if (status == EOF) /* close failed... do something? */
    {
        log_msg(NULL, LOG_ERR, "Could not close: %s", temp_filename);
        StrFree(temp_filename);
        StrFree(old_filename);
        return -1;
    }

    /* compare our temp file with the current one (if it exists) */
    file = fopen(temp_filename, "rb");
    if (file == NULL)
    {
        /* error */
        log_msg(NULL, LOG_ERR, "Could not reopen: %s", temp_filename);
        StrFree(temp_filename);
        StrFree(old_filename);
        return -1;
    }

    file2 = fopen(current_filename, "rb"); /* Might not exist */

    /* If current_filename exists then compare its contents to temp_filename */
    if (file2 != NULL) {
        same = 1;
        while(!feof(file)) {
            char1 = fgetc(file);
            if(ferror(file)) {
                log_msg(NULL, LOG_ERR, "Could not read: %s", temp_filename);
                fclose(file);
                fclose(file2);
                StrFree(temp_filename);
                StrFree(old_filename);
                return -1;
            }
            char2 = fgetc(file2);
            if(ferror(file2)) {
                log_msg(NULL, LOG_ERR, "Could not read: %s", current_filename);
                fclose(file);
                fclose(file2);
                StrFree(temp_filename);
                StrFree(old_filename);
                return -1;
            }
            if(char1 != char2) {
                same = 0;
                break;
            }
        }

        status = fclose(file2);
        if (status == EOF) /* close failed... do something? */
        {
            log_msg(NULL, LOG_ERR, "Could not close: %s", current_filename);
            fclose(file);
            StrFree(temp_filename);
            StrFree(old_filename);
            return -1;
        }
    }

    status = fclose(file);
    if (status == EOF) /* close failed... do something? */
    {
        log_msg(NULL, LOG_ERR, "Could not close: %s", temp_filename);
        StrFree(temp_filename);
        StrFree(old_filename);
        return -1;
    }

    /* If either current_filename does not exist, or if it is different to temp then same will == 0 */

    if (same == 0) {

        /* we now have a complete xml file. First move the old one out of the way */
        status = rename(current_filename, old_filename);
        if (status != 0 && status != -1)
        {
            /* cope with initial condition of files not existing */
            log_msg(NULL, LOG_ERR, "Could not rename: %s -> %s", current_filename, old_filename);
            StrFree(old_filename);
            StrFree(temp_filename);
            return -1;
        }

        /* Then copy our temp into place */
        if (rename(temp_filename, current_filename) != 0)
        {
            log_msg(NULL, LOG_ERR, "Could not rename: %s -> %s", temp_filename, current_filename);
            StrFree(old_filename);
            StrFree(temp_filename);
            return -1;
        }

        if (*signer_flag == 1) {
            /* call the signer engine to tell it that something changed */
            /* TODO for beta version connect straight to the socket
               should we make a blocking call on this?
               should we call it here or after we have written all of the files?
               have timeout if call is blocking */
            signer_command = NULL;
            StrAppend(&signer_command, SIGNER_CLI_COMMAND);
            StrAppend(&signer_command, " ");
            StrAppend(&signer_command, zone_name);

            status = system(signer_command);
            if (status != 0)
            {
                log_msg(NULL, LOG_ERR, "Could not call signer engine");
                log_msg(NULL, LOG_INFO, "Will continue: call 'ods-signer update' to manually update zones");
                *signer_flag = 0;
            }

            StrFree(signer_command);
        }
    }
    else {
        log_msg(NULL, LOG_INFO, "No change to: %s", current_filename);
        if (remove(temp_filename) != 0)
        {
            log_msg(NULL, LOG_ERR, "Could not remove: %s", temp_filename);
            StrFree(old_filename);
            StrFree(temp_filename);
            return -1;
        }
    }
    StrFree(old_filename);
    StrFree(temp_filename);

    return 0;
}

/*
 * CallBack to print key info in signerConfiguration
 */

int commKeyConfig(void* context, KSM_KEYDATA* key_data)
{
    FILE *file = (FILE *)context;

    fprintf(file, "\t\t\t<Key>\n");
    fprintf(file, "\t\t\t\t<Flags>%d</Flags>\n", key_data->keytype);
    fprintf(file, "\t\t\t\t<Algorithm>%d</Algorithm>\n", key_data->algorithm);
    fprintf(file, "\t\t\t\t<Locator>%s</Locator>\n", key_data->location);
    if (key_data->keytype == KSM_TYPE_KSK && key_data->state == KSM_STATE_ACTIVE)
    {
        fprintf(file, "\t\t\t\t<KSK />\n");
    }
    if (key_data->keytype == KSM_TYPE_ZSK && key_data->state == KSM_STATE_ACTIVE)
    {
        fprintf(file, "\t\t\t\t<ZSK />\n");
    }
    if (key_data->state > KSM_STATE_GENERATE && key_data->state < KSM_STATE_DEAD)
    {
        fprintf(file, "\t\t\t\t<Publish />\n");
    }
    fprintf(file, "\t\t\t</Key>\n");
    fprintf(file, "\n");

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
 *
 * Returns:
 *      int
 *          Status return.  0=> Success, non-zero => error.
 *          1 == error with input
 *          2 == not enough keys to satisfy policy
 *          3 == database error
 -*/


int allocateKeysToZone(KSM_POLICY *policy, int key_type, int zone_id, uint16_t interval, const char* zone_name)
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
        log_msg(NULL, LOG_DEBUG, "Couldn't turn \"now\" into a date, quitting...");
        exit(1);
    }

    if (policy == NULL) {
        log_msg(NULL, LOG_ERR, "NULL policy sent to allocateKeysToZone");
        StrFree(datetime);
        return 1;
    }

    if (key_type != KSM_TYPE_KSK && key_type != KSM_TYPE_ZSK) {
        log_msg(NULL, LOG_ERR, "Unknown keytype: %i in allocateKeysToZone", key_type);
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
    status = KsmKeyPredict(policy->id, key_type, 1, interval, &keys_needed);
    if (status != 0) {
        log_msg(NULL, LOG_ERR, "Could not predict key requirement for next interval for %s", zone_name);
        StrFree(datetime);
        return 3;
    }

    /* How many do we have ? TODO should this include the currently active key?*/
    status = KsmKeyCountQueue(key_type, &keys_in_queue, zone_id);
    if (status != 0) {
        log_msg(NULL, LOG_ERR, "Could not count current key numbers for zone %s", zone_name);
        StrFree(datetime);
        return 3;
    }

    /* or about to retire */
    status = KsmRequestPendingRetireCount(key_type, datetime, &collection, &keys_pending_retirement, zone_id, interval);
    if (status != 0) {
        log_msg(NULL, LOG_ERR, "Could not count keys which may retire before the next run (for zone %s)", zone_name);
        StrFree(datetime);
        return 3;
    }

    StrFree(datetime);
    new_keys = keys_needed - (keys_in_queue - keys_pending_retirement);

    /* fprintf(stderr, "comm(%d) %s: new_keys(%d) = keys_needed(%d) - (keys_in_queue(%d) - keys_pending_retirement(%d))\n", key_type, zone_name, new_keys, keys_needed, keys_in_queue, keys_pending_retirement); */

    /* Allocate keys */
    for (i=0 ; i < new_keys ; i++){
        key_pair_id = 0;
        if (key_type == KSM_TYPE_KSK) {
            status = KsmKeyGetUnallocated(policy->id, policy->ksk->sm, policy->ksk->bits, policy->ksk->algorithm, &key_pair_id);
            if (status == -1) {
                log_msg(NULL, LOG_WARNING, "Not enough keys to satisfy ksk policy for zone: %s", zone_name);
                return 2;
            }
            else if (status != 0) {
                log_msg(NULL, LOG_ERR, "Could not get an unallocated ksk for zone: %s", zone_name);
                return 3;
            }
        } else {
            status = KsmKeyGetUnallocated(policy->id, policy->zsk->sm, policy->zsk->bits, policy->zsk->algorithm, &key_pair_id);
            if (status == -1) {
                log_msg(NULL, LOG_WARNING, "Not enough keys to satisfy zsk policy for zone: %s", zone_name);
                return 2;
            }
            else if (status != 0) {
                log_msg(NULL, LOG_ERR, "Could not get an unallocated zsk for zone: %s", zone_name);
                return 3;
            }
        }
        if(key_pair_id > 0) {
            /* This will do all zones if keys are shared */ 
            if (policy->keys->share_keys == 1) {
                status = KsmDnssecKeyCreateOnPolicy(policy->id, key_pair_id, key_type);
            } else {
                status = KsmDnssecKeyCreate(zone_id, key_pair_id, key_type, &ignore);
            }
            /* fprintf(stderr, "comm(%d) %s: allocated keypair id %d\n", key_type, zone_name, key_pair_id); */
        } else {
            /* TODO what would this mean? */
        }

    }

    return status;
}

/* 
 *  Read the conf.xml file, extract the location of the zonelist.
 */
int read_zonelist_filename(const char* filename, char** zone_list_filename)
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
    reader = xmlNewTextReaderFilename(filename);
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
                    log_msg(NULL, LOG_ERR, "Error: can not read Common section of %s", filename);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                xpathCtx = xmlXPathNewContext(doc);
                if(xpathCtx == NULL) {
                    log_msg(NULL, LOG_ERR, "Error: can not create XPath context for Common section");
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* Evaluate xpath expression for ZoneListFile */
                xpathObj = xmlXPathEvalExpression(zonelist_expr, xpathCtx);
                if(xpathObj == NULL) {
                    log_msg(NULL, LOG_ERR, "Error: unable to evaluate xpath expression: %s", zonelist_expr);
                    /* Don't return? try to parse the rest of the file? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                *zone_list_filename = NULL;
                temp_char = (char *)xmlXPathCastToString(xpathObj);
                StrAppend(zone_list_filename, temp_char);
                StrFree(temp_char);
                xmlXPathFreeObject(xpathObj);
                log_msg(NULL, LOG_INFO, "zonelist filename set to %s.", *zone_list_filename);
            }
            /* Read the next line */
            ret = xmlTextReaderRead(reader);
            StrFree(tag_name);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            log_msg(NULL, LOG_ERR, "%s : failed to parse", filename);
            return(1);
        }
    } else {
        log_msg(NULL, LOG_ERR, "Unable to open %s", filename);
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

/*+
 * do_purge - Purge dead Keys
 *
 *
 * Arguments:
 *
 *      int interval
 *          how long a key needs to have been dead for before we purge it
 *
 *      int policy_id
 *          ID of the policy
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int do_purge(int interval, int policy_id)
{
    char*       sql = NULL;     /* SQL query */
    char*       sql2 = NULL;    /* SQL query */
    char*       sql3 = NULL;    /* SQL query */
    int         status = 0;     /* Status return */
    char        stringval[KSM_INT_STR_SIZE];  /* For Integer to String conversion */
    DB_RESULT	result;         /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */

    char            buffer[KSM_SQL_SIZE];    /* Long enough for any statement */
    unsigned int    nchar;          /* Number of characters converted */

    int         temp_id = -1;       /* place to store the key id returned */
    char*       temp_dead = NULL;   /* place to store dead date returned */
    char*       temp_loc = NULL;    /* place to store location returned */

    char *rightnow;

    /* Key information */
    hsm_key_t *key = NULL;

    log_msg(NULL, LOG_DEBUG, "Purging keys...");

    rightnow = DtParseDateTimeString("now");

    /* Check datetime in case it came back NULL */
    if (rightnow == NULL) {
        log_msg(NULL, LOG_DEBUG, "Couldn't turn \"now\" into a date, quitting...");
        exit(1);
    }

    /* Select rows */
    StrAppend(&sql, "select id, dead, location from KEYDATA_VIEW where state = 6 ");

#ifdef USE_MYSQL
    nchar = snprintf(buffer, sizeof(buffer),
        "and DEAD < DATE_ADD('%s', INTERVAL -%d SECOND) ", rightnow, interval);
#else
    nchar = snprintf(buffer, sizeof(buffer),
        "and DEAD < DATETIME('%s', '-%d SECONDS') ", rightnow, interval);
#endif /* USE_MYSQL */

    StrAppend(&sql, buffer);
    if (policy_id != -1) {
        StrAppend(&sql, "and policy_id = ");
        snprintf(stringval, KSM_INT_STR_SIZE, "%d", policy_id);
        StrAppend(&sql, stringval);
    }
    /* stop us doing the same key twice */
    StrAppend(&sql, " group by location");

    DusEnd(&sql);
    StrFree(rightnow);

    status = DbExecuteSql(DbHandle(), sql, &result);

    if (status == 0) {
        status = DbFetchRow(result, &row);
        while (status == 0) {
            /* Got a row, purge it */
            DbInt(row, 0, &temp_id);
            DbString(row, 1, &temp_dead);
            DbString(row, 2, &temp_loc);

            /* Delete from dnsseckeys */
            sql2 = DdsInit("dnsseckeys");
            DdsConditionInt(&sql2, "keypair_id", DQS_COMPARE_EQ, temp_id, 0);
            DdsEnd(&sql);

            status = DbExecuteSqlNoResult(DbHandle(), sql2);
            DdsFree(sql2);
            if (status != 0)
            {
                log_msg(NULL, LOG_ERR, "SQL failed: %s\n", DbErrmsg(DbHandle()));
                DbStringFree(temp_dead);
                DbStringFree(temp_loc);
                DbFreeRow(row);
                return status;
            }

            /* Delete from keypairs */
            sql3 = DdsInit("keypairs");
            DdsConditionInt(&sql3, "id", DQS_COMPARE_EQ, temp_id, 0);
            DdsEnd(&sql);

            status = DbExecuteSqlNoResult(DbHandle(), sql3);
            DdsFree(sql3);
            if (status != 0)
            {
                log_msg(NULL, LOG_ERR, "SQL failed: %s\n", DbErrmsg(DbHandle()));
                DbStringFree(temp_dead);
                DbStringFree(temp_loc);
                DbFreeRow(row);
                return status;
            }

            /* Delete from the HSM */
            key = hsm_find_key_by_id(NULL, temp_loc);

            if (!key) {
                log_msg(NULL, LOG_ERR, "Key not found: %s\n", temp_loc);
                DbStringFree(temp_dead);
                DbStringFree(temp_loc);
                DbFreeRow(row);
                return -1;
            }

            status = hsm_remove_key(NULL, key);

            hsm_key_free(key);

            if (!status) {
                log_msg(NULL, LOG_INFO, "Key remove successful.\n");
            } else {
                log_msg(NULL, LOG_ERR, "Key remove failed.\n");
                DbStringFree(temp_dead);
                DbStringFree(temp_loc);
                DbFreeRow(row);
                return -1;
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

    DusFree(sql);
    DbFreeRow(row);

    DbStringFree(temp_dead);
    DbStringFree(temp_loc);

    return status;
}
