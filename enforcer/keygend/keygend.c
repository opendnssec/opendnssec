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
 * keygend.c code implements the server_main
 * function needed by daemon.c
 *
 * The bit that makes the daemon do something useful
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

#include "daemon.h"
#include "daemon_util.h"
#include "kaspaccess.h"

#include "ksm/datetime.h"
#include "ksm/string_util.h"

#include "libhsm.h"
#include "keygend.h" 

int
server_init(DAEMONCONFIG *config)
{
    if (config == NULL) {
        log_msg(NULL, LOG_ERR, "Error, no config provided");
        exit(1);
    }

    /* set the default pidfile if nothing was provided on the command line*/
    if (config->pidfile == NULL) {
        config->pidfile = KEYGEN_PID;
    }

    return 0;
}

/*
 * Main loop of keygend server
 */
void
server_main(DAEMONCONFIG *config)
{
    DB_RESULT handle;
    DB_HANDLE dbhandle;
    int status = 0;
    int count = 0;
    int i = 0; 
    char *id;
    char *rightnow; 
    DB_ID ignore = 0;
    struct timeval tv;
    KSM_POLICY *policy;
    int result;
    hsm_ctx_t *ctx = NULL;
    hsm_key_t *key = NULL; 
   
    if (config == NULL) {
        log_msg(NULL, LOG_ERR, "Error, no config provided");
        exit(1);
    }

    policy = (KSM_POLICY *)malloc(sizeof(KSM_POLICY));
    policy->signer = (KSM_SIGNER_POLICY *)malloc(sizeof(KSM_SIGNER_POLICY));
    policy->signature = (KSM_SIGNATURE_POLICY *)malloc(sizeof(KSM_SIGNATURE_POLICY));
    policy->ksk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
    policy->zsk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
    policy->denial = (KSM_DENIAL_POLICY *)malloc(sizeof(KSM_DENIAL_POLICY));
    policy->enforcer = (KSM_ENFORCER_POLICY *)malloc(sizeof(KSM_ENFORCER_POLICY));
    policy->name = (char *)calloc(KSM_NAME_LENGTH, sizeof(char));
    /* Let's check all of those mallocs, or should we use MemMalloc ? */
    if (policy->signer == NULL || policy->signature == NULL ||
            policy->ksk == NULL || policy->zsk == NULL || 
            policy->denial == NULL || policy->enforcer == NULL) {
        log_msg(config, LOG_ERR, "Malloc for policy struct failed\n");
        exit(1);
    }
    kaspSetPolicyDefaults(policy, NULL);
   
    /* We keep the HSM connection open for the lifetime of the daemon */ 
    result = hsm_open(CONFIGFILE, hsm_prompt_pin, NULL);
    log_msg(config, LOG_INFO, "hsm_open result: %d\n", result);
    ctx = hsm_create_context();

    while (1) {

        /* Read the config file */
        status = ReadConfig(config);
        if (status != 0) {
            log_msg(config, LOG_ERR, "Error reading config");
            exit(1);
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
                kaspSetPolicyDefaults(policy, policy->name);

                /* Read the parameters for that policy */
                status = kaspReadPolicy(policy);

                if  (policy->shared_keys == 1 ) {
                    log_msg(config, LOG_INFO, "Key sharing is On");
                } else {
                    log_msg(config, LOG_INFO, "Key sharing is Off.");
                }

                rightnow = DtParseDateTimeString("now");

                /* Find out how many ksk keys are needed */
                status = ksmKeyPredict(policy->id, KSM_TYPE_KSK, policy->shared_keys, config->keygeninterval, &count);
                /* TODO: check capacity of HSM will not be exceeded */
                /* TODO: check how many unused keys there are (accounting for shared_keys) */
                /* Create the keys TODO: skip if enough unused keys exist */
                for (i=count ; i > 0 ; i--){
                        if (policy->ksk->algorithm == 5 ) {
                            key = hsm_generate_rsa_key(ctx, policy->ksk->sm_name, policy->ksk->bits);
                            if (key) {
                                log_msg(config, LOG_INFO,"Created key in HSM\n");
                            } else {
                                log_msg(config, LOG_ERR,"Error creating key in HSM\n");
                                exit(1);
                            }
                            id = hsm_get_key_id(ctx, key);
                            status = KsmKeyPairCreate(policy->id, id, policy->ksk->sm, policy->ksk->bits, policy->ksk->algorithm, rightnow, &ignore);
                            log_msg(config, LOG_INFO, "Created KSK size: %i, alg: %i with id: %s in HSM: %s.", policy->ksk->bits,
                                    policy->ksk->algorithm, id, policy->ksk->sm_name);
                            free(id);
                        } else {
                            log_msg(config, LOG_ERR, "Key algorithm unsupported by libhsm.");
                            exit(1);
                        }
                 }

                /* Find out how many zsk keys are needed */
                status = ksmKeyPredict(policy->id, KSM_TYPE_ZSK, policy->shared_keys, config->keygeninterval, &count);
                /* TODO: check capacity of HSM will not be exceeded */
                for (i = count ; i > 0 ; i--){
                   if (policy->zsk->algorithm == 5 ) {
                       key = hsm_generate_rsa_key(ctx, policy->ksk->sm_name, policy->zsk->bits);
                       if (key) {
                           log_msg(config, LOG_INFO,"Created key in HSM\n");
                       } else {
                           log_msg(config, LOG_ERR,"Error creating key in HSM\n");
                           exit(1);
                       }
                       id = hsm_get_key_id(ctx, key);
                       status = KsmKeyPairCreate(policy->id, id, policy->zsk->sm, policy->zsk->bits, policy->zsk->algorithm, rightnow, &ignore);
                       log_msg(config, LOG_INFO, "Created ZSK size: %i, alg: %i with id: %s in HSM: %s.", policy->zsk->bits,
                               policy->zsk->algorithm, id, policy->zsk->sm_name);
                       free(id);
                    } else {
                       log_msg(config, LOG_ERR, "unsupported key algorithm.");
                       exit(1);
                    }
                }
                StrFree(rightnow);

                /* get next policy */
                status = KsmPolicy(handle, policy);
            }
        } else {
            log_msg(config, LOG_ERR, "Error querying KASP DB for policies.");
            exit(1);
        }
        DbFreeResult(handle);

        /* Disconnect from DB in case we are asleep for a long time */
        log_msg(config, LOG_INFO, "Disconnecting from Database...");
        kaspDisconnect(&dbhandle);

        /* If we have been sent a SIGTERM then it is time to exit */
        if (config->term == 1 ){
            log_msg(config, LOG_INFO, "Received SIGTERM, exiting...");
            exit(0);
        }

        /* sleep for the key gen interval */
        tv.tv_sec = config->keygeninterval;
        tv.tv_usec = 0;
        log_msg(config, LOG_INFO, "Sleeping for %i seconds.",config->keygeninterval);
        select(0, NULL, NULL, NULL, &tv);

        /* If we have been sent a SIGTERM then it is time to exit */
        if (config->term == 1 ){
            log_msg(config, LOG_INFO, "Received SIGTERM, exiting...");
            exit(0);
        }
    }
    log_msg(config, LOG_INFO, "Disconnecting from Database...");
    kaspDisconnect(&dbhandle);

    /*
     * Destroy HSM context
     */
    if (ctx) {
      hsm_destroy_context(ctx);
    }

    result = hsm_close();
    log_msg(config, LOG_INFO, "all done! hsm_close result: %d\n", result);

    free(policy->name);
    free(policy->enforcer);
    free(policy->denial);
    free(policy->zsk);
    free(policy->ksk);
    free(policy->signature);
    free(policy->signer);
    free(policy);
}
<<<<<<< .mine
=======

/*
 * Generate keys according to policy 
 */
void
generateKeysForPolicy(DAEMONCONFIG *config, KSM_POLICY *policy, hsm_ctx_t *ctx)
{
    char *rightnow;
    DB_RESULT zone_handle;
    KSM_ZONE zone_data;
    int status = 0;
    DB_ID ksk_key_pair = 0;
    DB_ID zsk_key_pair = 0;
    DB_ID *ksk_array;
    DB_ID *zsk_array;
    DB_ID ignore = 0;
    int max_rollovers = 0;
    int keys_in_que = 0;
    int new_ksks = 0;
    int new_zsks = 0;
    int i = 0;

    status = KsmZoneInit(&zone_handle, policy->id);
    if (status != 0) {
        return;
    }

    /* We must have at least one zone */
    status = KsmZone(zone_handle, &zone_data);
    if (status != 0) {
        return;
    }

    rightnow = DtParseDateTimeString("now");

    if (policy->shared_keys == 1 ) {
        log_msg(config, LOG_INFO, "Key sharing is On");

        /* Predict how many keys we need to use */
        /* TODO: Check the status */
        status = ksmKeyPredict(policy->id, KSM_TYPE_KSK, config->keygeninterval, &max_rollovers);
        status = KsmRequestKeyQueCount(KSM_TYPE_KSK, &keys_in_que, zone_data.id);
        new_ksks = policy->ksk->emergency_keys + max_rollovers - keys_in_que;
        if (new_ksks > 0 ) {
            ksk_array = (DB_ID*)malloc(new_ksks * sizeof(DB_ID));
            if(ksk_array == NULL) return;
        } else {
            ksk_array = NULL;
        }

        for (i=0 ; i < new_ksks ; i++){
            ksk_array[i] = 0;
            generateKSK(config, policy, ctx, rightnow, &ksk_array[i]);
        }

        /* Predict how many keys we need to use */
        /* TODO: Check the status */
        status = ksmKeyPredict(policy->id, KSM_TYPE_ZSK, config->keygeninterval, &max_rollovers);
        status = KsmRequestKeyQueCount(KSM_TYPE_ZSK, &keys_in_que, zone_data.id);
        new_zsks = policy->zsk->emergency_keys + max_rollovers - keys_in_que;
        if (new_zsks > 0 ) {
            zsk_array = (DB_ID*)malloc(new_zsks * sizeof(DB_ID));
            if(zsk_array == NULL) {
                if(ksk_array != NULL) free(ksk_array);
                return;
            }
        } else {
            zsk_array = NULL;
        }


        /* Generate keys */
        for (i=0 ; i < new_zsks ; i++){
            zsk_array[i] = 0;
            generateZSK(config, policy, ctx, rightnow, &zsk_array[i]);
        }

        /* Add the keys to the zones */
        status = 0;
        while(status == 0) {
            for (i=0 ; i < new_ksks ; i++){
                if(ksk_array[i] > 0) {
                    KsmDnssecKeyCreate(zone_data.id, ksk_array[i], KSM_TYPE_KSK, &ignore);
                }
            }
            for (i=0 ; i < new_zsks ; i++){
                if(zsk_array[i] > 0) {
                    KsmDnssecKeyCreate(zone_data.id, zsk_array[i], KSM_TYPE_ZSK, &ignore);
                }
            }
            status = KsmZone(zone_handle, &zone_data);
        }

        if(ksk_array != NULL) free(ksk_array);
        if(zsk_array != NULL) free(zsk_array);
    } else {
        log_msg(config, LOG_INFO, "Key sharing is Off.");

        /* Do this for all zones */
        while(status == 0) {
            /* Predict how many keys we need to use */
            /* TODO: Check the status */
            status = ksmKeyPredict(policy->id, KSM_TYPE_KSK, config->keygeninterval, &max_rollovers);
            status = KsmRequestKeyQueCount(KSM_TYPE_KSK, &keys_in_que, zone_data.id);
            new_ksks = policy->ksk->emergency_keys + max_rollovers - keys_in_que;

            /* Generate keys */
            for (i=0 ; i < new_ksks ; i++){
                ksk_key_pair = 0;
                generateKSK(config, policy, ctx, rightnow, &ksk_key_pair);
                if(ksk_key_pair > 0) {
                    KsmDnssecKeyCreate(zone_data.id, ksk_key_pair, KSM_TYPE_KSK, &ignore);
                }
            }

            /* Predict how many keys we need to use */
            /* TODO: Check the status */
            status = ksmKeyPredict(policy->id, KSM_TYPE_ZSK, config->keygeninterval, &max_rollovers);
            status = KsmRequestKeyQueCount(KSM_TYPE_ZSK, &keys_in_que, zone_data.id);
            new_zsks = policy->zsk->emergency_keys + max_rollovers - keys_in_que;

            /* Generate keys */
            for (i=0 ; i < new_zsks ; i++){
                zsk_key_pair = 0;
                generateZSK(config, policy, ctx, rightnow, &zsk_key_pair);
                if(zsk_key_pair > 0) {
                    KsmDnssecKeyCreate(zone_data.id, ksk_key_pair, KSM_TYPE_ZSK, &ignore);
                }
            }

            /* Get the next zone */
            status = KsmZone(zone_handle, &zone_data);
        }
    }

    StrFree(rightnow);
}

/*
 * Generate KSK in HSM
 */
void
generateKSK(DAEMONCONFIG *config, KSM_POLICY *policy, hsm_ctx_t *ctx, char *rightnow, DB_ID *key_pair_id)
{
    int status = 0;
    hsm_key_t *key = NULL;
    char *id;

    if (policy->ksk->algorithm == 5 ) {
        /* TODO: check capacity of HSM will not be exceeded */
        key = hsm_generate_rsa_key(ctx, policy->ksk->sm_name, policy->ksk->bits);
        if (key) {
            log_msg(config, LOG_INFO,"Created key in HSM\n");
        } else {
            log_msg(config, LOG_ERR,"Error creating key in HSM\n");
            return;
        }
        id = hsm_get_key_id(ctx, key);
        status = KsmKeyPairCreate(policy->id, id, policy->ksk->sm, policy->ksk->bits, policy->ksk->algorithm, rightnow, key_pair_id);
        log_msg(config, LOG_INFO, "Created KSK size: %i, alg: %i with ID: %s in HSM: %s.", policy->ksk->bits,
                policy->ksk->algorithm, id, policy->ksk->sm_name);
        free(id);
    } else {
        log_msg(config, LOG_ERR, "Key algorithm unsupported by libhsm.");
        return;
    }
}

/*
 * Generate ZSK in HSM
 */
void
generateZSK(DAEMONCONFIG *config, KSM_POLICY *policy, hsm_ctx_t *ctx, char *rightnow, DB_ID *key_pair_id)
{
    int status = 0;
    hsm_key_t *key = NULL;
    char *id;

    if (policy->zsk->algorithm == 5 ) {
        /* TODO: check capacity of HSM will not be exceeded */
        key = hsm_generate_rsa_key(ctx, policy->zsk->sm_name, policy->zsk->bits);
        if (key) {
            log_msg(config, LOG_INFO,"Created key in HSM\n");
        } else {
            log_msg(config, LOG_ERR,"Error creating key in HSM\n");
            return;
        }
        id = hsm_get_key_id(ctx, key);
        status = KsmKeyPairCreate(policy->id, id, policy->zsk->sm, policy->zsk->bits, policy->zsk->algorithm, rightnow, key_pair_id);
        log_msg(config, LOG_INFO, "Created ZSK size: %i, alg: %i with ID: %s in HSM: %s.", policy->zsk->bits,
                policy->zsk->algorithm, id, policy->zsk->sm_name);
        free(id);
    } else {
        log_msg(config, LOG_ERR, "Key algorithm unsupported by libhsm.");
        return;
    }
}
>>>>>>> .r976
