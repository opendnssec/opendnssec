/* 
 * communicator.c code implements the server_main
 * function needed by daemon.c
 *
 * The bit that makes the daemon do something useful
 *
 * Copyright (c) 2008 2009, John Dickinson. All rights reserved.
 *
 * See LICENSE for the license.
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "daemon.h"
#include "daemon_util.h"
#include "ksm.h"
#include "communicator.h"
#include "kaspaccess.h"
#include "string_util2.h"
#include "datetime.h"

    int
server_init(DAEMONCONFIG *config)
{
    /* May remove this function if I decide we don't need it */
    return 0;
}

/*
 * Main loop of keygend server
 */
    void
server_main(DAEMONCONFIG *config)
{
    DB_RESULT handle;
    DB_RESULT handle2;
    DB_HANDLE	dbhandle;
    int status = 0;
    int status2 = 0;

    KSM_ZONE *zone;
    KSM_POLICY *policy;

    policy = (KSM_POLICY *)malloc(sizeof(KSM_POLICY));
    policy->signer = (KSM_SIGNER_POLICY *)malloc(sizeof(KSM_SIGNER_POLICY));
    policy->signature = (KSM_SIGNATURE_POLICY *)malloc(sizeof(KSM_SIGNATURE_POLICY));
    policy->ksk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
    policy->zsk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
    policy->denial = (KSM_DENIAL_POLICY *)malloc(sizeof(KSM_DENIAL_POLICY));
    policy->enforcer = (KSM_ENFORCER_POLICY *)malloc(sizeof(KSM_ENFORCER_POLICY));
    policy->name = (char *)calloc(KSM_NAME_LENGTH, sizeof(char));
    kaspSetPolicyDefaults(policy, NULL);

    zone = (KSM_ZONE *)malloc(sizeof(KSM_ZONE));

    kaspConnect(config, &dbhandle);

    while (1) {

        /* Read all policies */
        status = KsmPolicyInit(&handle, NULL);
        if (status == 0) {
            /* get the first policy */
            status = KsmPolicy(handle, policy);
            while (status == 0) {
                log_msg(config, LOG_INFO, "Policy %s found.", policy->name);

                /* Got one; loop round zones on this policy */
                status2 = KsmZoneInit(&handle2, policy->id);
                if (status2 == 0) {
                    /* get the first zone */
                    status2 = KsmZone(handle2, zone);
                    while (status2 == 0) {
                        log_msg(config, LOG_INFO, "zone %s found.", zone->name);

                        /* turn this zone and policy into a file */
                        status2 = commGenSignConf(zone, policy);
                        if (status2 == 0) {
                            log_msg(config, LOG_ERR, "Error writing signconf");
                            exit(1);
                        }

                        /* get next zone */
                        status2 = KsmZone(handle2, zone);
                    }
                    /* get next policy */
                    status = KsmPolicy(handle, policy);
                }
		else
		{
            		log_msg(config, LOG_ERR, "Error querying KASP DB for zones");
            		exit(1);
		}
            }
        } else {
            log_msg(config, LOG_ERR, "Error querying KASP DB for policies");
            exit(1);
        }
        DbFreeResult(handle);

        /* sleep for the key gen interval */
        commsleep(config);

    }
    kaspDisconnect(config, &dbhandle);
    free(policy->name);
    free(policy->enforcer);
    free(policy->denial);
    free(policy->zsk);
    free(policy->ksk);
    free(policy->signature);
    free(policy->signer);
    free(policy);

    free(zone);
}

int commGenSignConf(KSM_ZONE *zone, KSM_POLICY *policy)
{
    int status = 0;
    FILE *file;
    char *filename;
    char*   datetime = DtParseDateTimeString("now");

    StrAppend(&filename, OUR_PATH);
    StrAppend(&filename, zone->name);
    StrAppend(&filename, ".xml");

    file = fopen(filename, "w");

    if (file == NULL)
    {
        /* error */
        return -1;
    }

    fprintf(file, "<SignerConfiguration>\n");
    fprintf(file, "\t<Zone name=\"%s\">\n", zone->name);

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
    fprintf(file, "\t\t\t<NSEC%d>\n", policy->denial->version);
    if (policy->denial->version == 3)
    {
        fprintf(file, "\t\t\t\t<OptOut />\n");
        fprintf(file, "\t\t\t\t<Hash>\n");
        fprintf(file, "\t\t\t\t\t<Algorithm>%d</Algorithm>\n", policy->denial->algorithm);
        fprintf(file, "\t\t\t\t\t<Iterations>%d</Iterations>\n", policy->denial->iteration);
        fprintf(file, "\t\t\t\t</Hash>\n");
    }
    fprintf(file, "\t\t\t</NSEC%d>\n", policy->denial->version);
    fprintf(file, "\t\t</Denial>\n");

    fprintf(file, "\n");
   
    /* start of keys section */ 
    fprintf(file, "\t\t<Keys>\n");
    fprintf(file, "\t\t\t<TTL>PT%dS</TTL>\n", policy->ksk->ttl);

    KsmRequestKeys(0, 0, datetime, commKeyConfig, file, policy->id, zone->id);

    fprintf(file, "\t\t</Keys>\n");

    fprintf(file, "\n");

    fprintf(file, "\t\t<SOA>\n");
    fprintf(file, "\t\t\t<TTL>PT%dS</TTL>\n", policy->signer->soattl);
    fprintf(file, "\t\t\t<Minimum>PT%dS</Minimum>\n", policy->signer->soamin);
    fprintf(file, "\t\t\t<Serial>%s</Serial>\n", KsmKeywordSerialValueToName( policy->signer->serial) );
    fprintf(file, "\t\t</SOA>\n");

    fprintf(file, "\t</Zone>\n");
    fprintf(file, "</SignerConfiguration>\n");

    status = fclose(file);

    if (status == EOF) /* close failed... do something? */
    {
        return -1;
    }

    return status;
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
    if (key_data->keytype == KSM_TYPE_KSK)
    {
        fprintf(file, "\t\t\t\t<KSK />\n");
    }
    else
    {
        fprintf(file, "\t\t\t\t<ZSK />\n");
    }
    fprintf(file, "\t\t\t\t<%s />\n", KsmKeywordStateValueToName(key_data->state));
    fprintf(file, "\t\t\t</Key>\n");
    fprintf(file, "\n");

    return 0;
}

/*
 * Go to sleep
 */

void commsleep(DAEMONCONFIG* config)
{
    struct timeval tv;

    tv.tv_sec = config->keygeninterval;
    tv.tv_usec = 0;
    log_msg(config, LOG_INFO, "Sleeping for %i seconds.",config->keygeninterval);
    select(0, NULL, NULL, NULL, &tv);
}
