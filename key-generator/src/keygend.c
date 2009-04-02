/* 
* keygend.c code implements the server_main
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

#include "daemon.h"
#include "daemon_util.h"
#include "keygend_util.h"
#include "ksm.h"
#include "kaspaccess.h"

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
  DB_HANDLE	dbhandle;
	int status = 0;

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
	
  kaspConnect(config, &dbhandle);
	
	while (1) {
		
		/* Read the special policy update the config struct and get the latest keygeninterval etc*/
    status = kaspReadConfig(config);
    if (status != 0) {
      log_msg(config, LOG_ERR, "Error querying KASP DB for the special policy");
      exit(1);
    }
    
		/* Read all policies */
		status = KsmPolicyInit(&handle, NULL);
		if (status == 0) {
			/* get the first policy */
			status = KsmPolicy(handle, policy);
			while (status == 0) {
			  log_msg(config, LOG_INFO, "Policy %s found.", policy->name);
//				/* For all but the special policy */
//			if (strncmp(policy->name, "opendnssec", 10) != 0) {
//				
//
//				/* Clear the policy struct */
//				kaspSetPolicyDefaults(policy, policy->name);
//
//					/* Read the parameters for that policy */
//					status = kaspReadPolicy(policy);
//
//					/* Create keys for policy */
//					/* status = Createkeys(config, policy); */
//				}
				/* get next policy */
				status = KsmPolicy(handle, policy);
			}
		} else {
		  log_msg(config, LOG_ERR, "Error querying KASP DB for policies");
      exit(1);
		}
		DbFreeResult(handle);
		
		/* sleep for the key gen interval */
    keygensleep(config);
		
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
}

//				/* For all but the special policy */
//			if (strncmp(policy->name, "opendnssec", 10) != 0) {
//				
//
//				/* Clear the policy struct */
//				kaspSetPolicyDefaults(policy, policy->name);
//
//					/* Read the parameters for that policy */
//					status = kaspReadPolicy(policy);
//
//					/* Create keys for policy */
//					/* status = Createkeys(config, policy); */
//				}