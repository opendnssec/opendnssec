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

#include <uuid/uuid.h>
#include "datetime.h"
#include "string_util.h"

int
server_init(DAEMONCONFIG *config)
{
  /* May remove this function if I decide we don't need it */
  return 0;
}

uuid_t *dummy_hsm_keygen(){
  uuid_t *uuid;
  uuid  = malloc(sizeof(uuid_t));
  uuid_generate(*uuid);
  return uuid;
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
  int count = 0;
  int i = 0;
  uuid_t *uuid;
  char uuid_text[37];
  char *rightnow;
  DB_ID* ignore;
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

    status = ReadConfig(config);
    if (status != 0) {
      log_msg(config, LOG_ERR, "Error reading config");
      exit(1);
    }
    
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
			
			rightnow = DtParseDateTimeString("now");
			/* Find out how many ksk keys are needed */
      status = ksmKeyPredict(policy->id, KSM_TYPE_KSK, 0, config->keygeninterval, &count);
      for (i=count ; i > 0 ; i--){
        uuid = dummy_hsm_keygen();
        uuid_unparse(*uuid, uuid_text);
        status = KsmKeyPairCreate(policy->id, uuid_text, policy->ksk->sm, policy->ksk->bits, policy->ksk->algorithm, rightnow, ignore);
        log_msg(config, LOG_INFO, "Created KSK size: %i, alg: %i with uuid: %s in HSM ID: %i.", policy->ksk->bits, policy->ksk->algorithm, uuid_text, policy->ksk->sm);
        free(uuid);
      }
      /* Find out how many zsk keys are needed */
      status = ksmKeyPredict(policy->id, KSM_TYPE_ZSK, 0, config->keygeninterval, &count);
      for (i = count ; i > 0 ; i--){
        uuid = dummy_hsm_keygen();
        uuid_unparse(*uuid, uuid_text);
        status = KsmKeyPairCreate(policy->id, uuid_text, policy->zsk->sm, policy->zsk->bits, policy->zsk->algorithm, rightnow, ignore);
        log_msg(config, LOG_INFO, "Created ZSK with size: %i, alg: %i with uuid: %s in HSM ID: %i.", policy->zsk->bits, policy->zsk->algorithm, uuid_text, policy->zsk->sm);
        free(uuid);
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
