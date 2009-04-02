/* 
* kaspaccess.c kasp acccess functions needed by keygend
*
* Copyright (c) 2008 2009, John Dickinson. All rights reserved.
*
* See LICENSE for the license.
*/

/*
 * Get config from the KASP DB
 * Read the policy called opendnssec
 * This is a special policy that has no
 * zones associated with it.
 *
 */
#include <syslog.h>

#include "daemon.h"
#include "daemon_util.h"
#include "kaspaccess.h"
#include "ksm.h"

int
kaspReadConfig(DAEMONCONFIG* config)
{
	int status = 0;
	KSM_POLICY *policy;
	policy = (KSM_POLICY *)malloc(sizeof(KSM_POLICY));
	policy->signer = (KSM_SIGNER_POLICY *)malloc(sizeof(KSM_SIGNER_POLICY));
	policy->signature = (KSM_SIGNATURE_POLICY *)malloc(sizeof(KSM_SIGNATURE_POLICY));
	policy->ksk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
	policy->zsk = (KSM_KEY_POLICY *)malloc(sizeof(KSM_KEY_POLICY));
	policy->denial = (KSM_DENIAL_POLICY *)malloc(sizeof(KSM_DENIAL_POLICY));
	policy->enforcer = (KSM_ENFORCER_POLICY *)malloc(sizeof(KSM_ENFORCER_POLICY));
	policy->name = "opendnssec";
  kaspSetPolicyDefaults(policy,NULL);
	/* Check we are connected */
	/*if (! DbCheckConnected()) {
		return 0;
	}*/

	log_msg(config, LOG_INFO, "Reading config.\n");
	status = KsmPolicyRead(policy);
	if (status == 0) {
		log_msg(config, LOG_INFO, "Start global policy:\n");
		config->keygeninterval = policy->enforcer->keygeninterval;
		log_msg(config, LOG_INFO, "Key Generation Interval: %i\n", config->keygeninterval);
		log_msg(config, LOG_INFO, "End global policy.\n");
	}
	free(policy->enforcer);
	free(policy->denial);
	free(policy->zsk);
	free(policy->ksk);
	free(policy->signature);
	free(policy->signer);
	free(policy);
	return (status);

}

/*
* Set defaults for policies
* TODO: need to think if we actually want to do this
* and if it is the appropriate place
*/
void
kaspSetPolicyDefaults(KSM_POLICY *policy, char *name)
{

	if(name) policy->name = name;
	policy->signer->refresh = 0;
	policy->signer->jitter = 0;
	policy->signer->propdelay = 0;
	policy->signer->soamin = 0;
	policy->signer->soattl = 0;

	policy->signature->clockskew = 0;
	policy->signature->resign = 0;
	policy->signature->validity = 0;

	policy->denial->version = 0;
	policy->denial->resalt = 0;
	policy->denial->algorithm = 0;
	policy->denial->iteration = 0;
	policy->denial->optout = 0;
	policy->denial->ttl = 0;

	policy->ksk->algorithm = 0;
	policy->ksk->lifetime = 0;
	policy->ksk->sm = 0;
	policy->ksk->overlap = 0;
	policy->ksk->ttl = 0;
	policy->ksk->rfc5011 = 0;
	policy->ksk->type = KSM_TYPE_KSK;

	policy->zsk->algorithm = 0;
	policy->zsk->lifetime = 0;
	policy->zsk->sm = 0;
	policy->zsk->overlap = 0;
	policy->zsk->ttl = 0;
	policy->zsk->type = KSM_TYPE_ZSK;

	policy->enforcer->keycreate = 0;
}

/*
* Connect to the DB
*/
void
kaspConnect(DAEMONCONFIG* config, DB_HANDLE	*handle)
{
	/*
	 * Connect to the database
	 * specified on the command line
	 */

	/*
	 * TODO There is a memory leak in here somewhere
	 * ==7572== 16 bytes in 1 blocks are definitely lost in loss record 2 of 3
	 * ==7572==    at 0x4021BDE: calloc (vg_replace_malloc.c:397)
	 * ==7572==    by 0x804D40C: MemCalloc (memory.c:58)
	 * ==7572==    by 0x804B8C9: MsgRegister (message.c:111)
	 * ==7572==    by 0x804A42D: DbInitialize (database_connection.c:59)
	 * ==7572==    by 0x804A477: DbConnect (database_connection.c:117)
	 * ==7572==    by 0x804934E: kaspConnect (ods_kasp.c:39)
	 * ==7572==    by 0x80492D3: main (ods_enf.c:29)
	 *
	 */
	(void) DbConnect(handle, config->schema, config->host, config->password, config->user);

}

/*
* Disconnect from the DB
*/
void
kaspDisconnect(DAEMONCONFIG* config, DB_HANDLE*handle)
{
	/*
	 * Connect to the database
	 * specified on the command line
	 */

 (void) DbDisconnect(*handle); 

}

/*
* Read a policy
*/
int
kaspReadPolicy(KSM_POLICY* policy)
{
	int     status = 0;         /* Status return */

	/*
	 * Does the policy exist?
	 
	if (policy->name) {
		status = KsmPolicyExists(policy->name);
	} */
	if (status == 0 ) {
		/* OK read the policy */
		KsmPolicyRead(policy);
	}
	return (status);
}
