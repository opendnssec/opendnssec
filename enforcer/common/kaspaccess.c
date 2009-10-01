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
 * kaspaccess.c kasp acccess functions needed by keygend
 */


#include <syslog.h>
#include <stdlib.h>

#include "daemon.h"
#include "daemon_util.h"
#include "kaspaccess.h"
#include "ksm/string_util.h"
#include "ksm/string_util2.h"

/*
* Set defaults for policies
* TODO: need to think if we actually want to do this
* and if it is the appropriate place
* ALSO if we are doing set then make sure that we set everything 
*/
void
kaspSetPolicyDefaults(KSM_POLICY *policy, char *name)
{
    if (policy == NULL) {
        log_msg(NULL, LOG_ERR, "Error in kaspSetPolicyDefaults, no policy provided");
        return;
    }

	if (name) {
        if (policy->name) {
            StrFree(policy->name);
        }
        StrAppend(&policy->name, name);
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
    /* Note that all these XML derived strings are unsigned chars */
	if (DbConnect(handle, (char *)config->schema, (char *)config->host, (char *)config->password, (char *)config->user) != 0) {
        exit(-1);
    }

}

/*
* Disconnect from the DB
*/
void
kaspDisconnect(DB_HANDLE*handle)
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
    /* This fn checks that the policy exists for us */
    return KsmPolicyRead(policy);
}
