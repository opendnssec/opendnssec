/*
 * Copyright (c) 2011 Surfnet 
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2011 OpenDNSSEC AB (svb)
 * All rights reserved.
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

#include "hsmkey/hsmkey_gen_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "libhsm.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "hsmkey/hsmkey.pb.h"
#include "policy/kasp.pb.h"
#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"
#include "daemon/clientpipe.h"

#include <fcntl.h>
#include <string.h>
#include <memory>
#include <math.h>

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

static const char *module_str = "hsmkey_gen_task";

static bool
generate_keypair(int sockfd,
				 const char *repository,
				 unsigned int keysize,
				 std::string &locator)
{
    hsm_key_t *key = NULL;
    hsm_ctx_t *ctx = hsm_create_context();
    if (!ctx) {
		ods_log_error_and_printf(sockfd,module_str,"could not connect to HSM");
        return false;
    }
    
    /* Check for repository before starting using it */
    if (hsm_token_attached(ctx, repository) == 0) {
        hsm_print_error(ctx);
        hsm_destroy_context(ctx);
        return false;
    }
    
    ods_log_debug("[%s] Generating %d bit RSA key in repository: %s",
                  module_str,keysize,repository);
    client_printf(sockfd,"generating %d bit RSA key in repository: %s\n",
			   keysize, repository);

    key = hsm_generate_rsa_key(ctx, repository, keysize);
    if (key) {
        hsm_key_info_t *key_info;
        key_info = hsm_get_key_info(ctx, key);
        locator.assign(key_info ? key_info->id : "NULL");

        ods_log_debug("[%s] Key generation successful: %s",
					  module_str,locator.c_str());
        client_printf(sockfd,"key generation successful: %s\n",locator.c_str());
        
        hsm_key_info_free(key_info);
#if 0
        hsm_print_key(key);
#endif
        hsm_key_free(key);
    } else {
        ods_log_error_and_printf(sockfd, module_str, "key generation failed");
        hsm_destroy_context(ctx);
        return false;
    }
    hsm_destroy_context(ctx);
    return true;
}

static bool
generate_keypairs(int sockfd,
				  OrmConn conn,
				  int ngen,
				  int nbits,
				  const char *repository,
				  const char *policy_name,
				  ::google::protobuf::uint32 algorithm,
				  ::ods::hsmkey::keyrole role,
				  struct engineconfig_repository* hsm)
{
	// nothing todo !
	if (ngen<=0) {
		client_printf(sockfd,
				   "no %s keys of %d bits needed for policy '%s'.\n",
				   ::ods::hsmkey::keyrole_Name(role).c_str(),
				   nbits, policy_name);
		return true;
	}
	
    bool bkeysgenerated_and_stored = false;
    
    client_printf(sockfd,
			   "generating %d %ss of %d bits for policy '%s'.\n",
			   ngen,
			   ::ods::hsmkey::keyrole_Name(role).c_str(),
			   nbits, policy_name);
    
    // Generate additional keys until certain minimum number is 
    // available.
    for ( ;ngen>0; --ngen) {
        std::string locator;
        if (!generate_keypair(sockfd,repository,nbits,locator)) {
            // perhaps this HSM can't generate keys of this size.
            ods_log_error_and_printf(sockfd,
									 module_str,
									 "unable to generate a %s of %d bits",
									 ::ods::hsmkey::keyrole_Name(role).c_str(),
									 nbits);
            break;
		} else {
			
			// initialize the db hsm key with info from the generated hsm key.
            ::ods::hsmkey::HsmKey key;
            key.set_locator(locator);
            key.set_bits(nbits);
            key.set_repository(repository);
            key.set_policy(policy_name);
            key.set_algorithm(algorithm);
            key.set_role(role);
            key.set_key_type("RSA");

            key.set_backedup(0);
            key.set_backmeup(0);
			while (hsm) {
				if (strcmp(repository, hsm->name))
					key.set_requirebackup(hsm->require_backup);
				hsm = hsm->next;
			}

			{
				// We do insertion of the generated key into the database here
				// after generating of the key.
				// Key generation can take a long time so we accept the risk of 
				// creating orphaned keys in the hsm that are not registered in
				// the database because the transaction to insert them failed.
				OrmTransactionRW transaction(conn);
				const char *errmsg = NULL;
				if (!transaction.started())
					errmsg = "error starting transaction for storing "
							 "generated hsm key in the database.";
				else {
					pb::uint64 keyid;
					if (!OrmMessageInsert(conn, key, keyid)) 
						errmsg = "error inserting generated hsm key into "
								 "the database.";
					else {
						if (!transaction.commit())
							errmsg = "error commiting generated hsm key to "
									 "the database.";
						else
							bkeysgenerated_and_stored = true;
					}
				}
				if (errmsg) {
					ods_log_error_and_printf(sockfd, module_str, errmsg);
					break;
				}
			}
        }
    }
    
    if (ngen<=0) {
        client_printf(sockfd,
				   "finished generating %d bit %ss.\n",
				   nbits,
				   ::ods::hsmkey::keyrole_Name(role).c_str());
    }
    return bkeysgenerated_and_stored;
}

static bool
count_unused_hsmkeys(OrmConn conn,
					 const std::string &policy,
					 const std::string &repository,
					 pb::uint32 algorithm,
					 int bits,
					 ::ods::hsmkey::keyrole role,
					 int &nunusedkeys)
{
	nunusedkeys = 0;
	
	OrmTransaction transaction(conn);
	if (!transaction.started())
		return false;
	
	// Count the keys that match this 
	OrmResultRef rows;
	if (OrmMessageEnumWhere(conn,::ods::hsmkey::HsmKey::descriptor(),
							rows,"inception IS NULL")) 
	{
		for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
			::ods::hsmkey::HsmKey key;
			if (OrmGetMessage(rows, key, true)) {
				
				// only count keys that are not used and 
				// thus have inception not set.
				if (!key.has_inception()) {
					// key is available
					if (key.bits() == bits
						&& key.role() == role
						&& key.policy() == policy
						&& key.repository() == repository
						&& key.algorithm() == algorithm
						)
					{
						// This key has all the right properties
						++nunusedkeys;
					}
				}
			}
		}
		rows.release();
	}
	
	return true;
}

static void
generate_ksks(int sockfd, OrmConn conn, const ::ods::kasp::Policy &policy,
			  time_t duration, pb::uint64 nzones, struct engineconfig_repository* hsm)
{
	::ods::hsmkey::keyrole key_role = ::ods::hsmkey::KSK;
	for (int k=0; k<policy.keys().ksk_size(); ++k) {
		const ::ods::kasp::Ksk& key = policy.keys().ksk(k);
		int nunusedkeys;
		if (!count_unused_hsmkeys(conn,
								  policy.name(),
								  key.repository(),
								  key.algorithm(),
								  key.bits(),
								  key_role,
								  nunusedkeys))
		{
			ods_log_error_and_printf(sockfd,module_str,
									 "counting KSKs failed");
		} else {
			int key_pregen = (int)ceil((double)duration/(double)key.lifetime());
			if (!generate_keypairs(sockfd,
								   conn,
								   (nzones*key_pregen)-nunusedkeys,
								   key.bits(),
								   key.repository().c_str(),
								   policy.name().c_str(),
								   key.algorithm(),
								   key_role, hsm))
			{
				ods_log_error_and_printf(sockfd,module_str,
										 "generating KSKs failed");
			}
		}
	}
}

static void
generate_zsks(int sockfd, OrmConn conn, const ::ods::kasp::Policy &policy,
			  time_t duration, pb::uint64 nzones, struct engineconfig_repository* hsm)
{
	::ods::hsmkey::keyrole key_role = ::ods::hsmkey::ZSK;
	for (int k=0; k<policy.keys().zsk_size(); ++k) {
		const ::ods::kasp::Zsk& key = policy.keys().zsk(k);
		int nunusedkeys;
		if (!count_unused_hsmkeys(conn,
								  policy.name(),
								  key.repository(),
								  key.algorithm(),
								  key.bits(),
								  key_role,
								  nunusedkeys))
		{
			ods_log_error_and_printf(sockfd,module_str,
									 "counting ZSKs failed");
		} else {
			int key_pregen = (int)ceil((double)duration/(double)key.lifetime());
			if (!generate_keypairs(sockfd,
								   conn,
								   (nzones*key_pregen)-nunusedkeys,
								   key.bits(),
								   key.repository().c_str(),
								   policy.name().c_str(),
								   key.algorithm(),
								   key_role, hsm))
			{
				ods_log_error_and_printf(sockfd,module_str,
										 "generating ZSKs failed");
			}
		}
	}
}

static void
generate_csks(int sockfd, OrmConn conn, const ::ods::kasp::Policy &policy,
			  time_t duration, pb::uint64 nzones, struct engineconfig_repository* hsm)
{
	::ods::hsmkey::keyrole key_role = ::ods::hsmkey::CSK;
	for (int k=0; k<policy.keys().csk_size(); ++k) {
		const ::ods::kasp::Csk& key = policy.keys().csk(k);
		int nunusedkeys;
		if (!count_unused_hsmkeys(conn,
								  policy.name(),
								  key.repository(),
								  key.algorithm(),
								  key.bits(),
								  key_role,
								  nunusedkeys))
		{
			ods_log_error_and_printf(sockfd,module_str,
									 "counting CSKs failed");
		} else {
			int key_pregen = (int)ceil((double)duration/(double)key.lifetime());
			if (!generate_keypairs(sockfd,
								   conn,
								   (nzones*key_pregen)-nunusedkeys,
								   key.bits(),
								   key.repository().c_str(),
								   policy.name().c_str(),
								   key.algorithm(),
								   key_role, hsm))
			{
				ods_log_error_and_printf(sockfd,module_str,
										 "generating CSKs failed");
			}
		}
	}
}

bool count_zones_for_policy(int sockfd,
							OrmConn conn,
							const std::string &policy,
							pb::uint64 &count)
{
	count = 0;
	
	OrmTransaction transaction(conn);
	if (!transaction.started()) {
		ods_log_error_and_printf(sockfd, module_str,
								 "starting transaction failed");
		return false;
	}
	
	std::string qpolicy;
	if (!OrmQuoteStringValue(conn, policy, qpolicy)) {
		ods_log_error_and_printf(sockfd,module_str,
								 "quoting a string failed");
		return false;
	}

	const ::google::protobuf::Descriptor *zdesc =
		::ods::keystate::EnforcerZone::descriptor();
	if (!OrmMessageCountWhere(conn,zdesc,count,"policy=%s",qpolicy.c_str()))
	{
		ods_log_error_and_printf(sockfd,module_str,
							"counting zones associated with policy %s failed",
								 policy.c_str() );
		return false;
	}

	return true;
}

int 
perform_hsmkey_gen(int sockfd, engineconfig_type *config, int bManual,
				   time_t duration)
{
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    // If only manual key generation is allowed and we are not being called 
    // manually, then return.
    if (config->manual_keygen != 0 && bManual == 0) {
        ods_log_debug("[%s] not generating keys, because ManualKeyGeneration "
                      "flag is set in conf.xml.",
                      module_str);
        client_printf(sockfd,
				   "not generating keys, because ManualKeyGeneration flag is "
				   "set in conf.xml.\n");
        return 1;
    }
    
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return 1; // errors have already been reported.
	
	// load all policies into memory, we are going to be modifying the database 
	// hsm key tables later on in multiple separate transactions. We therefore 
	// need to finalize the transaction used to access the policies because
	// transaction nesting may not be possible on all databases.
	::ods::kasp::KASP kasp;
	{	OrmTransaction transaction(conn);
		if (!transaction.started()) {
			ods_log_error_and_printf(sockfd, module_str,
									 "starting transaction failed");
			return 1;
		}
		
		{	OrmResultRef rows;
			if (!OrmMessageEnum(conn,::ods::kasp::Policy::descriptor(),rows)) {
				ods_log_error_and_printf(sockfd, module_str,
										 "enumerating policies failed");
				return 1;
			}
			
			for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
				::ods::kasp::Policy *policy = kasp.add_policies();
				if (!policy) {
					ods_log_error_and_printf(sockfd, module_str,
											 "out of memory allocating policy");
					return 1;
				}
				
				if (!OrmGetMessage(rows, *policy, true)) {
					ods_log_error_and_printf(sockfd, module_str,
										"reading policy from database failed");
					return 1;
				}
			}
		}
	}	

    for (int i=0; i<kasp.policies_size(); ++i) {

		pb::uint64 count;
		if (!count_zones_for_policy(sockfd,conn,kasp.policies(i).name(),count)) {
			ods_log_error_and_printf(sockfd,
									 module_str,
									 "skipping key generation for %s policy",
									 kasp.policies(i).name().c_str());
			continue;
		}
		/** if ShareKeys set, don't multiply nr of pregenerated keys
		 * with the number of zones using this policy. */
		if (count > 0 && kasp.policies(i).keys().zones_share_keys())
			count = 1;
		generate_ksks(sockfd, conn, kasp.policies(i), duration, count, config->hsm);
		generate_zsks(sockfd, conn, kasp.policies(i), duration, count, config->hsm);
		generate_csks(sockfd, conn, kasp.policies(i), duration, count, config->hsm);
    }
    return 0;
}

static task_type *
hsmkey_gen_task_perform(task_type *task)
{
	engineconfig_type *config = (engineconfig_type *)task->context;
	time_t duration = config->automatic_keygen_duration;
	(void)perform_hsmkey_gen(-1, config, 0, duration);
	task_cleanup(task);
	return NULL;
}

task_type *
hsmkey_gen_task(engineconfig_type *config)
{
    const char *what = "pre-generate";
    const char *who = "hsm keys";
    task_id what_id = task_register(what,
                                    "hsmkey_gen_task_perform",
                                    hsmkey_gen_task_perform);
	return task_create(what_id, time_now(), who, (void*)config);
}
