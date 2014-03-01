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

#include "keystate/keystate_ds_submit_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "libhsm.h"
#include "libhsmdns.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "policy/kasp.pb.h"
#include "xmlext-pb/xmlext-rd.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <memory>
#include <fcntl.h>
#include <sys/stat.h>

static const char *module_str = "keystate_ds_submit_task";

static uint16_t
submit_dnskey_by_id(int sockfd,
					const char *ds_submit_command,
					const char *id,
					::ods::keystate::keyrole role,
					const char *zone,
					int algorithm,
					uint32_t ttl,
					bool force)
{
	struct stat stat_ret;
	/* Code to output the DNSKEY record  (stolen from hsmutil) */
	hsm_ctx_t *hsm_ctx = hsm_create_context();
	if (!hsm_ctx) {
		ods_log_error_and_printf(sockfd,
								 module_str,
								 "could not connect to HSM");
		return 0;
	}
	hsm_key_t *key = hsm_find_key_by_id(hsm_ctx, id);
	
	if (!key) {
		ods_log_error_and_printf(sockfd,
								 module_str,
								 "key %s not found in any HSM",
								 id);
		hsm_destroy_context(hsm_ctx);
		return 0;
	}
	
	char *dnskey_rr_str;

	hsm_sign_params_t *sign_params = hsm_sign_params_new();
	sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, zone);
	sign_params->algorithm = (ldns_algorithm)algorithm;
	sign_params->flags = LDNS_KEY_ZONE_KEY;
	sign_params->flags += LDNS_KEY_SEP_KEY; /*KSK=>SEP*/
	
	ldns_rr *dnskey_rr = hsm_get_dnskey(hsm_ctx, key, sign_params);
	/* Calculate the keytag for this key, we return it. */
	uint16_t keytag = ldns_calc_keytag(dnskey_rr);
	/* Override the TTL in the dnskey rr */
	if (ttl)
		ldns_rr_set_ttl(dnskey_rr, ttl);
	
#if 0
	ldns_rr_print(stdout, dnskey_rr);
#endif        
	dnskey_rr_str = ldns_rr2str(dnskey_rr);
	
	hsm_sign_params_free(sign_params);
	ldns_rr_free(dnskey_rr);
	hsm_key_free(key);

	/* Replace tab with white-space */
	for (int i = 0; dnskey_rr_str[i]; ++i) {
		if (dnskey_rr_str[i] == '\t') {
			dnskey_rr_str[i] = ' ';
		}
	}
	
	/* We need to strip off trailing comments before we send
	 to any clients that might be listening */
	for (int i = 0; dnskey_rr_str[i]; ++i) {
		if (dnskey_rr_str[i] == ';') {
			dnskey_rr_str[i] = '\n';
			dnskey_rr_str[i+1] = '\0';
			break;
		}
	}

	// submit the dnskey rr string to a configured
	// delegation signer submit program.
	if (!ds_submit_command || ds_submit_command[0] == '\0') {
		if (!force) {
			ods_log_error_and_printf(sockfd, module_str, 
				"No \"DelegationSignerSubmitCommand\" "
				"configured. No state changes made. "
				"Use --force to override.");
			keytag = 0;
		}
		/* else: Do nothing, return keytag. */
	} else if (stat(ds_submit_command, &stat_ret) != 0) {
		/* First check that the command exists */
		keytag = 0;
		ods_log_error_and_printf(sockfd, module_str,
			"Cannot stat file %s: %s", ds_submit_command,
			strerror(errno));
	} else if (S_ISREG(stat_ret.st_mode) && 
			!(stat_ret.st_mode & S_IXUSR || 
			  stat_ret.st_mode & S_IXGRP || 
			  stat_ret.st_mode & S_IXOTH)) {
		/* Then see if it is a regular file, then if usr, grp or 
		 * all have execute set */
		keytag = 0;
		ods_log_error_and_printf(sockfd, module_str,
			"File %s is not executable", ds_submit_command);
	} else {
		/* send records to the configured command */
		FILE *fp = popen(ds_submit_command, "w");
		if (fp == NULL) {
			keytag = 0;
			ods_log_error_and_printf(sockfd, module_str,
				"failed to run command: %s: %s",ds_submit_command,
				strerror(errno));
		} else {
			int bytes_written = fprintf(fp, "%s", dnskey_rr_str);
			if (bytes_written < 0) {
				keytag = 0;
				ods_log_error_and_printf(sockfd,  module_str,
					 "[%s] Failed to write to %s: %s", ds_submit_command,
					 strerror(errno));
			} else if (pclose(fp) == -1) {
				keytag = 0;
				ods_log_error_and_printf(sockfd, module_str,
					"failed to close %s: %s", ds_submit_command,
					strerror(errno));
			} else {
				ods_printf(sockfd, "key %s submitted to %s\n",
				   id, ds_submit_command);
			}
		}
	}
	LDNS_FREE(dnskey_rr_str);
	hsm_destroy_context(hsm_ctx);
	// Once the new DS records are seen in DNS please issue the ds-seen 
	// command for zone %s with the following cka_ids %s
	return keytag;
}

static bool
load_kasp_policy(OrmConn conn,const std::string &name,
				 ::ods::kasp::Policy &policy)
{
	std::string qname;
	if (!OrmQuoteStringValue(conn, name, qname))
		return false;
	
	OrmResultRef rows;
	if (!OrmMessageEnumWhere(conn,policy.descriptor(),rows,
							 "name=%s",qname.c_str()))
		return false;
	
	if (!OrmFirst(rows))
		return false;
	
	return OrmGetMessage(rows, policy, true);
}

static void
submit_keys(OrmConn conn,
			int sockfd,
			const char *zone,
			const char *id,
			const char *datastore,
			const char *ds_submit_command,
			bool force)
{
	#define LOG_AND_RETURN(errmsg)\
		do{ods_log_error_and_printf(sockfd,module_str,errmsg);return;}while(0)
	#define LOG_AND_RETURN_1(errmsg,p)\
		do{ods_log_error_and_printf(sockfd,module_str,errmsg,p);return;}while(0)

	OrmTransactionRW transaction(conn);
	if (!transaction.started())
		LOG_AND_RETURN("transaction not started");

	{	OrmResultRef rows;
		::ods::keystate::EnforcerZone enfzone;
		if (zone) {
			std::string qzone;
			if (!OrmQuoteStringValue(conn, std::string(zone), qzone))
				LOG_AND_RETURN("quoting string value failed");
			
			if (!OrmMessageEnumWhere(conn,enfzone.descriptor(),rows,"name = %s",qzone.c_str()))
				LOG_AND_RETURN("zone enumeration failed");
		} else {
			if (!OrmMessageEnum(conn,enfzone.descriptor(),rows))
				LOG_AND_RETURN("zone enumeration failed");
		}

		bool bZonesModified = false;

		if (!OrmFirst(rows)) {
			if (zone)
				LOG_AND_RETURN_1("zone %s not found",zone);
		} else {
			
			for (bool next=true; next; next=OrmNext(rows)) {
				
				OrmContextRef context;
				if (!OrmGetMessage(rows, enfzone, /*zones + keys*/true, context))
					LOG_AND_RETURN("retrieving zone from database failed");
				
				// Try to change the state of a specific 'submitted' key to 'seen'.
				bool bKeyModified = false;
				for (int k=0; k<enfzone.keys_size(); ++k) {
					const ::ods::keystate::KeyData &key = enfzone.keys(k);
						
					// Don't ever submit ZSKs to the parent.
					if (key.role()==::ods::keystate::ZSK)
						continue;
					
					// Onlyt submit KSKs that have the submit flag set.
					if (key.ds_at_parent()!=::ods::keystate::submit)
						continue;
				
					// Find the policy for the zone and get the ttl for the dnskey
					uint32_t dnskey_ttl = 0;
					::ods::kasp::Policy policy;
					if (!load_kasp_policy(conn, enfzone.policy(), policy)) {
						ods_log_error_and_printf(sockfd,module_str,
												 "unable to load policy %s",
												 enfzone.policy().c_str());
						continue;
					}
					dnskey_ttl = policy.keys().ttl();

					if (id) {
						// --id <id>
						//     Force submit key to the parent for specific key id.
						if (key.locator()==id) {
							// submit key with this id to the parent
							uint16_t keytag = 
							submit_dnskey_by_id(sockfd,ds_submit_command,
												key.locator().c_str(),
												key.role(),
												enfzone.name().c_str(),
												key.algorithm(),
												dnskey_ttl, force);
							if (keytag)
							{
								::ods::keystate::KeyData *kd =
									enfzone.mutable_keys(k);
								kd->set_ds_at_parent(::ods::keystate::submitted);
								bKeyModified = true;
							}
						}
					} else {
						if (zone) {
							// --zone <zone>
							//     Force submit key to the parent for specific zone.
							if (enfzone.name()==zone) {
								// submit key for this zone to the parent
								uint16_t keytag = 
								submit_dnskey_by_id(sockfd,ds_submit_command,
													key.locator().c_str(),
													key.role(),
													enfzone.name().c_str(),
													key.algorithm(),
													dnskey_ttl, force);
								if (keytag)
								{
									::ods::keystate::KeyData *kd = 
										enfzone.mutable_keys(k);
									kd->set_ds_at_parent(::ods::keystate::submitted);
									bKeyModified = true;
								}
							}
						} else {
							// --auto
							//     Submit all keys to the parent that have
							//     the submit flag set.
							uint16_t keytag = 
							submit_dnskey_by_id(sockfd,ds_submit_command,
												key.locator().c_str(),
												key.role(),
												enfzone.name().c_str(),
												key.algorithm(),
												dnskey_ttl, force);
							if (keytag)
							{
								::ods::keystate::KeyData *kd = 
									enfzone.mutable_keys(k);
								kd->set_ds_at_parent(::ods::keystate::submitted);
								bKeyModified = true;
							}
						}
					}
				}
				
				if (bKeyModified) {
					if (!OrmMessageUpdate(context))
						LOG_AND_RETURN_1("failed to update zone %s in the database", enfzone.name().c_str());

					bZonesModified = true;
				}
			}
			
			// we no longer need the query result, so release it.
			rows.release();
			
		}

		// Report back the status of the operation.
		if (bZonesModified) {
			// Commit updated records to the database.
			if (!transaction.commit())
				LOG_AND_RETURN_1("unable to commit updated zone %s to the database",zone);
			
			ods_log_debug("[%s] key states have been updated",module_str);
			ods_printf(sockfd,"update of key states completed.\n");
		} else {
			ods_log_debug("[%s] key states are unchanged",module_str);
			if (id)
				ods_printf(sockfd,
						   "No key state changes for id \"%s\"\n",
						   id);
			else
				if (zone)
					ods_printf(sockfd,
							   "No key state changes for zone \"%s\"\n",
							   zone);
				else
					ods_printf(sockfd,"key states are unchanged\n");
		}
	}
	
	#undef LOG_AND_RETURN
	#undef LOG_AND_RETURN_1
}

static void
list_keys_submit(OrmConn conn, int sockfd, const char *datastore)
{
	#define LOG_AND_RETURN(errmsg)\
		do{ods_log_error_and_printf(sockfd,module_str,errmsg);return;}while(0)
	
	// List the keys with submit flags.
	ods_printf(sockfd,
			   "Database set to: %s\n"
			   "Submit Keys:\n"
			   "Zone:                           "
			   "Key role:     "
			   "Id:                                      "
			   "\n"
			   ,datastore
			   );

	OrmTransaction transaction(conn);
	if (!transaction.started())
		LOG_AND_RETURN("transaction not started");
	
	{	OrmResultRef rows;
		::ods::keystate::EnforcerZone enfzone;
		if (!OrmMessageEnum(conn,enfzone.descriptor(),rows))
			LOG_AND_RETURN("zone enumeration failed");

		for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
			
			if (!OrmGetMessage(rows, enfzone, /*zones + keys*/true))
				LOG_AND_RETURN("retrieving zone from database failed");
			
			for (int k=0; k<enfzone.keys_size(); ++k) {
				const ::ods::keystate::KeyData &key = enfzone.keys(k);

				// Don't suggest ZSKs can be submitted, don't list them.
				if (key.role() == ::ods::keystate::ZSK)
					continue;
				
				// Only show keys that have the submit flag set.
				if (key.ds_at_parent()!=::ods::keystate::submit)
					continue;
				
				std::string keyrole = keyrole_Name(key.role());
				ods_printf(sockfd,
						   "%-31s %-13s %-40s\n",
						   enfzone.name().c_str(),
						   keyrole.c_str(),
						   key.locator().c_str()
						   );
			}
		}
	}
	
	#undef LOG_AND_RETURN
}

void 
perform_keystate_ds_submit(int sockfd, engineconfig_type *config,
						   const char *zone, const char *id, int bauto,
						   bool force)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	if (ods_orm_connect(sockfd, config, conn)) {
		// Evaluate parameters and submit keys to the parent when instructed to.
		if (zone || id || bauto)
			submit_keys(conn,sockfd,zone,id,config->datastore,
						config->delegation_signer_submit_command, force);
		else
			list_keys_submit(conn,sockfd,config->datastore);
	}
}

static task_type * 
keystate_ds_submit_task_perform(task_type *task)
{
	perform_keystate_ds_submit(-1,(engineconfig_type *)task->context,NULL,NULL,
							   0, false);
	task_cleanup(task);
	return NULL;
}

task_type *
keystate_ds_submit_task(engineconfig_type *config, const char *what,
						const char *who)
{
	task_id what_id = task_register(what, "keystate_ds_submit_task_perform",
									keystate_ds_submit_task_perform);
	return task_create(what_id, time_now(), who, (void*)config);
}
