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

#include "keystate/keystate_ds_retract_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "libhsm.h"
#include "libhsmdns.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"
#include "daemon/clientpipe.h"
#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <memory>
#include <fcntl.h>
#include <sys/stat.h>

static const char *module_str = "keystate_ds_retract_task";

static bool 
retract_dnskey_by_id(int sockfd,
					const char *ds_retract_command,
					const char *id,
					::ods::keystate::keyrole role,
					const char *zone,
					int algorithm,
					bool force)
{
	struct stat stat_ret;
	/* Code to output the DNSKEY record  (stolen from hsmutil) */
	hsm_ctx_t *hsm_ctx = hsm_create_context();
	if (!hsm_ctx) {
		ods_log_error_and_printf(sockfd,
								 module_str,
								 "could not connect to HSM");
		return false;
	}
	hsm_key_t *key = hsm_find_key_by_id(hsm_ctx, id);
	
	if (!key) {
		ods_log_error_and_printf(sockfd,
								 module_str,
								 "key %s not found in any HSM",
								 id);
		hsm_destroy_context(hsm_ctx);
		return false;
	}
	
	bool bOK = false;
	char *dnskey_rr_str;
	
	hsm_sign_params_t *sign_params = hsm_sign_params_new();
	sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, zone);
	sign_params->algorithm = (ldns_algorithm)algorithm;
	sign_params->flags = LDNS_KEY_ZONE_KEY;
	sign_params->flags += LDNS_KEY_SEP_KEY; /*KSK=>SEP*/
	
	ldns_rr *dnskey_rr = hsm_get_dnskey(hsm_ctx, key, sign_params);
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
	// pass the dnskey rr string to a configured
	// delegation signer retract program.
	if (!ds_retract_command || ds_retract_command[0] == '\0') {
		if (!force) {
			ods_log_error_and_printf(sockfd, module_str, 
				"No \"DelegationSignerRetractCommand\" "
				"configured. No state changes made. "
				"Use --force to override.");
			bOK = false;
		}
		/* else: Do nothing, return keytag. */
	} else if (stat(ds_retract_command, &stat_ret) != 0) {
		/* First check that the command exists */
		ods_log_error_and_printf(sockfd, module_str,
			"Cannot stat file %s: %s", ds_retract_command,
			strerror(errno));
	} else if (S_ISREG(stat_ret.st_mode) && 
			!(stat_ret.st_mode & S_IXUSR || 
			  stat_ret.st_mode & S_IXGRP || 
			  stat_ret.st_mode & S_IXOTH)) {
		/* Then see if it is a regular file, then if usr, grp or 
		 * all have execute set */
		ods_log_error_and_printf(sockfd, module_str,
			"File %s is not executable", ds_retract_command);
	} else {
		/* send records to the configured command */
		FILE *fp = popen(ds_retract_command, "w");
		if (fp == NULL) {
			ods_log_error_and_printf(sockfd, module_str,
				"failed to run command: %s: %s", ds_retract_command,
				strerror(errno));
		} else {
			int bytes_written = fprintf(fp, "%s", dnskey_rr_str);
			if (bytes_written < 0) {
				ods_log_error_and_printf(sockfd, module_str,
					"[%s] Failed to write to %s: %s", ds_retract_command,
					strerror(errno));
			} else if (pclose(fp) == -1) {
				ods_log_error_and_printf(sockfd, module_str,
					"failed to close %s: %s", ds_retract_command,
					strerror(errno));
			} else {
				bOK = true;
				client_printf(sockfd, "key %s retracted by %s\n", id,
					ds_retract_command);
			}
		}
	}
	
	LDNS_FREE(dnskey_rr_str);
	hsm_destroy_context(hsm_ctx);
	return bOK;
}

static void
retract_keys(OrmConn conn,
			int sockfd,
			const char *zone,
			const char *id,
			const char *datastore,
			const char *ds_retract_command,
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
			
			if (!OrmMessageEnumWhere(conn,enfzone.descriptor(),
									 rows,"name = %s",qzone.c_str()))
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
				
				// Try to change the state of a specific 'retract' key to 'retracted'.
				bool bKeyModified = false;
				for (int k=0; k<enfzone.keys_size(); ++k) {
					const ::ods::keystate::KeyData &key = enfzone.keys(k);
					
					// Don't retract ZSKs from the parent.
					if (key.role()==::ods::keystate::ZSK)
						continue;
					
					// Only retract KSKs that have the retract flag set.
					if (key.ds_at_parent()!=::ods::keystate::retract)
						continue;

					if (id) {
						// --id <id>
						//     Force retract key to the parent for specific key id.
						if (key.locator()==id) {
							// retract key with this id from the parent
							if (retract_dnskey_by_id(sockfd,ds_retract_command,
													 key.locator().c_str(),
													 key.role(),
													 enfzone.name().c_str(),
													 key.algorithm(),
													 force))
							{
								::ods::keystate::KeyData *kd =
									enfzone.mutable_keys(k);
								kd->set_ds_at_parent(::ods::keystate::retracted);
								bKeyModified = true;
							}
						}
					} else {
						if (zone) {
							// --zone <zone>
							//     Force retract key from the parent for specific zone.
							if (enfzone.name()==zone) {
								// retract key for this zone from the parent
								if (retract_dnskey_by_id(sockfd,ds_retract_command,
														 key.locator().c_str(),
														 key.role(),
														 enfzone.name().c_str(),
														 key.algorithm(),
														 force))
								{
									::ods::keystate::KeyData *kd = 
									enfzone.mutable_keys(k);
									kd->set_ds_at_parent(::ods::keystate::retracted);
									bKeyModified = true;
								}
							}
						} else {
							// --auto
							//     Retract all keys from the parent that have
							//     the retract flag set.
							if (retract_dnskey_by_id(sockfd,ds_retract_command,
													 key.locator().c_str(),
													 key.role(),
													 enfzone.name().c_str(),
													 key.algorithm(),
													 force))
							{
								::ods::keystate::KeyData *kd = 
									enfzone.mutable_keys(k);
								kd->set_ds_at_parent(::ods::keystate::retracted);
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
			client_printf(sockfd,"update of key states completed.\n");
		} else {
			ods_log_debug("[%s] key states are unchanged",module_str);
			if (id)
				client_printf(sockfd,
						   "No key state changes for id \"%s\"\n",
						   id);
			else
				if (zone)
					client_printf(sockfd,
							   "No key state changes for zone \"%s\"\n",
							   zone);
				else
					client_printf(sockfd,"key states are unchanged\n");
		}
	}
	
	#undef LOG_AND_RETURN
	#undef LOG_AND_RETURN_1
}

static void
list_keys_retract(OrmConn conn, int sockfd, const char *datastore)
{
	#define LOG_AND_RETURN(errmsg)\
		do{ods_log_error_and_printf(sockfd,module_str,errmsg);return;}while(0)
	
	// List the keys with retract flags.
	client_printf(sockfd,
			   "Database set to: %s\n"
			   "List of keys eligible to be retracted:\n"
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
				
				// Don't suggest ZSKs can be retracted, don't show them
				if (key.role() == ::ods::keystate::ZSK)
					continue;
				
				// Only show keys that have the retract flag set.
				if (key.ds_at_parent()!=::ods::keystate::retract)
					continue;
				
				std::string keyrole = keyrole_Name(key.role());
				client_printf(sockfd,
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
perform_keystate_ds_retract(int sockfd, engineconfig_type *config,
							const char *zone, const char *id, int bauto,
							bool force)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	if (ods_orm_connect(sockfd, config, conn)) {
		// Evaluate parameters and retract keys from the parent when instructed to.
		if (zone || id || bauto)
			retract_keys(conn,sockfd,zone,id,config->datastore,
						 config->delegation_signer_retract_command, force);
		else
			list_keys_retract(conn,sockfd,config->datastore);
	}
}

static task_type * 
keystate_ds_retract_task_perform(task_type *task)
{
	perform_keystate_ds_retract(-1,(engineconfig_type *)task->context,NULL,NULL,
							   0, false);
	task_cleanup(task);
	return NULL;
}

task_type *
keystate_ds_retract_task(engineconfig_type *config, const char *what,
						const char *who)
{
	task_id what_id = task_register(what, "keystate_ds_retract_task_perform",
									keystate_ds_retract_task_perform);
	return task_create(what_id, time_now(), who, (void*)config);
}
