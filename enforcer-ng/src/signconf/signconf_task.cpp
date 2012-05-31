/*
 * $Id$
 *
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

#include <memory>
#include <fcntl.h>

#include "signconf/signconf_task.h"
#include "shared/file.h"
#include "shared/duration.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "xmlext-pb/xmlext-rd.h"
#include "xmlext-pb/xmlext-wr.h"
#include "signconf/signconf.pb.h"
#include "policy/kasp.pb.h"
#include "keystate/keystate.pb.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

static const char *module_str = "signconf_task";

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

static bool
write_signer_configuration_to_file(int sockfd,
								   const ::ods::kasp::Policy *policy,
								   const ::ods::keystate::EnforcerZone *ks_zone)
{
	std::auto_ptr< ::ods::signconf::SignerConfigurationDocument > signconfdoc( 
							new ::ods::signconf::SignerConfigurationDocument );
	::ods::signconf::Zone *sc_zone =
					signconfdoc->mutable_signerconfiguration()->mutable_zone();
	sc_zone->set_name(ks_zone->name());
	
	// Get the Signatures parameters straight from the policy.
	::ods::signconf::Signatures *sc_sigs = sc_zone->mutable_signatures();
	const ::ods::kasp::Signatures &kp_sigs = policy->signatures();
	
	sc_sigs->set_resign( kp_sigs.resign() );
	sc_sigs->set_refresh( kp_sigs.refresh() );
	sc_sigs->set_valdefault( kp_sigs.valdefault() );
	sc_sigs->set_valdenial( kp_sigs.valdenial() );
	sc_sigs->set_jitter( kp_sigs.jitter() );
	sc_sigs->set_inceptionoffset( kp_sigs.inceptionoffset() );
	sc_sigs->set_max_zone_ttl( kp_sigs.max_zone_ttl() );
	
	// Get the Denial parameters straight from the policy
	::ods::signconf::Denial *sc_denial = sc_zone->mutable_denial();
	const ::ods::kasp::Denial &kp_denial = policy->denial();
	
	if (kp_denial.has_nsec() && kp_denial.has_nsec3()) {
		ods_log_error_and_printf(sockfd, module_str,
								 "policy %s contains both NSEC and NSEC3 in "
								 "Denial for zone %s", 
								 ks_zone->policy().c_str(),
								 ks_zone->name().c_str());
		return false;
	} else {
		if (!kp_denial.has_nsec() && !kp_denial.has_nsec3()) {
			ods_log_error_and_printf(sockfd, module_str,
									 "policy %s does not contains NSEC or "
									 "NSEC3 in Denial for zone %s", 
									 ks_zone->policy().c_str(),
									 ks_zone->name().c_str());
			return false;
		} else {
			// NSEC
			if(!kp_denial.has_nsec())
				sc_denial->clear_nsec();
			else
				sc_denial->mutable_nsec();
			
			// NSEC3
			if (!kp_denial.has_nsec3()) 
				sc_denial->clear_nsec3();
			else {
				::ods::signconf::NSEC3 *sc_nsec3 = sc_denial->mutable_nsec3();
				const ::ods::kasp::NSEC3 &kp_nsec3 = kp_denial.nsec3();
				if (kp_nsec3.has_optout())
					sc_nsec3->set_optout( kp_nsec3.optout() );
				else
					sc_nsec3->clear_optout();
				sc_nsec3->set_algorithm( kp_nsec3.algorithm() );
				sc_nsec3->set_iterations( kp_nsec3.iterations() );
				sc_nsec3->set_salt( kp_nsec3.salt() );
			}
		}
	}
	
	// Get the Keys from the zone data and add them to the signer 
	// configuration
	::ods::signconf::Keys *sc_keys = sc_zone->mutable_keys();
	sc_keys->set_ttl( policy->keys().ttl() );
	
	for (int k=0; k<ks_zone->keys_size(); ++k) {
		const ::ods::keystate::KeyData &ks_key = ks_zone->keys(k);
		
		// first check whether we actually should write this key into the
		// signer configuration.
		if (!ks_key.publish() && !ks_key.active_ksk() && !ks_key.active_zsk())
			continue;
		
		// yes we need to write the key to the configuration.
		::ods::signconf::Key* sc_key = sc_keys->add_keys();
		
		if (ks_key.role() == ::ods::keystate::ZSK)
			sc_key->set_flags( 256 ); // ZSK
		else
			sc_key->set_flags( 257 ); // KSK,CSK
		
		sc_key->set_algorithm( ks_key.algorithm() );
		sc_key->set_locator( ks_key.locator() );
		
		
		// The active flag determines whether the KSK or ZSK
		// flag is written to the signer configuration.
		sc_key->set_ksk( ks_key.active_ksk() &&
						(ks_key.role() == ::ods::keystate::KSK
						 || ks_key.role() == ::ods::keystate::CSK) );
		sc_key->set_zsk( ks_key.active_zsk() &&
						(ks_key.role() == ::ods::keystate::ZSK
						 || ks_key.role() == ::ods::keystate::CSK) );
		sc_key->set_publish( ks_key.publish() );
		
		// The deactivate flag was intended to allow smooth key rollover.
		// With the deactivate flag present a normal rollover would be 
		// performed where signatures would be replaced immmediately.
		// With deactivate flag not present a smooth rollover would be 
		// performed where signatures that had not yet passed there refresh
		// timestamp could be recycled and gradually replaced with 
		// new signatures.
		// Currently this flag is not supported by the signer engine.
		// sc_key->set_deactivate(  );
	}
	
	const ::ods::kasp::Zone &kp_zone = policy->zone();
	sc_zone->set_ttl( kp_zone.ttl() );
	sc_zone->set_min( kp_zone.min() );
	sc_zone->set_serial( (::ods::signconf::serial) kp_zone.serial() );
	
	if (policy->audit_size() > 0)
		sc_zone->set_audit(true);
	else
		sc_zone->clear_audit();
	
    if (!write_pb_message_to_xml_file(signconfdoc.get(),
									  ks_zone->signconf_path().c_str()))
	{
		ods_log_error_and_printf(sockfd, module_str,
								 "unable to write  signer config %s",
								 ks_zone->signconf_path().c_str());
		return false;
	}

	return true;
}


/*
 * ForEvery zone Z in zonelist do
 *   if flag signerConfNeedsWriting is set then
 *      Assign the data from the zone and associated policy to the signer
 *          configuration object
 *      Write signer configuration XML file at the correct location taken
 *          from zonedata signerconfiguration field in the zone 
 */
void 
perform_signconf(int sockfd, engineconfig_type *config, int bforce)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	int signer_flag = 1;  /* Is the signer responding? (1 == yes) */
    
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return;
	
	{	OrmTransactionRW transaction(conn);
		if (!transaction.started()) {
			ods_log_error_and_printf(sockfd, module_str,
									 "could not start database transaction");
			return;
		}
		
		{	OrmResultRef rows;
			::ods::keystate::EnforcerZone zone;
			bool ok;
			if (bforce)
				ok = OrmMessageEnum(conn, zone.descriptor(),rows);
			else
				ok = OrmMessageEnumWhere(conn, zone.descriptor(), rows,
										 "signconf_needs_writing = 1");
			if (!ok) {
				ods_log_error_and_printf(sockfd, module_str,
										 "error enumerating zones");
				return;
			}

			// Go through all the enumerated zones that need to be written.
			bool bZonesUpdated = false;
			for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
				
				OrmContextRef context;
				if (!OrmGetMessage(rows, zone, true,context)) {
					ods_log_error_and_printf(sockfd, module_str,
											 "error reading zone");
					return;
				}

				::ods::kasp::Policy policy;
				if (!load_kasp_policy(conn, zone.policy(), policy)) {
					ods_log_error_and_printf(sockfd,module_str,
											 "failed to find kasp "
											 "policy \"%s\"",
											 zone.policy().c_str());
					continue; // skip to next zone
				}

				if (!write_signer_configuration_to_file(sockfd,&policy,&zone))
					continue; // skip to next zone
				
				if (zone.signconf_needs_writing()) {
					zone.set_signconf_needs_writing(false);
					if (!OrmMessageUpdate(context)) {
						ods_log_error_and_printf(sockfd, module_str,
												 "updating zone %s in the "
												 "database failed",
												 zone.name().c_str());
					} else {
						bZonesUpdated = true;
						
						if (signer_flag) {
							/* call the signer engine to tell it that something changed */
							/* TODO for beta version connect straight to the socket
							   should we make a blocking call on this?
							   should we call it here or after we have written all of the files?
							   have timeout if call is blocking */
							char signer_command[512];
							strcpy(signer_command, SIGNER_CLI_UPDATE);
							strcat(signer_command, " ");
							strcat(signer_command, zone.name().c_str());
							if (system(signer_command) != 0)
							{
								ods_log_error("Could not call signer engine");
								ods_log_info("Will continue: call 'ods-signer update' to manually update zones");
								signer_flag = 0;
							}
						}
					}
				}
			}
			// We have finished processing the zones...
			rows.release();
			
			if (bZonesUpdated) {
				if (!transaction.commit()) {
					ods_log_error_and_printf(sockfd, module_str,
							"error commiting updated zones to the database.");
				}
			}
		}
	}
}

static task_type * 
signconf_task_perform(task_type *task)
{
    perform_signconf(-1,(engineconfig_type *)task->context,0);
    task_cleanup(task);
    return NULL;
}

task_type *
signconf_task(engineconfig_type *config, const char *what, const char * who)
{
    task_id what_id = task_register(what, "signconf_task_perform",
                                    signconf_task_perform);
	return task_create(what_id, time_now(), who, (void*)config);
}
