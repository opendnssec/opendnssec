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
 *	notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
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

#include "keystate/keystate_export_task.h"
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

static const char *module_str = "keystate_export_task";

static uint16_t 
dnskey_from_id(std::string &dnskey,
				const char *id,
				::ods::keystate::keyrole role,
				const char *zone,
				int algorithm,
				int bDS,
				uint32_t ttl)
{
	hsm_key_t *key;
	hsm_sign_params_t *sign_params;
	ldns_rr *dnskey_rr;
	ldns_algorithm algo = (ldns_algorithm)algorithm;
	
	/* Code to output the DNSKEY record  (stolen from hsmutil) */
	hsm_ctx_t *hsm_ctx = hsm_create_context();
	if (!hsm_ctx) {
		ods_log_error("[%s] Could not connect to HSM", module_str);
		return false;
	}
	key = hsm_find_key_by_id(hsm_ctx, id);
	
	if (!key) {
		// printf("Key %s in DB but not repository\n", id);
		hsm_destroy_context(hsm_ctx);
		return 0;
	}
	
	/*
	 * Sign params only need to be kept around 
	 * for the hsm_get_dnskey() call.
	 */
	sign_params = hsm_sign_params_new();
	sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, zone);
	sign_params->algorithm = algo;
	sign_params->flags = LDNS_KEY_ZONE_KEY;
	if (role == ::ods::keystate::KSK)
		sign_params->flags += LDNS_KEY_SEP_KEY; /*KSK=>SEP*/
	/* Get the DNSKEY record */
	dnskey_rr = hsm_get_dnskey(hsm_ctx, key, sign_params);
	hsm_sign_params_free(sign_params);
	/* Calculate the keytag for this key, we return it. */
	uint16_t keytag = ldns_calc_keytag(dnskey_rr);
	/* Override the TTL in the dnskey rr */
	if (ttl)
		ldns_rr_set_ttl(dnskey_rr, ttl);
	
	char *rrstr;
	if (!bDS) {
#if 0
		ldns_rr_print(stdout, dnskey_rr);
#endif
		rrstr = ldns_rr2str(dnskey_rr);
		dnskey = rrstr;
		LDNS_FREE(rrstr);
	} else {
	
		switch (algo) {
			case LDNS_RSASHA1: // 5
			{
				/* DS record (SHA1) */
				ldns_rr *ds_sha1_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA1);
#if 0
				ldns_rr_print(stdout, ds_sha1_rr);
#endif
				rrstr = ldns_rr2str(ds_sha1_rr);
				dnskey = rrstr;
				LDNS_FREE(rrstr);

				ldns_rr_free(ds_sha1_rr);
				break;
			}
			case LDNS_RSASHA256: // 8 - RFC 5702
			{
		
				/* DS record (SHA256) */
				ldns_rr *ds_sha256_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA256);
#if 0
				ldns_rr_print(stdout, ds_sha256_rr);
#endif
				rrstr = ldns_rr2str(ds_sha256_rr);
				dnskey = rrstr;
				LDNS_FREE(rrstr);

				ldns_rr_free(ds_sha256_rr);
				break;
			}
			default:
				ods_log_error("[%s] Can't hash algorithm %d.", module_str, algorithm);
				keytag = 0;
		}
	}
	ldns_rr_free(dnskey_rr);
	hsm_key_free(key);
	hsm_destroy_context(hsm_ctx);
	
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

void 
perform_keystate_export(int sockfd, engineconfig_type *config, const char *zone,
						int bds)
{
	#define LOG_AND_RETURN(errmsg) do { ods_log_error_and_printf(\
		sockfd,module_str,errmsg); return; } while (0)
	#define LOG_AND_RETURN_1(errmsg,param) do { ods_log_error_and_printf(\
		sockfd,module_str,errmsg,param); return; } while (0)

	GOOGLE_PROTOBUF_VERIFY_VERSION;
	
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return; // error already reported.
	
	{	OrmTransactionRW transaction(conn);
		if (!transaction.started())
			LOG_AND_RETURN("transaction not started");

		std::string qzone;
		if (!OrmQuoteStringValue(conn, std::string(zone), qzone))
			LOG_AND_RETURN("quoting string value failed");
		
		{	OrmResultRef rows;
			::ods::keystate::EnforcerZone enfzone;
			if (!OrmMessageEnumWhere(conn,enfzone.descriptor(),
									 rows,"name = %s",qzone.c_str()))
				LOG_AND_RETURN("zone enumeration failed");
			
			if (!OrmFirst(rows)) {
				ods_printf(sockfd,"zone %s not found\n",zone);
				return;
			}
			
			OrmContextRef context;
			if (!OrmGetMessage(rows, enfzone, /*zones + keys*/true, context))
				LOG_AND_RETURN("retrieving zone from database failed");
			
			// we no longer need the query result, so release it.
			rows.release();

			// Retrieve the dnskey ttl from the policy associated with the zone.
			::ods::kasp::Policy policy;
			if (!load_kasp_policy(conn, enfzone.policy(), policy))
				LOG_AND_RETURN_1("policy %s not found",enfzone.policy().c_str());
			uint32_t dnskey_ttl = policy.keys().ttl();

			bool bSubmitChanged = false;
			bool bRetractChanged = false;
			bool bKeytagChanged = false;
			
			for (int k=0; k<enfzone.keys_size(); ++k) {
				const ::ods::keystate::KeyData &key = enfzone.keys(k);
				if (key.role()==::ods::keystate::ZSK)
					continue;
				
				if (key.ds_at_parent()!=::ods::keystate::submit
					&& key.ds_at_parent()!=::ods::keystate::submitted
					&& key.ds_at_parent()!=::ods::keystate::retract
					&& key.ds_at_parent()!=::ods::keystate::retracted
					)
					continue;
				
				std::string dnskey;
				uint16_t keytag = dnskey_from_id(dnskey,key.locator().c_str(),
												 key.role(),
												 enfzone.name().c_str(),
												 key.algorithm(),bds,
												 dnskey_ttl);
				if (keytag) {
					ods_writen(sockfd, dnskey.c_str(), dnskey.size());
					bSubmitChanged = key.ds_at_parent()==::ods::keystate::submit;
					bRetractChanged = key.ds_at_parent()==::ods::keystate::retract;
					bKeytagChanged = key.keytag()!=keytag;
					if (bSubmitChanged) {
						::ods::keystate::KeyData *kd = enfzone.mutable_keys(k);
						kd->set_ds_at_parent(::ods::keystate::submitted);
					}
					if (bRetractChanged) {
						::ods::keystate::KeyData *kd = enfzone.mutable_keys(k);
						kd->set_ds_at_parent(::ods::keystate::retracted);
					}
					if (bKeytagChanged) {
						::ods::keystate::KeyData *kd = enfzone.mutable_keys(k);
						kd->set_keytag(keytag);
					}
				} else
					LOG_AND_RETURN_2("unable to find key with id %s or can't hash algorithm %d",
						key.locator().c_str(), key.algorithm());
			}
	
			if (bSubmitChanged || bRetractChanged || bKeytagChanged) {
				// Update the zone recursively in the database as keystates
				// have been changed because of the export
				
				if (!OrmMessageUpdate(context))
					LOG_AND_RETURN("updating zone in the database failed");
				
				if (!transaction.commit())
					LOG_AND_RETURN("committing zone to the database failed");
			}
		}
	}
}
