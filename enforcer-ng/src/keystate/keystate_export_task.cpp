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

/** Retrieve KEY from HSM, should only be called for DNSKEYs
 * @param id, locator of DNSKEY on HSM
 * @param zone, name of zone key belongs to
 * @param algorithm, alg of DNSKEY
 * @param ttl, ttl DS should get. if 0 DNSKEY_TTL is used.
 * @return RR on succes, NULL on error */
static ldns_rr *
get_dnskey(const char *id, const char *zone, int alg, uint32_t ttl)
{
	hsm_key_t *key;
	hsm_sign_params_t *sign_params;
	
	/* Code to output the DNSKEY record  (stolen from hsmutil) */
	hsm_ctx_t *hsm_ctx = hsm_create_context();
	if (!hsm_ctx) {
		ods_log_error("[%s] Could not connect to HSM", module_str);
		return NULL;
	}
	if (!(key = hsm_find_key_by_id(hsm_ctx, id))) {
		hsm_destroy_context(hsm_ctx);
		return NULL;
	}
	
	/* Sign params only need to be kept around 
	 * for the hsm_get_dnskey() call. */
	sign_params = hsm_sign_params_new();
	sign_params->owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, zone);
	sign_params->algorithm = (ldns_algorithm) alg;
	sign_params->flags = LDNS_KEY_ZONE_KEY | LDNS_KEY_SEP_KEY;
		
	/* Get the DNSKEY record */
	ldns_rr *dnskey_rr = hsm_get_dnskey(hsm_ctx, key, sign_params);

	hsm_key_free(key);
	hsm_sign_params_free(sign_params);
	hsm_destroy_context(hsm_ctx);
	
	/* Override the TTL in the dnskey rr */
	if (ttl) ldns_rr_set_ttl(dnskey_rr, ttl);
	
	return dnskey_rr;
}

/** get DNSKEY record and keytag, should only be called for DNSKEYs
 * @param[out] dnskey, DNSKEY in zonefile format
 * @param id, locator of DNSKEY on HSM
 * @param zone, name of zone key belongs to
 * @param algorithm, alg of DNSKEY
 * @param ttl, ttl DS should get. if 0 DNSKEY_TTL is used.
 * @return keytag on succes, 0 on error 
 * 
 * TODO: KEYTAG could very well be 0 THIS is not the right way to 
 * flag succes! */
static int 
dnskey_from_id(std::string &dnskey, const char *id, 
	const char *zone, int algorithm, uint32_t ttl)
{
	ldns_rr *dnskey_rr = get_dnskey(id, zone, algorithm, ttl);
	if (!dnskey_rr) return 0;

	char *rrstr = ldns_rr2str(dnskey_rr);
	dnskey = std::string(rrstr);
	LDNS_FREE(rrstr);
	ldns_rr_free(dnskey_rr);
	
	return 1;
}

/** Print SHA1 and SHA256 DS records, should only be called for DNSKEYs
 * @param sockfd, Where to print to
 * @param id, locator of DNSKEY on HSM
 * @param zone, name of zone key belongs to
 * @param algorithm, alg of DNSKEY
 * @param ttl, ttl DS should get. if 0 DNSKEY_TTL is used.
 * @return 1 on succes 0 on error */
static int 
print_ds_from_id(int sockfd, const char *id, const char *zone, 
	int algorithm, uint32_t ttl)
{
	ldns_rr *dnskey_rr = get_dnskey(id, zone, algorithm, ttl);
	if (!dnskey_rr) return 0;
	char *rrstr;
	ldns_rr *ds_sha_rr;
	
	/* DS record (SHA1) */
	ds_sha_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA1);
	rrstr = ldns_rr2str(ds_sha_rr);
	ods_printf(sockfd, ";KSK DS record (SHA1):\n%s", rrstr);
	LDNS_FREE(rrstr);
	ldns_rr_free(ds_sha_rr);
	
	/* DS record (SHA256) */
	ds_sha_rr = ldns_key_rr2ds(dnskey_rr, LDNS_SHA256);
	rrstr = ldns_rr2str(ds_sha_rr);
	ods_printf(sockfd, ";KSK DS record (SHA256):\n%s", rrstr);
	LDNS_FREE(rrstr);
	ldns_rr_free(ds_sha_rr);

	ldns_rr_free(dnskey_rr);
	return 1;
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

int 
perform_keystate_export(int sockfd, engineconfig_type *config, const char *zone,
						int bds)
{
	#define LOG_AND_RETURN(errmsg) do { ods_log_error_and_printf(\
		sockfd,module_str,errmsg); return 1; } while (0)
	#define LOG_AND_RETURN_1(errmsg,param) do { ods_log_error_and_printf(\
		sockfd,module_str,errmsg,param); return 1; } while (0)
	#define LOG_AND_RETURN_2(errmsg,param,param2) do { ods_log_error_and_printf(\
		sockfd,module_str,errmsg,param,param2); return 1; } while (0)

	GOOGLE_PROTOBUF_VERIFY_VERSION;
	
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return 1;
	
	OrmTransactionRW transaction(conn);
	if (!transaction.started())
		LOG_AND_RETURN("transaction not started");

	std::string qzone;
	if (!OrmQuoteStringValue(conn, std::string(zone), qzone))
		LOG_AND_RETURN("quoting string value failed");
	
	OrmResultRef rows;
	::ods::keystate::EnforcerZone enfzone;
	if (!OrmMessageEnumWhere(conn,enfzone.descriptor(), rows, 
		"name = %s", qzone.c_str()))
		LOG_AND_RETURN("zone enumeration failed");
	
	if (!OrmFirst(rows)) {
		ods_printf(sockfd,"zone %s not found\n",zone);
		return 1;
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
		
		if (!bds) {
			std::string dnskey;
			if (!dnskey_from_id(dnskey, key.locator().c_str(),
				enfzone.name().c_str(), key.algorithm(), dnskey_ttl))
			{
				LOG_AND_RETURN_2("unable to find key with id %s or can't hash algorithm %d",
					key.locator().c_str(), key.algorithm());
				
			} else {
				ods_writen(sockfd, dnskey.c_str(), dnskey.size());
			}
		} else {
			if (!print_ds_from_id(sockfd, key.locator().c_str(), 
				enfzone.name().c_str(), key.algorithm(), dnskey_ttl))
			{
				LOG_AND_RETURN_1("unable to find key with id %s on HSM",
					key.locator().c_str());
			}
		}
	}
	return 0;
}
