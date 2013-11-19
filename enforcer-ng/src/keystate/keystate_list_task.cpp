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

#include "keystate/keystate_list_task.h"
#include "shared/file.h"
#include "shared/duration.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <fcntl.h>

static const char *module_str = "keystate_list_task";

enum {KSK = 1, ZSK, CSK};
enum {KS_GEN = 0, KS_PUB, KS_RDY, KS_ACT, KS_RET, KS_DEA, KS_UNK, KS_MIX};
const char* statenames[] = {"generate", "publish", "ready", 
		"active", "retire", "dead", "unknown", "mixed"};
enum {DS_NSUB, DS_SUBM, DS_SBMD, DS_SEEN, DS_RETR, DS_RTRD};

/** Map 2.0 states to 1.x states
 * @param p: state of RR higher in the chain (e.g. DS)
 * @param c: state of RR lower in the chain (e.g. DNSKEY)
 * @param introducing: key goal
 * @return: state in 1.x speak
 **/
int keystate(int p, int c, int introducing)
{
	enum { HID = 0, RUM, OMN, UNR, NAV };
	if (introducing) {
		if (p == HID && c == HID) return KS_GEN;
		if (p == HID || c == HID) return KS_PUB;
		if (p == OMN && c == OMN) return KS_ACT;
		if (p == RUM || c == RUM) return KS_RDY;
		return KS_UNK;
	} else {
		if (p == HID && c == HID) return KS_DEA;
		if (p == UNR || c == UNR) return KS_RET;
		if (p == OMN && c == OMN) return KS_ACT;
		return KS_RET;
	}
}
int zskstate(const ::ods::keystate::KeyData &key)
{
	return keystate(key.dnskey().state(), key.rrsig().state(),
		key.introducing());
}
int kskstate(const ::ods::keystate::KeyData &key)
{
	return keystate(key.ds().state(), key.dnskey().state(),
		key.introducing());
}

/** Human readable keystate in 1.x speak
 * @param key: key to evaluate
 * @return: state as string
 **/
const char*
map_keystate(const ::ods::keystate::KeyData &key)
{
	int z,k;
	switch(key.role()) {
		case KSK: return statenames[kskstate(key)];
		case ZSK: return statenames[zskstate(key)];
		case CSK:
			k = kskstate(key);
			z = zskstate(key);
			if (k != z) return statenames[KS_MIX];
			return statenames[k];
	}
	statenames[KS_UNK];
}

/** Time of next transition. Caller responsible for freeing ret
 * @param zone: zone key belongs to
 * @param key: key to evaluate
 * @return: human readable transition time/event */
char*
map_keytime(::ods::keystate::EnforcerZone zone, 
	const ::ods::keystate::KeyData &key)
{
	switch(key.ds_at_parent()) {
		case DS_SUBM: return strdup("waiting for ds-submit");
		case DS_SBMD: return strdup("waiting for ds-seen");
		case DS_RETR: return strdup("waiting for ds-retract");
		case DS_RTRD: return strdup("waiting for ds-gone");
	}
	if ((signed int)zone.next_change() < 0)
		return strdup("-");

	char ct[26];
	struct tm srtm;
	time_t t = (time_t)zone.next_change();
	localtime_r(&t, &srtm);
	strftime(ct, 26, "%Y-%m-%d %H:%M:%S", &srtm);
	return strdup(ct);
}

void 
perform_keystate_list_compat(int sockfd, engineconfig_type* config)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	::ods::keystate::EnforcerZone zone;
	OrmResultRef rows;
	const char* fmt = "%-31s %-8s %-9s %s\n";

	if (!ods_orm_connect(sockfd, config, conn))
		return;
	OrmTransaction transaction(conn);
	
	if (!OrmMessageEnum(conn, zone.descriptor(), rows)) {
		ods_log_error("[%s] error enumerating zones", module_str);
		ods_printf(sockfd, "error enumerating zones\n");
		return;
	}
	
	ods_printf(sockfd, "Keys:\n");
	ods_printf(sockfd, fmt, "Zone:", "Keytype:", "State:", 
		"Date of next transition:");

	for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
		if (!OrmGetMessage(rows, zone, true)) {
			ods_log_error("[%s] error reading zone", module_str);
			ods_printf(sockfd, "error reading zone\n");
			return;
		}
			
		for (int k=0; k<zone.keys_size(); ++k) {
			const ::ods::keystate::KeyData &key = zone.keys(k);
			std::string keyrole = keyrole_Name(key.role());
			const char* state = map_keystate(key);
			char* tchange = map_keytime(zone, key);
			ods_printf(sockfd, fmt, zone.name().c_str(),
				keyrole.c_str(), state, tchange);
			free(tchange);
		}
	}
}

void 
perform_keystate_list_verbose(int sockfd, engineconfig_type *config)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return; // error already reported.
	
	{	OrmTransaction transaction(conn);
		if (!transaction.started()) {
			ods_log_error("[%s] Could not start database transaction", module_str);
			ods_printf(sockfd, "error: Could not start database transaction\n");
			return;
		}
		
		::ods::keystate::EnforcerZone zone;
		
		{	OrmResultRef rows;
			if (!OrmMessageEnum(conn, zone.descriptor(), rows)) {
				ods_log_error("[%s] error enumerating zones", module_str);
				ods_printf(sockfd, "error enumerating zones\n");
				return;
			}
			
			ods_printf(sockfd,
					   "Database set to: %s\n"
					   "Keys:\n"
					   "Zone:                           "
					   "Key role:     "
					   "DS:          "
					   "DNSKEY:      "
					   "RRSIGDNSKEY: "
					   "RRSIG:       "
					   "Pub: "
					   "Act: "
					   "Id:"
					   "\n"
					   ,config->datastore
					   );

			for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
				
				if (!OrmGetMessage(rows, zone, true)) {
					ods_log_error("[%s] error reading zone", module_str);
					ods_printf(sockfd, "error reading zone\n");
					return;
				}
					
				for (int k=0; k<zone.keys_size(); ++k) {
					const ::ods::keystate::KeyData &key = zone.keys(k);
					std::string keyrole = keyrole_Name(key.role());
					std::string ds_rrstate = rrstate_Name(key.ds().state());
					std::string dnskey_rrstate = rrstate_Name(key.dnskey().state());
					std::string rrsigdnskey_rrstate = rrstate_Name(key.rrsigdnskey().state());
					std::string rrsig_rrstate = rrstate_Name(key.rrsig().state());
					ods_printf(sockfd, 
							   "%-31s %-13s %-12s %-12s %-12s %-12s %d %4d    %s\n",
							   zone.name().c_str(),
							   keyrole.c_str(),
							   ds_rrstate.c_str(),
							   dnskey_rrstate.c_str(),
							   rrsigdnskey_rrstate.c_str(),
							   rrsig_rrstate.c_str(),
							   key.publish(),
							   key.active_ksk()||key.active_zsk(),
							   key.locator().c_str()
							   );
				}
			}
		}
    }
}

void 
perform_keystate_list(int sockfd, engineconfig_type *config, int bverbose)
{
	if (bverbose)
		perform_keystate_list_verbose(sockfd, config);
	else
		perform_keystate_list_compat(sockfd, config);
}
