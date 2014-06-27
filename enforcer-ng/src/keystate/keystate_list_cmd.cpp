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

#include "config.h"

#include "shared/duration.h"
#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>
#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"
#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"
#include <fcntl.h>


#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/str.h"
#include "daemon/clientpipe.h"

#include "keystate/keystate_list_cmd.h"

static const char *module_str = "keystate_list_task";

namespace KeyTypes {enum {KSK = 1, ZSK, CSK}; };
enum {KS_GEN = 0, KS_PUB, KS_RDY, KS_ACT, KS_RET, KS_DEA, KS_UNK, KS_MIX};
const char* statenames[] = {"generate", "publish", "ready", 
		"active", "retire", "dead", "unknown", "mixed"};

/** Map 2.0 states to 1.x states
 * @param p: state of RR higher in the chain (e.g. DS)
 * @param c: state of RR lower in the chain (e.g. DNSKEY)
 * @param introducing: key goal
 * @return: state in 1.x speak
 **/
static int
keystate(int p, int c, int introducing, int dsseen)
{
	enum { HID = 0, RUM, OMN, UNR, NAV };
	if (introducing) {
		if (p == HID && c == HID) return KS_GEN;
		if (p == HID || c == HID) return KS_PUB;
		if (p == OMN && c == OMN) return KS_ACT;
		if (p == RUM && dsseen && c == OMN) return KS_ACT;
		if (p == RUM || c == RUM) return KS_RDY;
		return KS_UNK;
	} else {
		/* retire conforms better to 1.4 terminology than dead. */
		if (p == HID && c == HID) return KS_RET; /* dead */
		if (p == UNR || c == UNR) return KS_RET;
		if (p == OMN && c == OMN) return KS_ACT;
		return KS_RET;
	}
}
static int
zskstate(const ::ods::keystate::KeyData &key)
{
	return keystate(key.dnskey().state(), key.rrsig().state(),
		key.introducing(), 0);
}
static int
kskstate(const ::ods::keystate::KeyData &key)
{
	return keystate(key.ds().state(), key.dnskey().state(),
		key.introducing(), key.ds_at_parent() == ::ods::keystate::seen);
}

/** Human readable keystate in 1.x speak
 * @param key: key to evaluate
 * @return: state as string
 **/
static const char*
map_keystate(const ::ods::keystate::KeyData &key)
{
	int z,k;
	switch(key.role()) {
		case KeyTypes::KSK: return statenames[kskstate(key)];
		case KeyTypes::ZSK: return statenames[zskstate(key)];
		case KeyTypes::CSK:
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
static char*
map_keytime(::ods::keystate::EnforcerZone zone, 
	const ::ods::keystate::KeyData &key)
{
	switch(key.ds_at_parent()) {
		case ::ods::keystate::submit: return strdup("waiting for ds-submit");
		case ::ods::keystate::submitted: return strdup("waiting for ds-seen");
		case ::ods::keystate::retract: return strdup("waiting for ds-retract");
		case ::ods::keystate::retracted: return strdup("waiting for ds-gone");
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

static int
perform_keystate_list_compat(int sockfd, engineconfig_type* config)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	::ods::keystate::EnforcerZone zone;
	OrmResultRef rows;
	const char* fmt = "%-31s %-8s %-9s %s\n";

	if (!ods_orm_connect(sockfd, config, conn))
		return 1;
	OrmTransaction transaction(conn);
	
	if (!OrmMessageEnum(conn, zone.descriptor(), rows)) {
		ods_log_error("[%s] error enumerating zones", module_str);
		client_printf(sockfd, "error enumerating zones\n");
		return 1;
	}
	
	client_printf(sockfd, "Keys:\n");
	client_printf(sockfd, fmt, "Zone:", "Keytype:", "State:", 
		"Date of next transition:");

	for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
		if (!OrmGetMessage(rows, zone, true)) {
			ods_log_error("[%s] error reading zone", module_str);
			client_printf(sockfd, "error reading zone\n");
			return 1;
		}
			
		for (int k=0; k<zone.keys_size(); ++k) {
			const ::ods::keystate::KeyData &key = zone.keys(k);
			std::string keyrole = keyrole_Name(key.role());
			const char* state = map_keystate(key);
			char* tchange = map_keytime(zone, key);
			client_printf(sockfd, fmt, zone.name().c_str(),
				keyrole.c_str(), state, tchange);
			free(tchange);
		}
	}
	return 0;
}

static int
perform_keystate_list_verbose(int sockfd, engineconfig_type *config,
	bool parsable)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	::ods::keystate::EnforcerZone zone;
	OrmResultRef rows;
	const char* fmthdr = "%-31s %-8s %-9s %-24s %-5s %-10s %-32s %-11s %s\n";
	const char* fmt    = "%-31s %-8s %-9s %-24s %-5d %-10d %-32s %-11s %d\n";
	const char* pfmt   = "%s;%s;%s;%s;%d;%d;%s;%s;%d\n";

	if (!ods_orm_connect(sockfd, config, conn))
		return 1;
	OrmTransaction transaction(conn);
	
	if (!OrmMessageEnum(conn, zone.descriptor(), rows)) {
		ods_log_error("[%s] error enumerating zones", module_str);
		client_printf(sockfd, "error enumerating zones\n");
		return 1;
	}

	if (!parsable) {
		client_printf(sockfd, "Keys:\n");
		client_printf(sockfd, fmthdr, "Zone:", "Keytype:", "State:", 
			"Date of next transition:", "Size:", "Algorithm:", "CKA_ID:", 
			"Repository:", "KeyTag:");
	}

	/*
	HsmKeyFactoryPB keyfactory(conn, NULL);
	HsmKey *hsmkey;

	for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
		if (!OrmGetMessage(rows, zone, true)) {
			ods_log_error("[%s] error reading zone", module_str);
			client_printf(sockfd, "error reading zone\n");
			return 1;
		}
		
		for (int k=0; k<zone.keys_size(); ++k) {
			const ::ods::keystate::KeyData &key = zone.keys(k);
			std::string keyrole = keyrole_Name(key.role());
			const char* state = map_keystate(key);
			char* tchange = map_keytime(zone, key);
			keyfactory.GetHsmKeyByLocator(key.locator(), &hsmkey);
			client_printf(sockfd, parsable?pfmt:fmt, zone.name().c_str(),
				keyrole.c_str(), state, tchange,
				hsmkey->bits(),
				key.algorithm(),
				key.locator().c_str(),
				hsmkey->repository().c_str(),
				(key.has_keytag() ? key.keytag() : -1)
			);
			free(tchange);
		}
	}
	*/
	return 0;
}

static int
perform_keystate_list_debug(int sockfd, engineconfig_type *config,
	bool parsable)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	const char *fmt  = "%-31s %-13s %-12s %-12s %-12s %-12s %d %4d    %s\n";
	const char *pfmt = "%s;%s;%s;%s;%s;%s;%d;%d;%s\n";

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return 1;
	
	{	OrmTransaction transaction(conn);
		if (!transaction.started()) {
			ods_log_error("[%s] Could not start database transaction", module_str);
			client_printf(sockfd, "error: Could not start database transaction\n");
			return 1;
		}
		
		::ods::keystate::EnforcerZone zone;
		
		{	OrmResultRef rows;
			if (!OrmMessageEnum(conn, zone.descriptor(), rows)) {
				ods_log_error("[%s] error enumerating zones", module_str);
				client_printf(sockfd, "error enumerating zones\n");
				return 1;
			}
			
			if (!parsable) client_printf(sockfd,
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
					client_printf(sockfd, "error reading zone\n");
					return 1;
				}

				for (int k=0; k<zone.keys_size(); ++k) {
					const ::ods::keystate::KeyData &key = zone.keys(k);
					std::string keyrole = keyrole_Name(key.role());
					std::string ds_rrstate = rrstate_Name(key.ds().state());
					std::string dnskey_rrstate = rrstate_Name(key.dnskey().state());
					std::string rrsigdnskey_rrstate = rrstate_Name(key.rrsigdnskey().state());
					std::string rrsig_rrstate = rrstate_Name(key.rrsig().state());
					client_printf(sockfd, 
							   parsable?pfmt:fmt,
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
	return 0;
}

int 
perform_keystate_list(int sockfd, engineconfig_type *config, 
	bool bverbose, bool bdebug, bool bparsable)
{
	if (bdebug)
		return perform_keystate_list_debug(sockfd, config, bparsable);
	else if (bverbose)
		return perform_keystate_list_verbose(sockfd, config, bparsable);
	else
		return perform_keystate_list_compat(sockfd, config);
}

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key list               List the keys in the enforcer database.\n"
		"      [--verbose]                (aka -v)  also show additional key parameters.\n"
		"      [--debug]                  (aka -d)  print information about the keystate.\n"
		"      [--parsable]               (aka -p)  output machine parsable list\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, key_list_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	char buf[ODS_SE_MAXLINE];
	const int NARGV = 8;
	const char *argv[NARGV];
	int argc;

	ods_log_debug("[%s] %s command", module_str, key_list_funcblock()->cmdname);
	
	cmd = ods_check_command(cmd, n, key_list_funcblock()->cmdname);
	// Use buf as an intermediate buffer for the command.
	strncpy(buf, cmd, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';
	
	// separate the arguments
	argc = ods_str_explode(buf, NARGV, argv);
	if (argc > NARGV) {
		ods_log_warning("[%s] too many arguments for %s command",
						module_str,key_list_funcblock()->cmdname);
		client_printf(sockfd,"too many arguments\n");
		return -1;
	}
	
	bool bVerbose = ods_find_arg(&argc,argv,"verbose","v") != -1;
	bool bDebug = ods_find_arg(&argc,argv,"debug","d") != -1;
	bool bParsable = ods_find_arg(&argc,argv,"parsable","p") != -1;
	if (argc) {
		ods_log_warning("[%s] unknown arguments for %s command",
						module_str,key_list_funcblock()->cmdname);
		client_printf(sockfd,"unknown arguments\n");
		return -1;
	}
	return perform_keystate_list(sockfd, engine->config, bVerbose, bDebug, bParsable);
}

static struct cmd_func_block funcblock = {
	"key list", &usage, NULL, &handles, &run
};

struct cmd_func_block*
key_list_funcblock(void)
{
	return &funcblock;
}
