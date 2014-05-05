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

#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "enforcer/enforce_task.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/str.h"
#include "daemon/clientpipe.h"
#include "shared/duration.h"
#include "db/key_data.h"
#include "db/zone.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>
#include "keystate/keystate.pb.h"
#include "xmlext-pb/xmlext-rd.h"
#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"
#include <memory>
#include <fcntl.h>

#include "keystate/keystate_ds_gone_cmd.h"

static const char *module_str = "keystate_ds_gone_cmd";

static int
list_keys_retracted(db_connection_t *dbconn, int sockfd)
{
	const char *fmth = "%-31s %-13s %-13s %-40s\n";
	const char *fmtl = "%-31s %-13s %-13u %-40s\n";

	key_data_list_t *key_list;
	const key_data_t *key;
	zone_t *zone;

	if (!(key_list = key_data_list_new(dbconn)))
		return 10;
	if (key_data_list_get(key_list)) {
		key_data_list_free(key_list);
		return 11;
	}
	if (!(zone = zone_new(dbconn))) {
		key_data_list_free(key_list);
		return 12;
	}

	/*client_printf(sockfd, "Database set to: %s\n", datastore);*/
	client_printf(sockfd, "List of keys that have been retracted:\n");
	client_printf(sockfd, fmth, "Zone:", "Key role:", "Keytag:", "Id:");

	/* This is horrible, we have many of this key_data's!
	 *
	 * I want to have something like:
	 * SELECT zone.name, tag, locator
	 * FROM key_data
	 * JOIN zone ON zone.id == zoneid
	 * WHERE locator IS NOT NULL AND
	 * 		(role == KSK OR role == CSK) AND
	 * 		ds_at_parent == KEY_DATA_DS_AT_PARENT_RETRACTED
	 * */

	for (key = key_data_list_begin(key_list); key;
		key = key_data_list_next(key_list))
	{
		if (!key_data_is_ksk(key)) continue; /* skip ZSK */
		if (!key_data_locator(key)) continue; /* placeholder */
		if (key_data_ds_at_parent(key) != KEY_DATA_DS_AT_PARENT_RETRACTED)
			continue;

		if(!zone_get_by_id(zone, key_data_zone_id(key))) {
			client_printf(sockfd, fmtl, zone_name(zone),
				key_data_role_text(key), key_data_keytag(key),
				key_data_locator(key)
			);
			zone_reset(zone);
		}
	}
	key_data_list_free(key_list);
	zone_free(zone);
	return 0;
}

static void
change_keys_retracted_to_unsubmitted(OrmConn conn, int sockfd,
	const char *zone, const char *id, uint16_t keytag)
{
	#define LOG_AND_RETURN(errmsg)\
		do{ods_log_error_and_printf(sockfd,module_str,errmsg);return;}while(0)
	#define LOG_AND_RETURN_1(errmsg,p)\
		do{ods_log_error_and_printf(sockfd,module_str,errmsg,p);return;}while(0)
	
	OrmTransactionRW transaction(conn);
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
		
		if (!OrmFirst(rows))
			LOG_AND_RETURN_1("zone %s not found",zone);
		
		OrmContextRef context;
		if (!OrmGetMessage(rows, enfzone, /*zones + keys*/true, context))
			LOG_AND_RETURN("retrieving zone from database failed");
		
		// we no longer need the query result, so release it.
		rows.release();
		
		// Try to change the state of a specific 'retracted' key to 'unsubmitted'.
		bool bKeyStateMatched = false;
		bool bZoneModified = false;
		for (int k=0; k<enfzone.keys_size(); ++k) {
			const ::ods::keystate::KeyData &key = enfzone.keys(k);
			
			// ZSKs are never trust anchors so skip them.
			if (key.role() == ::ods::keystate::ZSK)
				continue;
			
			// Skip KSKs with a zero length id, they are placeholder keys.
			if (key.locator().size()==0)
				continue;
			
			if ((id && key.locator()==id) || (keytag && key.keytag()==keytag)) {
				bKeyStateMatched = true;
				
				if (key.ds_at_parent()!=::ods::keystate::retracted) {
					client_printf(sockfd,
							   "Key that matches id \"%s\" in zone "
							   "\"%s\" is not retracted but %s\n",
							   key.locator().c_str(), zone,
							   dsatparent_Name(key.ds_at_parent()).c_str());
					break;
				}
				
				enfzone.mutable_keys(k)->set_ds_at_parent(::ods::keystate::unsubmitted);
				enfzone.set_next_change(0); // reschedule immediately
				bZoneModified = true;
			}
		}
		
		// Report back the status of the operation.
		if (!bKeyStateMatched) {
			if (id)
				client_printf(sockfd,
						   "No KSK key matches id \"%s\" in zone \"%s\"\n",
						   id,
						   zone);
			else
				client_printf(sockfd,
						   "No KSK key matches keytag \"%u\" in zone \"%s\"\n",
						   keytag,
						   zone);
		} else {
			if (bZoneModified) {
				// Update key states for the zone in the database.
				if (!OrmMessageUpdate(context))
					LOG_AND_RETURN_1("unable to update zone %s in the database",zone);
				
				// Commit updated records to the database.
				if (!transaction.commit())
					LOG_AND_RETURN_1("unable to commit updated zone %s to the database",zone);
				
				ods_log_debug("[%s] key states have been updated",module_str);
				client_printf(sockfd,"update of key states completed.\n");
			} else {
				ods_log_debug("[%s] key states are unchanged",module_str);
				client_printf(sockfd,"key states are unchanged\n");
			}
		}
	}
	
	#undef LOG_AND_RETURN
	#undef LOG_AND_RETURN_1
}

/**
 * Print help for the 'key list' command
 *
 */
static void
usage(int sockfd)
{
	client_printf(sockfd,
		"key ds-gone            Issue a ds-gone to the enforcer for a KSK. \n"
		"                       (This command with no parameters lists eligible keys.)\n"
		"      --zone <zone>              (aka -z)  zone.\n"
		"      --keytag <keytag> | --cka_id <CKA_ID>    (aka -x | -k)\n"
	);
}

static int
handles(const char *cmd, ssize_t n)
{
	return ods_check_command(cmd, n, key_ds_gone_funcblock()->cmdname)?1:0;
}

static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	#define NARGV 16
	const char *argv[NARGV];
	char buf[ODS_SE_MAXLINE];
	int have_zone, have_id, have_tag, argc;
	const char *zone, *cka_id, *keytag;
	uint16_t nkeytag = 0;
	
	strncpy(buf, cmd, ODS_SE_MAXLINE);
	argc = ods_str_explode(buf, NARGV, argv);
	buf[sizeof(buf)-1] = '\0';
	if (argc > NARGV) {
		ods_log_warning("[%s] too many arguments for %s command",
			module_str, cmd);
		return -1;
	}
	have_zone = (ods_find_arg_and_param(&argc, argv, "zone", "z",
		&zone) != -1);
	have_id = (ods_find_arg_and_param(&argc, argv, "cka_id", "k",
		&cka_id) != -1);
	have_tag = (ods_find_arg_and_param(&argc, argv, "keytag", "x",
		&keytag) != -1);

	if (!have_zone && !have_id && !have_tag) {
		return list_keys_retracted(dbconn, sockfd);
	} else if (!have_zone) {
		ods_log_warning("[%s] expected option --zone <zone> for %s command",
			module_str, key_ds_gone_funcblock()->cmdname);
		client_printf(sockfd,"expected --zone <zone> option\n");
		return -1;
	} else if (!have_id && !have_tag) {
		ods_log_warning("[%s] expected option --cka_id <cka_id> or "
			"--keytag <keytag> for %s command",
			module_str, key_ds_gone_funcblock()->cmdname);
		client_printf(sockfd,"expected --cka_id <cka_id> or "
			"--keytag <keytag> option\n");
		return -1;
	} else if (have_id && have_tag) {
		ods_log_warning("[%s] both --cka_id <cka_id> and --keytag <keytag> given, "
			"please only specify one for %s command",
			module_str, key_ds_gone_funcblock()->cmdname);
		client_printf(sockfd,
			"both --cka_id <cka_id> and --keytag <keytag> given, "
			"please only specify one\n");
		return -1;
	} else if (have_tag) {
		int kt = atoi(keytag);
		if (kt <= 0 || kt >= 65536) {
			ods_log_warning("[%s] value \"%s\" for --keytag is invalid",
				module_str, keytag);
			client_printf(sockfd, "value \"%s\" for --keytag is invalid\n",
				keytag);
			return -1;
		}
		nkeytag = (uint16_t )kt;
	}
	//~ change_keys_retracted_to_unsubmitted(conn, sockfd, zone, id, keytag);
	flush_enforce_task(engine, 0);
	return 0;
}

static struct cmd_func_block funcblock = {
	"key ds-gone", &usage, NULL, &handles, &run
};

struct cmd_func_block*
key_ds_gone_funcblock(void)
{
	return &funcblock;
}
