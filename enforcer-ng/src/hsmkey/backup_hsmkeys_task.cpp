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

#include "hsmkey/backup_hsmkeys_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "libhsm.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "hsmkey/hsmkey.pb.h"

#include "xmlext-pb/xmlext-rd.h"

#include <map>
#include <fcntl.h>
#include <utility>

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

static const char *module_str = "backup_hsmkeys_task";

void 
perform_backup_prepare(int sockfd, engineconfig_type *config, const char *repository)
{
	int keys_marked;
	// check that we are using a compatible protobuf version.
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn)) return;

	OrmTransaction transaction(conn);
	if (!transaction.started()) {
		ods_printf(sockfd,"error: database transaction failed\n");
		return;
	}

	OrmResultRef rows;
	if ((repository && !OrmMessageEnumWhere(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows, 
			"repository='%s'", repository)) ||
		(!repository && !OrmMessageEnum(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows)))
	{
		ods_printf(sockfd,"error: key enumeration failed\n");
		return;
	}

	pb::uint64 keyid;
	keys_marked = 0;
	OrmContextRef context;
	for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
		::ods::hsmkey::HsmKey key;
		if (OrmGetMessage(rows, key, true, context)) {
			key.set_backmeup(true);
			keys_marked++;
			pb::uint64 keyid;
			if (!OrmMessageUpdate(context)) {
				ods_log_error_and_printf(sockfd, module_str,
					"database record update failed");
			}
			context.release();
		}
	}
	rows.release();
	if (!transaction.commit()) {
		ods_printf(sockfd,"error committing transaction.");
		return;
	}
	ods_printf(sockfd,"info: keys flagged for backup: %d\n", keys_marked);
}

void 
perform_backup_commit(int sockfd, engineconfig_type *config, const char *repository)
{
	int keys_marked;
	// check that we are using a compatible protobuf version.
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn)) return;

	OrmTransaction transaction(conn);
	if (!transaction.started()) {
		ods_printf(sockfd,"error: database transaction failed\n");
		return;
	}

	OrmResultRef rows;
	if ((repository && !OrmMessageEnumWhere(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows, 
			"repository='%s'", repository)) ||
		(!repository && !OrmMessageEnum(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows)))
	{
		ods_printf(sockfd,"error: key enumeration failed\n");
		return;
	}
	OrmContextRef context;
	keys_marked = 0;
	for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
		::ods::hsmkey::HsmKey key;
		if (OrmGetMessage(rows, key, true, context)) {
			if (key.backmeup()) {
				key.set_backedup(true);
				key.set_backmeup(false);
				keys_marked++;
				if (!OrmMessageUpdate(context)) {
					ods_log_error_and_printf(sockfd, module_str,
						"database record update failed");
				}
			}
			context.release();
		}
	}
	rows.release();
	if (!transaction.commit()) {
		ods_printf(sockfd,"error committing transaction.");
		return;
	}
	ods_printf(sockfd,"info: keys flagged as backed up: %d\n", keys_marked);
}

void 
perform_backup_rollback(int sockfd, engineconfig_type *config, const char *repository)
{
	int keys_marked;
	// check that we are using a compatible protobuf version.
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn)) return;

	OrmTransaction transaction(conn);
	if (!transaction.started()) {
		ods_printf(sockfd,"error: database transaction failed\n");
		return;
	}

	OrmResultRef rows;
	if ((repository && !OrmMessageEnumWhere(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows, 
			"repository='%s'", repository)) ||
		(!repository && !OrmMessageEnum(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows)))
	{
		ods_printf(sockfd,"error: key enumeration failed\n");
		return;
	}
	OrmContextRef context;
	keys_marked = 0;
	for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
		::ods::hsmkey::HsmKey key;
		if (OrmGetMessage(rows, key, true, context)) {
			if (key.backmeup()) {
				key.set_backmeup(false);
				keys_marked++;
				if (!OrmMessageUpdate(context)) {
					ods_log_error_and_printf(sockfd, module_str,
						"database record update failed");
				}
			}
			context.release();
		}
	}
	rows.release();
	if (!transaction.commit()) {
		ods_printf(sockfd,"error committing transaction.");
		return;
	}
	ods_printf(sockfd,"info: keys unflagged for backed up: %d\n", keys_marked);
}

void 
perform_backup_list(int sockfd, engineconfig_type *config, const char *repository)
{
	int keys_marked;
	struct engineconfig_repository* hsm;
	// check that we are using a compatible protobuf version.
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn)) return;

	OrmTransaction transaction(conn);
	if (!transaction.started()) {
		ods_printf(sockfd,"error: database transaction failed\n");
		return;
	}

	OrmResultRef rows;
	if ((repository && !OrmMessageEnumWhere(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows, 
			"repository='%s'", repository)) ||
		(!repository && !OrmMessageEnum(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows)))
	{
		ods_printf(sockfd,"error: key enumeration failed\n");
		return;
	}
	
	using namespace std;
	typedef std::vector<int> Val;
	typedef map<string, Val> Policy;
	
	Policy::iterator polit;
	Val val;
	Policy pol;
	
	OrmContextRef context;
	for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
		::ods::hsmkey::HsmKey key;
		if (OrmGetMessage(rows, key, true, context)) {
			val = pol[key.policy()];
			if (val.empty()) {
				val.push_back(key.backmeup());
				val.push_back(key.backedup());
				val.push_back(1);
			} else {
				val[0] += key.backmeup();
				val[1] += key.backedup();
				val[2]++;
			}
			pol[key.policy()] = val;
			context.release();
		}
	}
	rows.release();
	
	ods_printf(sockfd, "Backups:\n");
	for (polit = pol.begin();  polit != pol.end(); polit++) {
		string policyname = (*polit).first;
		int backmeup = (*polit).second[0];
		int backedup = (*polit).second[1];
		int total = (*polit).second[2];
		ods_printf(sockfd, "Repository %s has %d keys: %d backed up, %d unbacked "
			"up, %d prepared.\n", policyname.c_str(), total, backedup, total - backedup, backmeup);
	}

	if (!transaction.commit()) {
		ods_printf(sockfd,"error committing transaction.");
		return;
	}
}
