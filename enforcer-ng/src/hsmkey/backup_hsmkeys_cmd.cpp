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

#include <map>
#include <fcntl.h>
#include <utility>

#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/str.h"
#include "shared/duration.h"
#include "daemon/clientpipe.h"
#include "libhsm.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>
#include "hsmkey/hsmkey.pb.h"
#include "xmlext-pb/xmlext-rd.h"
#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include "hsmkey/backup_hsmkeys_cmd.h"

static const char *module_str = "backup_hsmkeys_cmd";

int 
perform_backup_prepare(int sockfd, engineconfig_type *config, const char *repository)
{
	int keys_marked;
	// check that we are using a compatible protobuf version.
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn)) return 1;

	OrmTransaction transaction(conn);
	if (!transaction.started()) {
		client_printf(sockfd,"error: database transaction failed\n");
		return 1;
	}

	OrmResultRef rows;
	if ((repository && !OrmMessageEnumWhere(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows, 
			"repository='%s'", repository)) ||
		(!repository && !OrmMessageEnum(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows)))
	{
		client_printf(sockfd,"error: key enumeration failed\n");
		return 1;
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
		client_printf(sockfd,"error committing transaction.");
		return 1;
	}
	client_printf(sockfd,"info: keys flagged for backup: %d\n", keys_marked);
	return 0;
}

int 
perform_backup_commit(int sockfd, engineconfig_type *config, const char *repository)
{
	int keys_marked;
	// check that we are using a compatible protobuf version.
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn)) return 1;

	OrmTransaction transaction(conn);
	if (!transaction.started()) {
		client_printf(sockfd,"error: database transaction failed\n");
		return 1;
	}

	OrmResultRef rows;
	if ((repository && !OrmMessageEnumWhere(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows, 
			"repository='%s'", repository)) ||
		(!repository && !OrmMessageEnum(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows)))
	{
		client_printf(sockfd,"error: key enumeration failed\n");
		return 1;
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
		client_printf(sockfd,"error committing transaction.");
		return 1;
	}
	client_printf(sockfd,"info: keys flagged as backed up: %d\n", keys_marked);
	return 0;
}

int 
perform_backup_rollback(int sockfd, engineconfig_type *config, const char *repository)
{
	int keys_marked;
	// check that we are using a compatible protobuf version.
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn)) return 1;

	OrmTransaction transaction(conn);
	if (!transaction.started()) {
		client_printf(sockfd,"error: database transaction failed\n");
		return 1;
	}

	OrmResultRef rows;
	if ((repository && !OrmMessageEnumWhere(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows, 
			"repository='%s'", repository)) ||
		(!repository && !OrmMessageEnum(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows)))
	{
		client_printf(sockfd,"error: key enumeration failed\n");
		return 1;
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
		client_printf(sockfd,"error committing transaction.");
		return 1;
	}
	client_printf(sockfd,"info: keys unflagged for backed up: %d\n", keys_marked);
	return 0;
}

int 
perform_backup_list(int sockfd, engineconfig_type *config, const char *repository)
{
	int keys_marked;
	struct engineconfig_repository* hsm;
	// check that we are using a compatible protobuf version.
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn)) return 1;

	OrmTransaction transaction(conn);
	if (!transaction.started()) {
		client_printf(sockfd,"error: database transaction failed\n");
		return 1;
	}

	OrmResultRef rows;
	if ((repository && !OrmMessageEnumWhere(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows, 
			"repository='%s'", repository)) ||
		(!repository && !OrmMessageEnum(conn,
			::ods::hsmkey::HsmKey::descriptor(), rows)))
	{
		client_printf(sockfd,"error: key enumeration failed\n");
		return 1;
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
	
	client_printf(sockfd, "Backups:\n");
	for (polit = pol.begin();  polit != pol.end(); polit++) {
		string policyname = (*polit).first;
		int backmeup = (*polit).second[0];
		int backedup = (*polit).second[1];
		int total = (*polit).second[2];
		client_printf(sockfd, "Repository %s has %d keys: %d backed up, %d unbacked "
			"up, %d prepared.\n", policyname.c_str(), total, backedup, total - backedup, backmeup);
	}

	if (!transaction.commit()) {
		client_printf(sockfd,"error committing transaction.");
		return 1;
	}
	return 0;
}

static void
usage(int sockfd)
{
	client_printf(sockfd,
		"backup list            Enumerate backup status of keys.\n"
		"      --repository <repository>  (aka -r)  Limit to this repository.\n");
	client_printf(sockfd,
		"backup prepare         Flag the keys found in all configured HSMs as to be \n"
		"                       backed up.\n"
		"      --repository <repository>  (aka -r)  Limit to this repository.\n");
	client_printf(sockfd,
		"backup commit          Mark flagged keys found in all configured HSMs as\n"
		"                       backed up.\n"
		"      --repository <repository>  (aka -r)  Limit to this repository.\n");
	client_printf(sockfd,
		"backup rollback        Cancel a 'backup prepare' action.\n"
		"      --repository <repository>  (aka -r)  Limit to this repository.\n");
}

static int
handles(const char *cmd, ssize_t n)
{
	if (ods_check_command(cmd, n, "backup prepare")) return 1;
	if (ods_check_command(cmd, n, "backup commit")) return 1;
	if (ods_check_command(cmd, n, "backup rollback")) return 1;
	if (ods_check_command(cmd, n, "backup list")) return 1;
	return 0;
}

static int
handled_backup_cmd(int sockfd, engine_type* engine, 
		const char *scmd, ssize_t n, 
		int task(int, engineconfig_type *, const char *))
{
	char buf[ODS_SE_MAXLINE];
    const int NARGV = 8;
    const char *argv[NARGV];
    int argc;
	const char *repository = NULL;

	ods_log_debug("[%s] %s command", module_str, scmd);

	// Use buf as an intermediate buffer for the command.
	strncpy(buf, scmd, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';
	// separate the arguments
	argc = ods_str_explode(buf, NARGV, argv);
	if (argc > NARGV) {
		ods_log_warning("[%s] too many arguments for %s command",
						module_str,scmd);
		client_printf(sockfd,"too many arguments\n");
		return -1;
	}
	(void)ods_find_arg_and_param(&argc,argv,"repository","r",&repository);
	return task(sockfd,engine->config, repository);
}


static int
run(int sockfd, engine_type* engine, const char *cmd, ssize_t n,
	db_connection_t *dbconn)
{
	if (ods_check_command(cmd,n,"backup prepare")) {
		return handled_backup_cmd(sockfd, engine, 
			cmd, n, &perform_backup_prepare);
	} else if (ods_check_command(cmd,n,"backup commit")) {
		return handled_backup_cmd(sockfd, engine, 
			cmd, n, &perform_backup_commit);
	} else if (ods_check_command(cmd,n,"backup rollback")) {
		return handled_backup_cmd(sockfd, engine, 
			cmd, n, &perform_backup_rollback);
	} else if (ods_check_command(cmd,n,"backup list")) {
		return handled_backup_cmd(sockfd, engine, 
			cmd, n, &perform_backup_list);
	} else {
		return -1;
	}
}

static struct cmd_func_block funcblock = {
	"backup", &usage, NULL, &handles, &run
};

struct cmd_func_block*
backup_funcblock(void)
{
	return &funcblock;
}
