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
/****************************/
#include <stdio.h>

 /**/

#include "shared/duration.h"
#include "shared/file.h"
#include "policy/policy_export_task.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h> 

#include "policy/kasp.pb.h"

#include "xmlext-pb/xmlext-rd.h"
#include "xmlext-pb/xmlext-wr.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

#include <fcntl.h>
#include <memory>

static const char *module_str = "policy_export_task";

#define ODS_LOG_AND_RETURN(errmsg) do { \
	ods_log_error_and_printf(sockfd,module_str,errmsg); return; } while (0)
#define ODS_LOG_AND_CONTINUE(errmsg) do { \
	ods_log_error_and_printf(sockfd,module_str,errmsg); continue; } while (0)
	
void
perform_policy_export_to_file(const std::string& filename, engineconfig_type *config, const char *policyname)
{
 	perform_policy_export(&filename, 0, config, policyname);
}

void
perform_policy_export_to_fd(int sockfd, engineconfig_type *config, const char *policyname)
{
 	perform_policy_export(NULL, sockfd, config, policyname);
}
	

void 
perform_policy_export(const std::string *filename, int sockfd, engineconfig_type *config, const char *policyname)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn)) return;
	
	OrmTransaction transaction(conn);
	if (!transaction.started()) {
		ods_log_error_and_printf(sockfd, module_str, 
			"database transaction failed");
		return;
	}

	OrmResultRef rows;
	::ods::kasp::Policy policy;
	if (!OrmMessageEnum(conn,policy.descriptor(),rows)) {
		ods_log_error_and_printf(sockfd, module_str,
			"database policy enumeration failed\n");
		return;
	}
	
	if (!OrmFirst(rows)) {
		ods_log_debug("[%s] policy list completed", module_str);
		// We should still output an empty file in this case
		// but reporting this on the command line is helpful
		ods_printf(sockfd,
			"Database set to: %s\n"
			"There are no policies configured\n"
			,config->datastore);
	}

	std::auto_ptr< ::ods::kasp::KaspDocument > kaspdoc(
	          new ::ods::kasp::KaspDocument );
	// This is a dummy variable so that empty zonelists will be exported
	// It does not appear in the output file
	kaspdoc->mutable_kasp()->set_export_empty(true);

	for (bool next=OrmFirst(rows); next; next = OrmNext(rows)) {
		OrmContextRef context;
		if (!OrmGetMessage(rows, policy, true, context)) {
		     rows.release();
		     ods_log_error("[%s] retrieving policy from database failed", module_str);
		     return;
		}
		const char *name = policy.name().c_str();
		if (!name || (policyname && strcmp(name, policyname) != 0))
			continue;
						
		 ::ods::kasp::Policy *added_policy = kaspdoc->mutable_kasp()->add_policies();
		 added_policy->CopyFrom(policy);
	}
 	rows.release();

    // Where should we write the output?
    if (filename != NULL) {
		// Lets not bother with a backup file in this case as 1.4 doesn't
		// Do the write as an atomic operation i.e. write to a .tmp then rename it...
		std::string filename_tmp(*filename);
		filename_tmp.append(".tmp");								
		if (!write_pb_message_to_xml_file(kaspdoc.get(), filename_tmp.c_str())) {
		     ods_log_error("[%s] writing kasp xml to output failed", module_str);
		     return;
		}	
	    if (rename(filename_tmp.c_str(), filename->c_str())) {
	        ods_log_error("[%s] failed to rename %s to %s", module_str, filename_tmp.c_str(), filename->c_str());
	        return;
	    }
	    if (!remove(filename_tmp.c_str())) {
	        ods_log_error("[%s] failed to remove %s", module_str, filename_tmp.c_str());
	    }			

	} else {
	     if (!write_pb_message_to_xml_fd(kaspdoc.get(), sockfd)) {
	         ods_log_error("[%s] writing kasp xml to output failed", module_str);
	         return;
		}
	}

    ods_log_debug("[%s] policy export completed", module_str);
}

