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

#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "policy/policy_resalt_task.h"
#include "policy/resalt.h"
#include "scheduler/task.h"
#include "daemon/engine.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "kasp.pb.h"

#include "xmlext-pb/xmlext-rd.h"

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"
#include "daemon/clientpipe.h"

#include <memory>
#include <fcntl.h>
#include <time.h>

static const char *module_str = "policy_resalt_task";

static const time_t TIME_INFINITE = ((time_t)-1);

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

time_t 
perform_policy_resalt(int sockfd, engine_type* engine)
{
	#define LOG_AND_RESCHEDULE(errmsg,resched) do {\
		ods_log_error_and_printf(sockfd,module_str,errmsg);\
		ods_log_error("[%s] retrying in %d seconds", module_str, resched);\
		return (time_now() + resched); } while (0)
	
	GOOGLE_PROTOBUF_VERIFY_VERSION;

    time_t time_resched = TIME_INFINITE;
	
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, engine->config, conn)) {
		ods_log_error("[%s] retrying in %d seconds", module_str, 60);
		return (time_now() + 60);
	}

	OrmTransactionRW transaction(conn);
	if (!transaction.started())
		LOG_AND_RESCHEDULE("starting transaction failed", 60);

	
	{	OrmResultRef rows;
		::ods::kasp::Policy policy;
		if (!OrmMessageEnum(conn, policy.descriptor(), rows))
			LOG_AND_RESCHEDULE("unable to enumerate policies", 60);

		if (!OrmFirst(rows)) {
			client_printf(sockfd, 
					   "Database set to: %s\n"
					   "There are no policies configured\n",
					   engine->config->datastore);
			return time_resched;
		}
		
		client_printf(sockfd,
				   "Database set to: %s\n"
				   "Policies:\n"
				   "Policy:                         "
				   "Updated:  "
				   "Next resalt scheduled:"
				   "\n",
				   engine->config->datastore);

		
		bool bSomePoliciesUpdated = false;
		for (bool next=true; next; next=OrmNext(rows)) {

			::ods::kasp::Policy policy;
			OrmContextRef context;
			if (!OrmGetMessage(rows, policy, true, context))
				LOG_AND_RESCHEDULE("reading policy from database failed", 60);

			// Update the salt for this policy when required
			bool bCurrentPolicyUpdated = false;
			if (PolicyUpdateSalt(policy) == 1) {
				bCurrentPolicyUpdated = true;
				bSomePoliciesUpdated = true;
			}

			// calculate the next resalt time for this policy
			std::string text_resalt;
			if (!policy.denial().has_nsec3()) {
				text_resalt = "not applicable (no NSEC3)";
			} else {
				time_t time_resalt = policy.denial().nsec3().salt_last_change()
									+policy.denial().nsec3().resalt();
				char tbuf[32]; 
				if (!ods_ctime_r(tbuf,sizeof(tbuf),time_resalt)) {
					text_resalt = "invalid date/time";
				} else {
					text_resalt = tbuf;
					if (time_resched==TIME_INFINITE)
						time_resched = time_resalt;
					else
						if (time_resalt>time_now() && time_resalt<time_resched)
							// Keep the earliest (future) reschedule time.
							time_resched = time_resalt;
				}
			}

			client_printf(sockfd,
					   "%-31s %-9s %-48s\n",
					   policy.name().c_str(),
					   bCurrentPolicyUpdated ? "yes" : "no",
					   text_resalt.c_str());
			
			if (bCurrentPolicyUpdated)
				if (!OrmMessageUpdate(context))
					LOG_AND_RESCHEDULE("updating policy in database failed",60);
		}
		
		// query result no longer needed.
		rows.release();

		if (!bSomePoliciesUpdated) {
			ods_log_debug("[%s] policy resalt complete", module_str);
			client_printf(sockfd,"policy resalt complete\n");
			return time_resched;
		}
	}
	
	if (!transaction.commit())
		LOG_AND_RESCHEDULE("committing policy changes failed", 60);

	ods_log_debug("[%s] policies have been updated",module_str);
	client_printf(sockfd,"Policies have been updated.\n");
	return time_resched;
}

static task_type * 
policy_resalt_task_perform(task_type *task)
{
	task->backoff = 0;
    task->when = perform_policy_resalt(-1,(engine_type *)task->context);
    return task; // return task, it needs to be rescheduled.
}

task_type *
policy_resalt_task(engine_type* engine)
{
    const char *what = "resalt";
    const char *who = "policies";
    task_id what_id = task_register(what,
                                 "policy_resalt_task_perform", 
                                 policy_resalt_task_perform);
	return task_create(what_id, time_now(), who, (void*)engine);
}
