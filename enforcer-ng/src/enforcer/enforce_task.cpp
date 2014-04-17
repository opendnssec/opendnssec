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

#include <ctime>
#include <iostream>
#include <cassert>
#include <memory>
#include <fcntl.h>
#include <map>

#include "policy/kasp.pb.h"
#include "keystate/keystate.pb.h"

#include "enforcer/enforcerdata.h"
#include "enforcer/enforcer.h"
#include "daemon/clientpipe.h"
#include "daemon/engine.h"
#include "daemon/orm.h"
#include "enforcer/enforce_task.h"
#include "hsmkey/hsmkey_gen_task.h"
#include "signconf/signconf_task.h"
#include "keystate/keystate_ds_submit_task.h"
#include "keystate/keystate_ds_retract_task.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/allocator.h"

#include "enforcer/enforcerzone.h"
#include "enforcer/hsmkeyfactory.h"

#include "protobuf-orm/pb-orm.h"

static const char *module_str = "enforce_task";

/* hack for perform_enforce. The task is somewhat persistent, it is
 * rescheduled but not recreated, thus needs some additional state.
 * this SHOULD be in task context. Ideally a struct wrapping this 
 * bool and engine. But the task does not have a context destructor 
 * atm. This hack prevents a leak. */
bool enforce_all = 1;

static void 
schedule_task(int sockfd, engine_type* engine, task_type *task, const char *what)
{
    /* schedule task */
    if (!task) {
        ods_log_crit("[%s] failed to create %s task", module_str, what);
    } else {
        char buf[ODS_SE_MAXLINE];
        ods_status status = lock_and_schedule_task(engine->taskq, task, 0);
        if (status != ODS_STATUS_OK) {
            ods_log_crit("[%s] failed to create %s task", module_str, what);
            client_printf(sockfd, "Unable to schedule %s task.\n", what);
        } else {
            client_printf(sockfd, "Scheduled %s task.\n", what);
            engine_wakeup_workers(engine);
        }
    }
}

class HsmKeyFactoryCallbacks : public HsmKeyFactoryDelegatePB {
private:
    int _sockfd;
    engine_type *_engine;
    bool _bShouldLaunchKeyGen;
public:
    
    HsmKeyFactoryCallbacks(int sockfd, engine_type *engine)
    : _sockfd(sockfd),_engine(engine), _bShouldLaunchKeyGen(false)
    {
        
    }
    
    ~HsmKeyFactoryCallbacks()
    {
        if (_bShouldLaunchKeyGen) {
			// Keys were given out by the key factory during the last enforce.
			// We need to schedule the "hsm key gen" task to create additional
			// keys if needed.
			schedule_task(_sockfd, _engine,hsmkey_gen_task(_engine->config),
						  "hsm key gen");
		}
    }

    virtual void OnKeyCreated(int bits, const std::string &repository,
                              const std::string &policy, int algorithm,
                              KeyRole role)
    {
        _bShouldLaunchKeyGen = true;
    }
    
    virtual void OnKeyShortage(int bits, const std::string &repository,
                               const std::string &policy, int algorithm,
                               KeyRole role)
    {
        _bShouldLaunchKeyGen = true;
    }
};

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

static time_t 
reschedule_enforce(task_type *task, time_t t_when, const char *z_when)
{
    if (!task)
        return -1;
    
    ods_log_assert(task->allocator);
    ods_log_assert(task->who);
    allocator_deallocate(task->allocator,(void*)task->who);
    task->who = allocator_strdup(task->allocator, z_when);

    task->when = std::max(t_when, time_now());
    task->backoff = 0;
    return task->when;
}

static time_t
perform_enforce(int sockfd, engine_type *engine, int bForceUpdate,
	task_type* task)
{
	#define LOG_AND_RESCHEDULE(errmsg)\
		do {\
			ods_log_error_and_printf(sockfd,module_str,errmsg);\
			ods_log_error("[%s] retrying in 30 minutes", module_str);\
			return reschedule_enforce(task,t_now + 30*60, "next zone");\
		} while (0)

	#define LOG_AND_RESCHEDULE_15SECS(errmsg)\
		do {\
			ods_log_error_and_printf(sockfd,module_str,errmsg);\
			ods_log_error("[%s] retrying in 15 seconds", module_str);\
			return reschedule_enforce(task,t_now + 15, "next zone");\
		} while (0)
	
	#define LOG_AND_RESCHEDULE_1(errmsg,param)\
		do {\
			ods_log_error_and_printf(sockfd,module_str,errmsg,param);\
			ods_log_error("[%s] retrying in 30 minutes", module_str);\
			return reschedule_enforce(task,t_now + 30*60, "next zone");\
		} while (0)
	
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	
    time_t t_now = time_now();
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, engine->config, conn)) {
		ods_log_error("[%s] retrying in 30 minutes", module_str);
		return reschedule_enforce(task, t_now + 30*60, "next zone");
	}

	std::auto_ptr< HsmKeyFactoryCallbacks > hsmKeyFactoryCallbacks(
			new HsmKeyFactoryCallbacks(sockfd,engine));
    // Hook the key factory up with the database
    HsmKeyFactoryPB keyfactory(conn,hsmKeyFactoryCallbacks.get());

	// Flags that indicate tasks to be scheduled after zones have been enforced.
    bool bSignerConfNeedsWriting = false;
    bool bSubmitToParent = false;
    bool bRetractFromParent = false;
	bool zones_need_updating = false;

	OrmResultRef rows;
	::ods::keystate::EnforcerZone enfzone;

	bool ok;
	if (bForceUpdate)
		ok = OrmMessageEnum(conn,enfzone.descriptor(),rows);
	else {
		const char *where = "next_change IS NULL OR next_change <= %d";
		ok = OrmMessageEnumWhere(conn,enfzone.descriptor(),rows,where,t_now);
	}
	if (!ok)
		LOG_AND_RESCHEDULE_15SECS("zone enumeration failed");

	// Go through all the zones that need handling and call enforcer
	// update for the zone when its schedule time is earlier or
	// identical to time_now.

	bool next=OrmFirst(rows);
	// I would output a count of the zones here, but according to the documenation
	// a count is very expensive!
	if (next) {
		ods_log_info("[%s] Updating all zones that need require action", module_str);
		zones_need_updating = true;
	}
	while (next) {
		if (engine->need_to_reload || engine->need_to_exit) break;
		OrmTransactionRW transaction(conn);
		if (!transaction.started())
			LOG_AND_RESCHEDULE_15SECS("transaction not started");
		for (int cnt = 5; next && cnt; next = OrmNext(rows), cnt--) {
			OrmContextRef context;
			if (!OrmGetMessage(rows, enfzone, /*zones + keys*/true, context))
				LOG_AND_RESCHEDULE_15SECS("retrieving zone from database failed");
			::ods::kasp::Policy policy;
			if (!load_kasp_policy(conn, enfzone.policy(), policy)) {
				/* Policy for this zone not found, don't reschedule */
				client_printf(sockfd, 
					"Next update for zone %s NOT scheduled "
					"because policy %s is missing !\n",
					enfzone.name().c_str(),
					enfzone.policy().c_str());
				enfzone.set_next_change((time_t)-1);
			} else {
				EnforcerZonePB enfZone(&enfzone, policy);
				time_t t_next = update(enfZone, t_now, keyfactory);
				if (enfZone.signerConfNeedsWriting())
					bSignerConfNeedsWriting = true;

				bool bSubmitThisZone = false;
				bool bRetractThisZone = false;
				KeyDataList &kdl = enfZone.keyDataList();
				for (int k=0; k<kdl.numKeys(); ++k) {
					if (kdl.key(k).dsAtParent() == DS_SUBMIT)
						bSubmitThisZone = true;
					if (kdl.key(k).dsAtParent() == DS_RETRACT)
						bRetractThisZone = true;
				}
				if (bSubmitThisZone || bRetractThisZone) {
					for (int k=0; k<kdl.numKeys(); ++k) {
						if (kdl.key(k).dsAtParent() == DS_SUBMIT)
							ods_log_warning("[%s] please submit DS "
								"with keytag %d for zone %s",
								module_str, kdl.key(k).keytag()&0xFFFF,
								enfzone.name().c_str());
						if (kdl.key(k).dsAtParent() == DS_RETRACT)
							ods_log_warning("[%s] please retract"
								" DS with keytag %d for zone %s",
								module_str, kdl.key(k).keytag()&0xFFFF,
								enfzone.name().c_str());
					}
				}
				bSubmitToParent |= bSubmitThisZone;
				bRetractFromParent |= bRetractThisZone;
				
				if (t_next == -1) {
					client_printf(sockfd,
						"Next update for zone %s NOT scheduled "
						"by enforcer !\n", enfzone.name().c_str());
				}
				
				enfZone.setNextChange(t_next);
				if (t_next != -1) {
					// Invalid schedule time then skip the zone.
					char tbuf[32] = "date/time invalid\n"; // at least 26 bytes
					ctime_r(&t_next,tbuf); // note that ctime_r inserts a \n
					client_printf(sockfd,
							   "Next update for zone %s scheduled at %s",
							   enfzone.name().c_str(),
							   tbuf);
				}
			}
			if (!OrmMessageUpdate(context))
				LOG_AND_RESCHEDULE_15SECS("updating zone in the database failed");
		}
		if (!transaction.commit())
			LOG_AND_RESCHEDULE_15SECS("committing updated zones to the database failed");
	}
	// we no longer need the query result, so release it.
	rows.release();
	if (zones_need_updating)
		ods_log_info("[%s] Completed updating all zones that need required action", module_str);

    // Delete the call backs and launch key pre-generation when we ran out 
    // of keys during the enforcement
    hsmKeyFactoryCallbacks.reset();


	// when to reschedule next zone for enforcement
    time_t t_when = t_now + 1 * 365 * 24 * 60 * 60; // now + 1 year
    // which zone to reschedule next for enforcement
    std::string z_when("next zone");

	{	OrmTransaction transaction(conn);
		if (!transaction.started())
			LOG_AND_RESCHEDULE_15SECS("transaction not started");
		
		{	OrmResultRef rows;
			::ods::keystate::EnforcerZone enfzone;
			
			// Determine the next schedule time.
			const char *where =
				"next_change IS NULL OR next_change > 0 ORDER BY next_change";
			if (!OrmMessageEnumWhere(conn,enfzone.descriptor(),rows,where))
				LOG_AND_RESCHEDULE_15SECS("zone query failed");
			
			if (!OrmFirst(rows)) {
				ods_log_error_and_printf(sockfd, module_str,
					"No zones need updating ever.");
				return -1;
			}
			
			if (!OrmGetMessage(rows, enfzone, false))
				LOG_AND_RESCHEDULE("unable to retriev zone from database");
			
			// t_next can never go negative as next_change is a uint32 and 
			// time_t is a long (int64) so -1 stored in next_change will 
			// become maxint in t_next.
			time_t t_next = enfzone.next_change();
			
			// Determine whether this zone is going to be scheduled next.
			// If the enforcer wants a reschedule earlier than currently
			// set, then use that.
			if (t_next < t_when) {
				t_when = t_next;
				z_when = enfzone.name().c_str();
			}
		}
	}

    // Launch signer configuration writer task when one of the 
    // zones indicated that it needs to be written.
    if (bSignerConfNeedsWriting) {
        task_type *signconf =
            signconf_task(engine->config, "signconf", "signer configurations");
        schedule_task(sockfd,engine,signconf,"signconf");
    }
	else
		ods_log_info("[%s] No changes to any signconf file required", module_str);

    // Launch ds-submit task when one of the updated key states has the
    // DS_SUBMIT flag set.
    if (bSubmitToParent) {
        task_type *submit =
            keystate_ds_submit_task(engine->config,
                                    "ds-submit","KSK keys with submit flag set");
        schedule_task(sockfd,engine,submit,"ds-submit");
    }

    // Launch ds-retract task when one of the updated key states has the
    // DS_RETRACT flag set.
    if (bRetractFromParent) {
        task_type *retract =
            keystate_ds_retract_task(engine->config,
                                "ds-retract","KSK keys with retract flag set");
        schedule_task(sockfd,engine,retract,"ds-retract");
    }

    return reschedule_enforce(task,t_when,z_when.c_str());
}

time_t perform_enforce_lock(int sockfd, engine_type *engine,
	int bForceUpdate, task_type* task)
{
	time_t returntime;
	int locked;
	if (lock_basic_trylock(&engine->enforce_lock)) {
		client_printf(sockfd, "An other enforce task is already running."
			" No action taken.\n");
		return 0;
	}
	returntime = perform_enforce(sockfd, engine, bForceUpdate, task);
	lock_basic_unlock(&engine->enforce_lock);
	return returntime;
}

static task_type *
enforce_task_perform(task_type *task)
{
	int return_time = perform_enforce_lock(-1, (engine_type *)task->context, 
		enforce_all, task);
	enforce_all = 0; /* global */
	if (return_time != -1) return task;
	task_cleanup(task);
	return NULL;
}

task_type *
enforce_task(engine_type *engine, bool all)
{
	const char *what = "enforce";
	const char *who = "next zone";
	enforce_all = all;
	task_id what_id = task_register(what, 
		"enforce_task_perform", enforce_task_perform);
	return task_create(what_id, time_now(), who, (void*)engine);
}


int
flush_enforce_task(engine_type *engine, bool enforce_all)
{
    /* flush (force to run) the enforcer task when it is waiting in the 
     task list. */
    task_type *enf = enforce_task(engine, enforce_all);
    lock_basic_lock(&engine->taskq->schedule_lock);
    /* [LOCK] schedule */
    task_type *running_enforcer = schedule_lookup_task(engine->taskq, enf);

    if (running_enforcer) {
        running_enforcer->flush = 1;
        task_cleanup(enf);
    } else {
        if (schedule_task(engine->taskq, enf, 1) != ODS_STATUS_OK) {
            ods_log_info("[%s] Unable to schedule enforce task.", module_str);
        }
    }
    /* [UNLOCK] schedule */
    lock_basic_unlock(&engine->taskq->schedule_lock);
    engine_wakeup_workers(engine);
    return 1;
}
