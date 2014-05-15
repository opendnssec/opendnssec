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
#include "scheduler/schedule.h"
#include "scheduler/task.h"

#include "enforcer/enforcerzone.h"
#include "enforcer/hsmkeyfactory.h"

#include "db/zone.h"

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
        ods_status status = schedule_task(engine->taskq, task);
        if (status != ODS_STATUS_OK) {
            ods_log_crit("[%s] failed to create %s task", module_str, what);
            client_printf(sockfd, "Unable to schedule %s task.\n", what);
        } else {
            client_printf(sockfd, "Scheduled %s task.\n", what);
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
	task_type* task, db_connection_t *dbconn)
{
	/* loop all zones in need for an update */
	zone_list_t *zonelist = NULL;
	zone_t *zone;
	const zone_t *czone, *firstzone;
	policy_t *policy;
	key_data_list_t *keylist;
	const key_data_t *key;
    db_clause_list_t* clauselist;
    db_clause_t* clause;
    time_t t_next, t_now = time_now();

	// Flags that indicate tasks to be scheduled after zones have been enforced.
    int bSignerConfNeedsWriting = 0;
    int bSubmitToParent = 0;
    int bRetractFromParent = 0;


	if (!bForceUpdate) {
		clause = zone_next_change_clause(clauselist, t_now);
		if (db_clause_set_type(clause, DB_CLAUSE_LESS_OR_EQUAL) ||
			(zonelist = zone_list_new_get_by_clauses(dbconn, clauselist)))
		{
			db_clause_list_free(clauselist);
		}
	} else { /* all zones */
		zonelist = zone_list_new_get(dbconn);
	}
	
	while ((zone = zone_list_get_next(zonelist)) &&
		!engine->need_to_reload && !engine->need_to_exit)
	{
		if (!bForceUpdate && (zone_next_change(zone) == -1)) {
			zone_free(zone);
			continue;
		}
		if (!(policy = zone_get_policy(zone))) {
			client_printf(sockfd, 
				"Next update for zone %s NOT scheduled "
				"because policy is missing !\n", zone_name(zone));
			if (zone_set_next_change(zone, -1)) {
				/*dberr*/
				zone_free(zone);
				break;
			}
			zone_free(zone);
			continue;
		}

		t_next = update(zone, policy, t_now);
		bSignerConfNeedsWriting |= zone_signconf_needs_writing(zone);

		keylist = zone_get_keys(zone);
		while ((key = key_data_list_next(keylist))) {
			if (key_data_ds_at_parent(key) == KEY_DATA_DS_AT_PARENT_SUBMIT) {
				ods_log_warning("[%s] please submit DS "
					"with keytag %d for zone %s",
					module_str, key_data_keytag(key)&0xFFFF, zone_name(zone));
				bSubmitToParent = 1;
			} else if (key_data_ds_at_parent(key) == KEY_DATA_DS_AT_PARENT_RETRACT) {
				ods_log_warning("[%s] please retract DS "
					"with keytag %d for zone %s",
					module_str, key_data_keytag(key)&0xFFFF, zone_name(zone));
				bRetractFromParent = 1;
			}
		}
		key_data_list_free(keylist);
		
		if (t_next == -1) {
			client_printf(sockfd,
				"Next update for zone %s NOT scheduled "
				"by enforcer !\n", zone_name(zone));
		} else {
			/* Invalid schedule time then skip the zone.*/
			char tbuf[32] = "date/time invalid\n"; // at least 26 bytes
			ctime_r(&t_next, tbuf); /* note that ctime_r inserts \n */
			client_printf(sockfd,
				"Next update for zone %s scheduled at %s",
				zone_name(zone), tbuf);
		}
		zone_set_next_change(zone, t_next);
		zone_free(zone);
	}
	zone_list_free(zonelist);
	/* crude way to find out when to schedule the next change */
	zonelist = zone_list_new_get(dbconn);
	t_next = -1;
	firstzone = NULL;
	while ((czone = zone_list_next(zonelist))) {
		time_t t_update = zone_next_change(czone);
		if (t_update != -1) { /* -1 = no update ever */
			if (t_update < t_next || firstzone == NULL) {
				t_next = t_update;
				firstzone = czone;
			}
		}
	}
	if (firstzone) {
		t_next = reschedule_enforce(task, t_next, zone_name(firstzone));
	} else {
		t_next = -1;
	}
	zone_list_free(zonelist);

	/* Launch signer configuration writer task when one of the 
	 * zones indicated that it needs to be written.
	 * TODO: unschedule it first!
	 */
	if (bSignerConfNeedsWriting) {
		task_type *signconf =
			signconf_task(engine->config, "signconf", "signer configurations");
		schedule_task(sockfd,engine,signconf,"signconf");
	} else {
		ods_log_info("[%s] No changes to any signconf file required", module_str);
	}

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

    return t_next;
}

time_t perform_enforce_lock(int sockfd, engine_type *engine,
	int bForceUpdate, task_type* task, db_connection_t *dbconn)
{
	time_t returntime;
	int locked;
	if (pthread_mutex_trylock(&engine->enforce_lock)) {
		client_printf(sockfd, "An other enforce task is already running."
			" No action taken.\n");
		return 0;
	}
	returntime = perform_enforce(sockfd, engine, bForceUpdate, task,
		dbconn);
	pthread_mutex_unlock(&engine->enforce_lock);
	return returntime;
}

static task_type *
enforce_task_perform(task_type *task)
{
	int return_time = perform_enforce_lock(-1, (engine_type *)task->context, 
		enforce_all, task, task->dbconn);
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
		module_str, enforce_task_perform);
	return task_create(what_id, time_now(), who, (void*)engine);
}

int
flush_enforce_task(engine_type *engine, bool enforce_all)
{
	task_id what_id;
	/* flush (force to run) the enforcer task when it is waiting in the 
	 task list. */
	if (!task_id_from_long_name(module_str, &what_id)) {
		/* no such task */
		return 0;
	}
	schedule_flush_type(engine->taskq, what_id);
	return 1;
}
