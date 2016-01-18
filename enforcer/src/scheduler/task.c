/*
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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

/**
 * Tasks.
 *
 */

#include "config.h"
#include "scheduler/task.h"
#include "duration.h"
#include "file.h"
#include "log.h"

static const char* task_str = "task";

typedef struct taskreg taskreg_type;

struct taskreg {
    const char *short_name;
	const char *long_name;
	how_type how;
	how_type clean;
};

static taskreg_type taskreg[16];
static int ntaskreg = 0;
const int NUM_HOW_REG = sizeof(taskreg)/sizeof(taskreg_type);

bool task_id_from_long_name(const char *long_name, task_id *pwhat)
{
	int i;
	for (i=0; i<ntaskreg; ++i) {
		if (strcmp(taskreg[i].long_name,long_name)==0) {
			*pwhat = TASK_DYNAMIC_FIRST+i;
            return true;
		}
	}
	return false;
}

static const char *task_id_to_short_name(task_id id, const char *def)
{
    if (id >= TASK_DYNAMIC_FIRST && (signed)id-TASK_DYNAMIC_FIRST < ntaskreg) {
        return taskreg[id-TASK_DYNAMIC_FIRST].short_name;
    }
    return def;
}

static bool task_id_to_how(task_id id, how_type *phow)
{
    if (id >= TASK_DYNAMIC_FIRST && (signed)id-TASK_DYNAMIC_FIRST < ntaskreg) {
        *phow = taskreg[id-TASK_DYNAMIC_FIRST].how;
        return true;
    }
    return false;
}

task_id task_register(const char *short_name, const char *long_name,
    how_type how)
{
    int i;
    
    /* update existing registration */
    for (i=0; i<ntaskreg; ++i) {
        if (strcmp(long_name, taskreg[i].long_name)==0) {
            taskreg[i].how = how;
            return TASK_DYNAMIC_FIRST+i;
        }
    }
    
	if (ntaskreg >= NUM_HOW_REG) {
		ods_log_error("Unable to register additional name,how pairs for tasks.");
		return TASK_NONE;
	}
    taskreg[ntaskreg].short_name = short_name;
	taskreg[ntaskreg].long_name = long_name;
	taskreg[ntaskreg].how = how;
    return TASK_DYNAMIC_FIRST+ntaskreg++;
}

/**
 * Create a new task.
 *
 */
task_type*
task_create(task_id what_id, time_t when, const char* who, const char* what,
    void* context, how_type clean_context)
{
    task_type* task = NULL;

    if (!who || !context) {
        ods_log_error("[%s] cannot create: missing context info", task_str);
        return NULL;
    }
    ods_log_assert(who);
    ods_log_assert(context);

    task = (task_type*) malloc(sizeof(task_type));
    if (!task) {
        ods_log_error("[%s] cannot create: malloc failed", task_str);
        return NULL;
    }
    task->what = what_id;
    task->interrupt = TASK_NONE;
    task->halted = TASK_NONE;
    task->when = when;
    task->backoff = 0;
    task->who = strdup(who);
    task->dname = ldns_dname_new_frm_str(what);
    task->flush = 0;
    task->context = context;
    task->clean_context = clean_context;
    if (!task_id_to_how(what_id, &task->how))
        task->how = NULL; /* Standard task */
    return task;
}

/**
 * Clean up task.
 *
 */
void
task_cleanup(task_type* task)
{
    if (!task) {
        return;
    }
    if (task->dname) {
        ldns_rdf_deep_free(task->dname);
        task->dname = NULL;
    }
    if (task->clean_context && task->context) {
        (void)task->clean_context(task);
        task->context = NULL;
    }
    free(task->who);
    free(task);
}


/**
 * Compare tasks.
 *
 */
int
task_compare(const void* a, const void* b)
{
    task_type* x = (task_type*)a;
    task_type* y = (task_type*)b;

    ods_log_assert(x);
    ods_log_assert(y);

    /* If a task is set to flush, it should go in front. */
    if (x->flush != y->flush) {
        return y->flush - x->flush;
    }

    /* order task on time, dname */
    if (x->when != y->when) {
        return (int) x->when - y->when;
    }
    return ldns_dname_compare((const void*) x->dname,
        (const void*) y->dname);
}

/**
 * Compare tasks by name
 */
int
task_compare_name(const void* a, const void* b)
{
    task_type* x = (task_type*)a;
    task_type* y = (task_type*)b;
    ods_log_assert(x);
    ods_log_assert(y);
    /* order task on time, dname */
    return ldns_dname_compare((const void*) x->dname,
        (const void*) y->dname);
}


/**
 * String-format of what.
 *
 */
const char*
task_what2str(int what)
{
    switch (what) {
        case TASK_NONE:
            return "do nothing with";
            break;
        case TASK_SIGNCONF:
            return "load signconf for";
            break;
        case TASK_READ:
            return "read";
            break;
        case TASK_NSECIFY:
            return "nsecify";
            break;
        case TASK_SIGN:
            return "sign";
            break;
        case TASK_AUDIT:
            return "audit";
            break;
        case TASK_WRITE:
            return "write";
            break;
        default:
            return task_id_to_short_name(what, "???");
    }
    return "[!!!]"; /* we should never get here.. */
}


/**
 * String-format of who.
 *
 */
const char*
task_who2str(const char* who)
{
    if (who) {
        return who;
    }
    return "(null)";
}


/**
 * Convert task to string.
 *
 */
char*
task2str(task_type* task, char* buftask)
{
    char ctimebuf[32]; /* at least 26 according to docs */
    time_t now = time_now();
    char* strtime = NULL;
    char* strtask = NULL;

    if (task) {
        if (task->flush) {
            strtime = ctime_r(&now,ctimebuf);
        } else {
            strtime = ctime_r(&task->when,ctimebuf);
        }
        if (strtime) {
            strtime[strlen(strtime)-1] = '\0';
        }
        if (buftask) {
            (void)snprintf(buftask, ODS_SE_MAXLINE, "On %s I will [%s] %s"
                "\n", strtime?strtime:"(null)", task_what2str(task->what),
                task_who2str(task->who));
            return buftask;
        } else {
            strtask = (char*) calloc(ODS_SE_MAXLINE, sizeof(char));
            snprintf(strtask, ODS_SE_MAXLINE, "On %s I will [%s] %s\n",
                strtime?strtime:"(null)", task_what2str(task->what),
                task_who2str(task->who));
            return strtask;
        }
    }
    return NULL;
}


/**
 * Perform task.
 *
 */
task_type *
task_perform(task_type *task)
{
	if (task->how) 
        return task->how(task);

    task_cleanup(task);
    return NULL;
}
