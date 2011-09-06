#include <ctime>
#include <iostream>
#include <cassert>

// Interface of this cpp file is used by C code, we need to declare 
// extern "C" to prevent linking errors.
extern "C" {
#include "enforcer/autostart_cmd.h"

#include "enforcer/enforce_task.h"
#include "policy/policy_resalt_task.h"

#include "shared/duration.h"
#include "shared/file.h"
#include "shared/str.h"
#include "daemon/engine.h"
}

static const char *module_str = "autostart_cmd";

static void 
schedule_task(engine_type* engine, task_type *task, const char * what)
{
    /* schedule task */
    if (!task) {
        ods_log_crit("[%s] failed to create %s task", module_str, what);
    } else {
        char buf[ODS_SE_MAXLINE];
        ods_status status = lock_and_schedule_task(engine->taskq, task, 0);
        if (status != ODS_STATUS_OK) {
            ods_log_crit("[%s] failed to create %s task", module_str, what);
        } else {
            ods_log_debug("[%s] scheduled %s task", module_str, what);
            engine_wakeup_workers(engine);
        }
    }
}
 
void
autostart(engine_type* engine)
{
    ods_log_debug("[%s] autostart", module_str);
    schedule_task(engine, policy_resalt_task(engine->config), "resalt");
    schedule_task(engine, enforce_task(engine), "enforce");
}
