#ifndef _ENFORCER_ENFORCE_TASK_H_
#define _ENFORCER_ENFORCE_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

time_t perform_enforce(int sockfd, engine_type *engine, int bForce,
                       task_type *task);

task_type *enforce_task(engine_type *engine);

int flush_enforce_task(engine_type *engine);

#endif
