#ifndef _ENFORCER_ENFORCE_TASK_H_
#define _ENFORCER_ENFORCE_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

time_t perform_enforce(int sockfd, engineconfig_type *config);

task_type *enforce_task(engineconfig_type *config);

#endif
