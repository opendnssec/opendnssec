#ifndef _POLICY_POLICY_RESALT_TASK_H_
#define _POLICY_POLICY_RESALT_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

time_t perform_policy_resalt(int sockfd, engineconfig_type *config);

task_type *policy_resalt_task(engineconfig_type *config);

#endif
