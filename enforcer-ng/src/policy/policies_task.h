#ifndef _POLICY_POLICIES_TASK_H_
#define _POLICY_POLICIES_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_policies(int sockfd, engineconfig_type *config);

task_type *policies_task(engineconfig_type *config);

#endif
