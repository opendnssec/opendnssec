#ifndef _POLICY_POLICY_LIST_TASK_H_
#define _POLICY_POLICY_LIST_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_policy_list(int sockfd, engineconfig_type *config);

task_type *policy_list_task(engineconfig_type *config);

#endif
