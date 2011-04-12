#ifndef _ZONE_UPDATE_TASK_H_
#define _ZONE_UPDATE_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_update(int sockfd, engineconfig_type *config);

task_type *update_task(engineconfig_type *config);

#endif
