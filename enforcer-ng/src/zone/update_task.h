#ifndef _ZONE_UPDATE_ZONELIST_TASK_H_
#define _ZONE_UPDATE_ZONELIST_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_update_zonelist(int sockfd, engineconfig_type *config);

task_type *update_zonelist_task(engineconfig_type *config);

#endif
