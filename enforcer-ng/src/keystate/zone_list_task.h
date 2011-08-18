#ifndef _KEYSTATE_ZONE_LIST_TASK_H_
#define _KEYSTATE_ZONE_LIST_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_zone_list(int sockfd, engineconfig_type *config);

#endif
