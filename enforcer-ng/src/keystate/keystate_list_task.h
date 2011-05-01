#ifndef _KEYSTATE_LIST_TASK_H_
#define _KEYSTATE_LIST_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_keystate_list(int sockfd, engineconfig_type *config);

task_type *keystate_list_task(engineconfig_type *config);

#endif
