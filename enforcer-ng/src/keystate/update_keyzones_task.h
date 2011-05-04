#ifndef _KEYSTATE_UPDATE_KEYZONES_TASK_H_
#define _KEYSTATE_UPDATE_KEYZONES_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_update_keyzones(int sockfd, engineconfig_type *config);

task_type *update_keyzones_task(engineconfig_type *config,
                                 const char *shortname);

#endif
