#ifndef _HSMKEY_UPDATE_HSMKEYS_TASK_H_
#define _HSMKEY_UPDATE_HSMKEYS_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_update_hsmkeys(int sockfd, engineconfig_type *config);

task_type *update_hsmkeys_task(engineconfig_type *config, 
                               const char *shortname);

#endif
