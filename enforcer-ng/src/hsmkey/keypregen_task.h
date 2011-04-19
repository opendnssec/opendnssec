#ifndef _HSMKEY_KEYPREGEN_TASK_H_
#define _HSMKEY_KEYPREGEN_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_keypregen(int sockfd, engineconfig_type *config);

task_type *keypregen_task(engineconfig_type *config);

#endif
