#ifndef _SIGNCONF_SIGNCONF_TASK_H_
#define _SIGNCONF_SIGNCONF_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_signconf(int sockfd, engineconfig_type *config);

task_type *signconf_task(engineconfig_type *config);

#endif
