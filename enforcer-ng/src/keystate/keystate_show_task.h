#ifndef _KEYSTATE_SHOW_TASK_H_
#define _KEYSTATE_SHOW_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_keystate_show(int sockfd, engineconfig_type *config,
                           const char *id);

#endif
