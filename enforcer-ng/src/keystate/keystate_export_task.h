#ifndef _KEYSTATE_EXPORT_TASK_H_
#define _KEYSTATE_EXPORT_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_keystate_export(int sockfd, engineconfig_type *config,
                             const char *id);

#endif
