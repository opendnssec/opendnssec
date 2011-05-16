#ifndef _HSMKEY_LIST_TASK_H_
#define _HSMKEY_LIST_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_hsmkey_list(int sockfd, engineconfig_type *config, int bVerbose);

#endif
