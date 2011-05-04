#ifndef _HSMKEY_GEN_TASK_H_
#define _HSMKEY_GEN_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_hsmkey_gen(int sockfd, engineconfig_type *config);

task_type *hsmkey_gen_task(engineconfig_type *config, const char *shortname);

#endif
