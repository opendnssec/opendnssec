#ifndef _KEYSTATE_DS_SUBMIT_TASK_H_
#define _KEYSTATE_DS_SUBMIT_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void
perform_keystate_ds_submit(int sockfd, engineconfig_type *config,
                           const char *zone, const char *id, int bauto);

task_type *
keystate_ds_submit_task(engineconfig_type *config, const char *what,
                        const char *who);

#endif
