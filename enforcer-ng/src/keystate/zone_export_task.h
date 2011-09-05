#ifndef _ZONE_EXPORT_TASK_H_
#define _ZONE_EXPORT_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

void perform_zone_export(int sockfd, engineconfig_type *config,
                         const char *zone);

#endif
