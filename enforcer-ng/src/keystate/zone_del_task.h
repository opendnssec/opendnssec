#ifndef _KEYSTATE_ZONE_DEL_TASK_H_
#define _KEYSTATE_ZONE_DEL_TASK_H_

#include "daemon/cfg.h"

void perform_zone_del(int sockfd, engineconfig_type *config, const char *zone);

#endif
