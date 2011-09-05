#ifndef _KEYSTATE_EXPORT_TASK_H_
#define _KEYSTATE_EXPORT_TASK_H_

#include "daemon/cfg.h"

void perform_keystate_export(int sockfd, engineconfig_type *config,
                             const char *zone, int bds);

#endif
