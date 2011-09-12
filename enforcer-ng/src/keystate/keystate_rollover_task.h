#ifndef _KEYSTATE_ROLLOVER_TASK_H_
#define _KEYSTATE_ROLLOVER_TASK_H_

#include "daemon/cfg.h"

void perform_keystate_rollover(int sockfd, engineconfig_type *config,
                               const char *zone, const char *keytype);

#endif
