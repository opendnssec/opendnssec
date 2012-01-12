#ifndef _KEYSTATE_ZONE_ADD_TASK_H_
#define _KEYSTATE_ZONE_ADD_TASK_H_

#include "daemon/cfg.h"

void perform_zone_add(int sockfd,
					  engineconfig_type *config,
					  const char *zone,
					  const char *policy,
					  const char *signerconf,
					  const char *ad_input_file,
					  const char *ad_output_file,
					  const char *ad_input_type,
					  const char *ad_input_config,
					  const char *ad_output_type,
					  const char *ad_output_config);

#endif
