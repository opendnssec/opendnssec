/*
 * policy_purge_task.h
 *
 *  Created on: 2013��10��18��
 *      Author: zhangjm
 */

#ifndef POLICY_PURGE_TASK_H_
#define POLICY_PURGE_TASK_H_

#include "daemon/cfg.h"
#include "scheduler/task.h"

int perform_policy_purge(int sockfd, engineconfig_type *config);

#endif /* POLICY_PURGE_TASK_H_ */
