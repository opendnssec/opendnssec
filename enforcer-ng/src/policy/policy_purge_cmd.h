/*
 * policy_purge_cmd.h
 *
 *  Created on: 2013��10��18��
 *      Author: zhangjm
 */

#ifndef POLICY_PURGE_CMD_H_
#define POLICY_PURGE_CMD_H_

#include "daemon/engine.h"

#ifdef __cplusplus
extern "C" {
#endif

void
help_policy_purge_cmd(int sockfd);

int
handled_policy_purge_cmd(int sockfd, engine_type* engine, const char *cmd,
                          ssize_t n);

#ifdef __cplusplus
}
#endif

#endif /* POLICY_PURGE_CMD_H_ */
