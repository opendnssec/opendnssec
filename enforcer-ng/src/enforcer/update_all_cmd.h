/*
 * update_all_cmd.h
 *
 *  Created on: 2013Äê10ÔÂ11ÈÕ
 *      Author: zhangjm
 */

#ifndef UPDATE_ALL_CMD_H_
#define UPDATE_ALL_CMD_H_

#include "daemon/engine.h"

#ifdef __cplusplus
extern "C" {
#endif

void help_update_all_cmd(int sockfd);

int handled_update_all_cmd(int sockfd, engine_type* engine, const char *cmd,
					  ssize_t n);

#ifdef __cplusplus
}
#endif

#endif /* UPDATE_ALL_CMD_H_ */
