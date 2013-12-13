/*
 * update_conf_cmd.h
 *
 *  Created on: 2013Äê10ÔÂ11ÈÕ
 *      Author: zhangjm
 */

#ifndef UPDATE_CONF_CMD_H_
#define UPDATE_CONF_CMD_H_

#include "enforcer/update_conf_task.h"
#include "daemon/engine.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef __cplusplus
extern "C" {
#endif


void help_update_conf_cmd(int sockfd);

int handled_update_conf_cmd(int sockfd, engine_type* engine, const char *cmd, ssize_t n);

#ifdef __cplusplus
}
#endif

#endif /* UPDATE_CONF_CMD_H_ */
