/*
 * update_conf_task.h
 *
 *  Created on: 2013Äê10ÔÂ8ÈÕ
 *      Author: zhangjm
 */

#ifndef UPDATE_CONF_TASK_H_
#define UPDATE_CONF_TASK_H_

#include "config.h"
#include "daemon/engine.h"

#include "daemon/cfg.h"
#include "scheduler/task.h"

int perform_update_conf(engine_type* engine, const char *cmd, ssize_t n);


#endif /* UPDATE_CONF_TASK_H_ */
