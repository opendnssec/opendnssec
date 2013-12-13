/*
 * update_conf_task.cpp
 *
 *  Created on: 2013Äê10ÔÂ8ÈÕ
 *      Author: zhangjm
 */
#include "update_conf_task.h"

#include "config.h"
#include "daemon/cfg.h"
#include "parser/confparser.h"
#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/status.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>


int perform_update_conf(engine_type* engine, const char *cmd,ssize_t n){

	 int cmdline_verbosity = 0;
	 const char* cfgfile = ODS_SE_CFGFILE;


    engine->config->hsm = parse_conf_repositories(cfgfile);

}

