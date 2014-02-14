#!/usr/bin/env bash

#TEST: Set logging to a different channel and check if only the new channel receives ODS logging

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

ods_start_ods-control &&

syslog_grep 'ods-enforcerd: .*Log User set to: local1' &&
syslog_grep 'ods-enforcerd: .*Switched log facility to: local1' &&

ods_stop_ods-control &&
return 0

ods_kill
return 1
