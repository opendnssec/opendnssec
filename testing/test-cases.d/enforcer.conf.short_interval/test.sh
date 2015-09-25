#!/usr/bin/env bash

#TEST: Change the Interval to 4 seconds and check if the enforcer runs 4 times


if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

ods_start_ods-control &&

ods_enforcer_waitfor_starts 5
#syslog_waitfor_count 60 5 'ods-enforcerd: .*Sleeping for' &&

ods_stop_ods-control  &&
return 0

ods_kill
return 1
