#!/usr/bin/env bash

#TEST: Change WorkerThreads to 1 and check if only 1 thread is used


if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

ods_start_ods-control &&

syslog_waitfor 10 'ods-signerd: .*\[worker\[1\]\].*report for duty' &&

ods_stop_ods-control &&

! syslog_grep 'ods-signerd: .*\[worker\[2\]\].*report for duty' &&
return 0

ods_kill
return 1
