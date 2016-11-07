#!/usr/bin/env bash

#TEST: Change WorkerThreads to 32 and check if 32 threads are used


if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

ods_start_ods-control &&

syslog_waitfor 10 'ods-signerd: .*\[worker\[32\]\].*report for duty' &&
sleep 2 &&

ods_stop_ods-control &&

! syslog_grep 'ods-signerd: .*\[worker\[33\]\].*report for duty' &&
return 0

ods_kill
return 1
