#!/usr/bin/env bash
#
# Change WorkerThreads to 1 and check if only 1 thread is used

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

log_this_timeout ods-control-start 30 ods-control start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

syslog_waitfor 10 'ods-signerd: .*\[worker\[1\]\] report for duty' &&

log_this_timeout ods-control-stop 30 ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&

! syslog_grep 'ods-signerd: .*\[worker\[2\]\] report for duty' &&
return 0

ods_kill
return 1
