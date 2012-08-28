#!/usr/bin/env bash
#
# Use a different database name for database and check if enforcer fails to connect

if [ -z "$HAVE_MYSQL" ]; then
	return 0
fi &&

! ods_reset_env &&

ods_setup_conf conf.xml conf-correct.xml &&

ods_reset_env &&

ods_setup_conf conf.xml conf.xml &&

! log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 10 "ods-enforcerd: .*ERROR: unable to connect to database - Access denied for user 'test'@'localhost' to database 'test999'" &&
! pgrep -u `id -u` 'ods-enforcerd' >/dev/null 2>/dev/null &&
return 0

ods_kill
return 1
