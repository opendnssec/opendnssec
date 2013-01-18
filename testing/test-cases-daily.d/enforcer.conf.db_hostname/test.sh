#!/usr/bin/env bash

#TEST: Change the Hostname for database and check if enforcer fails to connect

#TODO: Merge with 40-010 (change_db_port)?

if [ -z "$HAVE_MYSQL" ]; then
	return 0
fi &&

! ods_reset_env &&

ods_setup_conf conf.xml conf-correct.xml &&

ods_reset_env &&

ods_setup_conf conf.xml conf.xml &&

! log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 80 "ods-enforcerd: .*ERROR: unable to connect to database - Can't connect to MySQL server on 'www.opendnssec.org'" &&
! pgrep -u `id -u` 'ods-enforcerd' >/dev/null 2>/dev/null &&
return 0

ods_kill
return 1
