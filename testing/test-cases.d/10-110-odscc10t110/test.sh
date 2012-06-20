#!/usr/bin/env bash
#
# Use a Repository Capacity of 1 and expect failure

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

log_this_timeout ods-control-enforcer-start 30 ods-control enforcer start &&
syslog_waitfor 60 'ods-enforcerd: .*Repository SoftHSM is full, cannot create more ZSKs for policy default' &&
syslog_waitfor 60 'ods-enforcerd: .*Not enough keys to satisfy zsk policy for zone: ods' &&
syslog_waitfor 60 'ods-enforcerd: .*\[engine\] enforcer started' &&

log_this_timeout ods-control-enforcer-stop 30 ods-control enforcer stop &&
syslog_waitfor 60 'ods-enforcerd: .*\[engine\] enforcer shutdown' &&
return 0

ods_kill
return 1
