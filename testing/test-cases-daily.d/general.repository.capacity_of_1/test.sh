#!/usr/bin/env bash

#TEST: Use a Repository Capacity of 1 and expect failure


if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

ods_start_enforcer &&
syslog_waitfor 60 'ods-enforcerd: .*Repository SoftHSM is full, cannot create more ZSKs for policy default' &&
syslog_waitfor 60 'ods-enforcerd: .*Not enough keys to satisfy zsk policy for zone: ods' &&

ods_stop_enforcer &&
return 0

ods_kill
return 1
