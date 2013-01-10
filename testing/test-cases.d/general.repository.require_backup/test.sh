#!/usr/bin/env bash

#TEST: RequireBackup turned on and check that non-backedup keys are not used if backup not done.

#CATEGORY: general-repository-fail_require_backup

#TODO: Remove as duplicates first part of 10-160 (require_backup)

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 60 'ods-enforcerd: .*NOTE: keys generated in repository SoftHSM will not become active until they have been backed up' &&
syslog_waitfor 60 'ods-enforcerd: .*ERROR: Trying to make non-backed up ZSK active when RequireBackup flag is set' &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&

log_this_timeout ods-control-enforcer-stop 60 ods-control enforcer stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
return 0

ods_kill
return 1
