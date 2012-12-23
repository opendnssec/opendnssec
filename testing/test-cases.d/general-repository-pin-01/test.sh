#!/usr/bin/env bash

#TEST: Configure no PIN while PIN is needed, expect failure

#CATEGORY: general-repository-fail_as_no_pin


ods_reset_env &&

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql-no-module.xml
else
	ods_setup_conf conf.xml conf-no-module.xml
fi &&

! log_this ods-hsmutil-purge ods-hsmutil purge SoftHSM  &&
log_grep ods-hsmutil-purge stderr 'Incorrect PIN for repository SoftHSM' &&

! log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 10 'ods-enforcerd: .*Incorrect PIN for repository SoftHSM' &&

! log_this_timeout ods-control-signer-start 60 ods-control signer start &&
syslog_waitfor 10 'ods-signerd: .*\[hsm\].*Incorrect PIN for repository SoftHSM' &&

! pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null &&
return 0

ods_kill
return 1
