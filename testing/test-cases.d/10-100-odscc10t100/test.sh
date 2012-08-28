#!/usr/bin/env bash
#
# Use a Repository Capacity of 0 and expect failure

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

! ods_reset_env &&
log_grep ods-ksmutil-setup stderr "Type positiveInteger doesn't allow value '0'" &&

! log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 10 "ods-enforcerd: .*Type positiveInteger doesn't allow value '0'" &&
! pgrep -u `id -u` 'ods-enforcerd' >/dev/null 2>/dev/null &&

! log_this_timeout ods-control-signer-start 60 ods-control signer start &&
# signer does not log anything to syslog if reading conf.xml
! pgrep -u `id -u` 'ods-signerd' >/dev/null 2>/dev/null &&

return 0

ods_kill
return 1
