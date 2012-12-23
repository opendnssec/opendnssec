#!/usr/bin/env bash

#TEST: Set logging to a invalid channel and expect failure.

#CATEGORY: general-common-fail_invalid_logging_channel

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

! ods_reset_env &&
log_grep ods-ksmutil-setup stdout 'Error validating file' &&
log_grep ods-ksmutil-setup stderr 'element Facility: Relax-NG validity error : Error validating value' &&
log_grep ods-ksmutil-setup stderr 'element Facility: Relax-NG validity error : Element Facility failed to validate content' &&

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-correct-mysql.xml
else
	ods_setup_conf conf.xml conf-correct.xml
fi &&
ods_reset_env &&
if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
else
	ods_setup_conf conf.xml conf.xml
fi &&

! log_this_timeout ods-control-start 30 ods-control enforcer start &&
syslog_waitfor 10 'ods-enforcerd: .*Error validating file' &&
syslog_waitfor 10 'ods-enforcerd: .*Error validating value' &&
syslog_waitfor 10 'ods-enforcerd: .*Element Facility failed to validate content' &&
! pgrep -u `id -u` 'ods-enforcerd' >/dev/null 2>/dev/null &&

! log_this_timeout ods-control-signer-start 30 ods-control signer start &&
# signer does not log anything to syslog if invalid config
! pgrep -u `id -u` 'ods-signerd' >/dev/null 2>/dev/null &&

return 0

ods_kill
return 1
