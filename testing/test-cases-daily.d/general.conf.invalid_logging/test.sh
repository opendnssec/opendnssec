#!/usr/bin/env bash

#TEST: Set logging to a invalid channel and expect failure.


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

! ods_start_enforcer &&
syslog_waitfor 10 'ods-enforcerd: .*Error validating file' &&
syslog_waitfor 10 'ods-enforcerd: .*Error validating value' &&
syslog_waitfor 10 'ods-enforcerd: .*Element Facility failed to validate content' &&
! pgrep -u `id -u` 'ods-enforcerd' >/dev/null 2>/dev/null &&

! ods_start_signer &&
# signer does not log anything to syslog if invalid config
! pgrep -u `id -u` 'ods-signerd' >/dev/null 2>/dev/null &&

return 0

ods_kill
return 1
