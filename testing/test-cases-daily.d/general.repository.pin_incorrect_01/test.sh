#!/usr/bin/env bash

#TEST: Use correct PIN plus one additional character while PIN is needed, expect failure

#TODO: Merge with 10-080 (fail_incorrect_pin)?

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env_noenforcer &&

! log_this ods-hsmutil-purge ods-hsmutil purge SoftHSM  &&
log_grep ods-hsmutil-purge stderr 'Incorrect PIN for repository SoftHSM' &&

! ods_start_enforcer &&
syslog_waitfor 10 'ods-enforcerd: .*Incorrect PIN for repository SoftHSM' &&

! ods_start_signer &&
syslog_waitfor 10 'ods-signerd: .* Incorrect PIN for repository SoftHSM' &&
syslog_waitfor 10 'ods-signerd: \[engine\] opening hsm failed' &&

! pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null &&

return 0

ods_kill
return 1
