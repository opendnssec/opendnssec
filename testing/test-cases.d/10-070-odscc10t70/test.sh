#!/usr/bin/env bash
#
# Configure no PIN while PIN is needed, expect failure

ods_reset_env &&

! log_this ods-hsmutil-purge ods-hsmutil purge SoftHSM  &&
log_grep ods-hsmutil-purge stderr 'Incorrect PIN for repository SoftHSM' &&

! log_this ods-control-start ods-control start &&
syslog_waitfor 10 'ods-enforcerd: .*Incorrect PIN for repository SoftHSM' &&
syslog_waitfor 10 'ods-signerd: .*\[hsm\].*Incorrect PIN for repository SoftHSM' &&
return 0

ods_kill
return 1
