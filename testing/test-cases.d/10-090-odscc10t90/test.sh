#!/usr/bin/env bash
#
# Use correct PIN plus one additional character, expect failure

ods_reset_env &&

! log_this ods-hsmutil-purge ods-hsmutil purge SoftHSM  &&
log_grep ods-hsmutil-purge stderr 'Incorrect PIN for repository SoftHSM' &&

! log_this ods-control-start ods-control start &&
syslog_waitfor 10 'ods-enforcerd: .*Incorrect PIN for repository SoftHSM' &&
syslog_waitfor 10 'ods-signerd: .*\[engine\].*setup failed: HSM error' &&
return 0

ods_kill
return 1
