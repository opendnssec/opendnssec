#!/usr/bin/env bash
#
# Configure an Incorrect PIN and run signing

ods_reset_env &&

! log_this ods-control-start ods-control start &&
syslog_waitfor 60 'ods-enforcerd: .*Incorrect PIN for repository SoftHSM' &&
syslog_grep 'ods-signerd: .*\[engine\].*setup failed: HSM error' &&
return 0

ods_kill
return 1
