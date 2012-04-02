#!/usr/bin/env bash
#
# Use a Repository Capacity of 1 and expect failure

ods_reset_env &&

log_this ods-control-enforcer-start ods-control enforcer start &&
syslog_waitfor 60 'ods-enforcerd: .*Repository SoftHSM is full, cannot create more ZSKs for policy default' &&
syslog_waitfor 60 'ods-enforcerd: .*Not enough keys to satisfy zsk policy for zone: ods' &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&

log_this ods-control-enforcer-stop ods-control enforcer stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
return 0

ods_kill
return 1
