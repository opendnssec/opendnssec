#!/usr/bin/env bash
#
# Configure and sign with one repository (SoftHSM)

log_this ods-control-enforcer-start ods-control enforcer start &&
log_grep ods-control-enforcer-start stdout 'OpenDNSSEC ods-enforcerd started' &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&

log_this ods-control-signer-start ods-control signer start &&
log_grep ods-control-signer-start stdout 'Engine running' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

log_this ods-control-start ods-control stop &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
syslog_grep 'ods-enforcerd: .*all done' &&
return 0

ods_kill
return 1
