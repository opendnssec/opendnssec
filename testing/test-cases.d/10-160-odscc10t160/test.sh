#!/usr/bin/env bash
#
# "RequireBackup turned on, backup keys, and sign zone"

ods_reset_env &&

log_this ods-control-enforcer-start ods-control enforcer start &&
syslog_waitfor 60 'ods-enforcerd: .*NOTE: keys generated in repository SoftHSM will not become active until they have been backed up' &&
syslog_waitfor 60 'ods-enforcerd: .*ERROR: Trying to make non-backed up ZSK active when RequireBackup flag is set' &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&

log_this ods-ksmutil-backup-prepare ods-ksmutil backup prepare &&
log_this ods-ksmutil-backup-commit ods-ksmutil backup commit &&
log_this ods-ksmutil-notify ods-ksmutil notify &&

log_this ods-control-signer-start ods-control signer start &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

log_this ods-control-stop ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
return 0

ods_kill
return 1
