#!/usr/bin/env bash

#TEST: RequireBackup turned on and check that non-backedup keys are not used if backup not done. Then back the keys up and check the zone is signed OK.

#CATEGORY: general-repository-keys-require_backup

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 60 'ods-enforcerd: .*NOTE: keys generated in repository SoftHSM will not become active until they have been backed up' &&
syslog_waitfor 60 'ods-enforcerd: .*ERROR: Trying to make non-backed up ZSK active when RequireBackup flag is set' &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&

log_this ods-ksmutil-backup-prepare ods-ksmutil backup prepare &&
log_this ods-ksmutil-backup-commit ods-ksmutil backup commit &&
log_this ods-ksmutil-notify ods-ksmutil notify &&
syslog_waitfor_count 60 2 'ods-enforcerd: .*Sleeping for' &&

log_this_timeout ods-control-signer-start 60 ods-control signer start &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

log_this_timeout ods-control-stop 60 ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
return 0

ods_kill
return 1
