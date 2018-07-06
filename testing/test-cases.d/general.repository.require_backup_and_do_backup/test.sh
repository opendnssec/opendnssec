#!/usr/bin/env bash

#TEST: RequireBackup turned on and check that non-backedup keys are not used if backup not done. Then back the keys up and check the zone is signed OK.


if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

ods_start_enforcer &&
#syslog_grep 'ods-enforcerd: .*NOTE: keys generated in repository SoftHSM will not become active until they have been backed up' &&
#syslog_grep 'ods-enforcerd: .*ERROR: Trying to make non-backed up ZSK active when RequireBackup flag is set' &&

log_this ods-enforcer-backup-prepare ods-enforcer backup prepare &&
log_this ods-enforcer-backup-commit ods-enforcer backup commit &&

# Count how many times the enforcer has run
ods_enforcer_count_starts &&

#log_this ods-enforcer-notify ods-enforcer notify &&
# We should see the enforcer wake up and run once more
#ods_enforcer_waitfor_starts $(( ODS_ENFORCER_START_COUNT + 1 )) &&

ods_start_signer &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

# The signer indicates the zone is signed, however the enforcer
# manages the key generation.  Hence give the enforcer time to
# generate the necessary keys.
#sleep 60 &&

log_this ods-hsmutil-list ods-hsmutil list &&
# Number of keys is not always the same
#log_grep ods-hsmutil-list stdout '15 keys found.' &&
log_grep ods-hsmutil-list stdout 'Repository.*ID.*Type' &&
log_grep ods-hsmutil-list stdout 'SoftHSM.*RSA/1024' &&

ods_stop_ods-control &&
return 0

ods_kill
return 1
