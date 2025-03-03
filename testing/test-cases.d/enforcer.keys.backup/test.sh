#!/usr/bin/env bash

ODS_ENFORCER_WAIT_STOP_LOG=600

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

##################  Basic behaviour  ###########################
# Fail with no zones
ods_start_enforcer &&

# Generate keys with algorithm 7, length 2048
log_this ods-zone-add-1 ods-enforcer zone add --zone ods1 --policy Policy1 &&
ods_enforcer_idle &&

syslog_waitfor 60 "ods-enforcerd: .*1 zone(s) found on policy \"Policy1\""  &&
syslog_waitfor 60 'ods-enforcerd: .*1 new KSK(s) (2048 bits) need to be created.'  &&
syslog_waitfor 60 'ods-enforcerd: .*5 new ZSK(s) (2048 bits) need to be created.' &&

log_this enforcer-backuplist ods-enforcer backup list --repository SoftHSM &&
log_grep enforcer-backuplist stdout "SoftHSM\s\+Required" &&
! log_grep enforcer-backuplist stdout "SoftHSM\s\+Not Required" &&

log_this enforcer-backupprepare ods-enforcer backup prepare --repository SoftHSM &&
log_grep enforcer-backupprepare stdout "info: keys flagged for backup: 8"

log_this enforcer-backuplist2 ods-enforcer backup list --repository SoftHSM &&
log_grep enforcer-backuplist2 stdout "SoftHSM\s\+Prepared" &&

log_this enforcer-backupcommit ods-enforcer backup commit --repository SoftHSM &&
log_grep enforcer-backupcommit stdout "info: keys marked backup done: 8"

log_this enforcer-backuplist3 ods-enforcer backup list --repository SoftHSM &&
log_grep enforcer-backuplist3 stdout "SoftHSM\s\+Done" &&

ods_stop_enforcer &&

echo && 
echo "************OK******************" &&
echo &&

return 0 

echo
echo "************ERROR******************"
echo
ods_kill
return 1
