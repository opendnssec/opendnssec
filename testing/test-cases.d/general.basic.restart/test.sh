#!/usr/bin/env bash

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env && 

ods_start_ods-control &&

find $INSTALL_ROOT -name core\* -delete &&
log_this 01 ods-enforcer zone add -z ods &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods.*RRSIG\[new=51 ' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
log_this 02 ods-signer stop &&
sleep 5 &&

# Re-start signer and check that it does not give an error
# indicating it could not used back-up files, and that the
# signatures are mostly re-used (why not all?).
log_this 03 ods-signer start &&
sleep 5 &&
log_this 04 ods-signer sign --all &&
syslog_waitfor_count 60 2 'ods-signerd: .*\[STATS\] ods' &&
! syslog_grep "unable to recover zone ods from backup, performing full sign" &&
syslog_grep_count 1 'ods-signerd: .*\[STATS\] ods.*RRSIG\[new=51 ' &&
! syslog_grep_count 2 'ods-signerd: .*\[STATS\] ods.*RRSIG\[new=51 ' &&
! syslog_grep "unable to recover zone ods from backup, performing full sign" &&
syslog_grep 'ods-signerd: .*\[STATS\] ods.*RRSIG\[new=[0-9]* reused=[^0]' &&

ods_stop_ods-control &&

# There should be no core dump
test `find $INSTALL_ROOT -name core\* | wc -l` -eq 0 &&

return 0

ods_kill
return 1
