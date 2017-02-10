#!/usr/bin/env bash

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

echo -n "LINE: ${LINENO} " && ods_reset_env && 

echo -n "LINE: ${LINENO} " && ods_start_ods-control &&

echo -n "LINE: ${LINENO} " && find $INSTALL_ROOT -name core\* -delete &&
echo -n "LINE: ${LINENO} " && log_this 01 ods-enforcer zone add -z ods &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods.*RRSIG\[new=52 ' &&
echo -n "LINE: ${LINENO} " && test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && log_this 02 ods-signer stop &&
echo -n "LINE: ${LINENO} " && sleep 15 &&

# Re-start signer and check that it does not give an error
# indicating it could not used back-up files, and that the
# signatures are mostly re-used (why not all?).
echo -n "LINE: ${LINENO} " && log_this 03 ods-signer start &&
echo -n "LINE: ${LINENO} " && sleep 15 &&
echo -n "LINE: ${LINENO} " && log_this 04 ods-signer sign --all &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 60 2 'ods-signerd: .*\[STATS\] ods' &&
echo -n "LINE: ${LINENO} " && ! syslog_grep "unable to recover zone ods from backup, performing full sign" &&
echo -n "LINE: ${LINENO} " && syslog_grep_count 1 'ods-signerd: .*\[STATS\] ods.*RRSIG\[new=52 ' &&
echo -n "LINE: ${LINENO} " && ! syslog_grep_count 2 'ods-signerd: .*\[STATS\] ods.*RRSIG\[new=52 ' &&
echo -n "LINE: ${LINENO} " && ! syslog_grep "unable to recover zone ods from backup, performing full sign" &&
echo -n "LINE: ${LINENO} " && syslog_grep 'ods-signerd: .*\[STATS\] ods.*RRSIG\[new=[0-9]* reused=[^0]' &&

echo -n "LINE: ${LINENO} " && ods_stop_ods-control &&

# There should be no core dump
echo -n "LINE: ${LINENO} " && test `find $INSTALL_ROOT -name core\* | wc -l` -eq 0 &&

return 0

ods_kill
return 1
