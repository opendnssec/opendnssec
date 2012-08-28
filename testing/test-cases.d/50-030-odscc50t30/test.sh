#!/usr/bin/env bash
#
# Change the /tmp location and change WorkingDirectory in conf.xml accordingly

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

rm -rf "$INSTALL_ROOT/var/opendnssec/tmp" &&
rm -rf "$INSTALL_ROOT/var/opendnssec/temp" &&
mkdir "$INSTALL_ROOT/var/opendnssec/temp" &&

ods_reset_env &&

log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&

log_this_timeout ods-control-signer-start 60 ods-control signer start &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

log_this_timeout ods-control-start 60 ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&

! test -d "$INSTALL_ROOT/var/opendnssec/tmp" &&
rm -rf "$INSTALL_ROOT/var/opendnssec/temp" &&
mkdir "$INSTALL_ROOT/var/opendnssec/tmp" &&

return 0

ods_kill
rm -rf "$INSTALL_ROOT/var/opendnssec/temp"
mkdir "$INSTALL_ROOT/var/opendnssec/tmp"
return 1
