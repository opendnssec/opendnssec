#!/usr/bin/env bash

#TEST: Change the /tmp location and change WorkingDirectory in conf.xml accordingly


if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

rm -rf "$INSTALL_ROOT/var/opendnssec/tmp" &&
rm -rf "$INSTALL_ROOT/var/opendnssec/temp" &&
mkdir "$INSTALL_ROOT/var/opendnssec/temp" &&

ods_reset_env &&

ods_start_ods-control &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

ods_stop_ods-control &&

! test -d "$INSTALL_ROOT/var/opendnssec/tmp" &&
rm -rf "$INSTALL_ROOT/var/opendnssec/temp" &&
mkdir "$INSTALL_ROOT/var/opendnssec/tmp" &&

return 0

ods_kill
rm -rf "$INSTALL_ROOT/var/opendnssec/temp"
mkdir "$INSTALL_ROOT/var/opendnssec/tmp"
return 1
