#!/usr/bin/env bash

#TEST: Change the kasp.xml location and change PolicyFile in conf.xml accordingly


if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf2-mysql.xml
else
	ods_setup_conf conf.xml conf2.xml
fi &&
mv -- "$INSTALL_ROOT/etc/opendnssec/kasp.xml" "$INSTALL_ROOT/etc/opendnssec/kasp2.xml" &&

log_this_timeout ods-control-start 60 ods-control start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

log_this_timeout ods-control-stop 60 ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
return 0

ods_kill
return 1
