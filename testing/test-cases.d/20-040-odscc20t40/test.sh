#!/usr/bin/env bash
#
# Change the zonelist.xml location and change ZoneListFile in conf.xml accordingly

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf2-mysql.xml
else
	ods_setup_conf conf.xml conf2.xml
fi &&
mv -- "$INSTALL_ROOT/etc/opendnssec/zonelist.xml" "$INSTALL_ROOT/etc/opendnssec/zonelist2.xml" &&

log_this_timeout ods-control-start 30 ods-control start &&
syslog_waitfor 60 'ods-enforcerd: .*\[engine\] enforcer started' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

log_this_timeout ods-control-stop 30 ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*\[engine\] enforcer shutdown' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
return 0

ods_kill
return 1
