#!/usr/bin/env bash

#TEST: Use a Repository Capacity of 100000 and expect success

#TODO: Merge with 10-020 (many_repositories)?

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

ods_start_ods-control &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

ods_stop_ods-control &&
return 0

ods_kill
return 1
