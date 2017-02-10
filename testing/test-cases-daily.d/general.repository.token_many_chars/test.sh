#!/usr/bin/env bash

#TEST: Use a Tokenlabel with 30 character, sign a single zone.

#TODO: Merge with 10-020 (many_repositories)?

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_softhsm_init_token 0 "OpenDNSSEC" "1234" "1234" &&
ods_softhsm_init_token 1 "ABCDEFGHIJKLMNOPQRSTVWXYZ12345" "4321" "4321" &&



ods_setup_env &&

ods_start_ods-control 360 &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

ods_stop_ods-control &&
return 0

ods_kill
return 1
