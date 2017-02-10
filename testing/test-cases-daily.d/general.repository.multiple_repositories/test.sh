#!/usr/bin/env bash

#TEST: Configure 4 repositories and sign a single zone using 2 of these different repositories. 

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_softhsm_init_token 0 "OpenDNSSEC" "1234" "1234" &&
ods_softhsm_init_token 1 "OpenDNSSEC2" "1111" "1111" &&
ods_softhsm_init_token 2 "OpenDNSSEC3" "2222" "2222" &&
ods_softhsm_init_token 3 "OpenDNSSEC4" "3333" "3333" &&

ods_setup_env &&

ods_start_ods-control 360 &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

ods_stop_ods-control &&
return 0

ods_kill
return 1
