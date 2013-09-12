#!/usr/bin/env bash
#
#TEST: Change the zonefetch.xml location and change ZoneFetchFile in conf.xml accordingly

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf2-mysql.xml
else
	ods_setup_conf conf.xml conf2.xml
fi &&
mv -- "$INSTALL_ROOT/etc/opendnssec/zonefetch.xml" "$INSTALL_ROOT/etc/opendnssec/zonefetch2.xml" &&

ods_start_ods-control &&
ods_stop_ods-control &&

return 0

ods_kill
return 1
