#!/usr/bin/env bash

#TEST: Change the zonelist.xml location and change ZoneListFile in conf.xml accordingly

#TODO: Merge with 20-030 (change_kasp_xml_location)?

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

ods_start_ods-control &&
ods_stop_ods-control &&
return 0

ods_kill
return 1
