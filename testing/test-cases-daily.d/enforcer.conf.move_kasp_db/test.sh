#!/usr/bin/env bash

#TEST: Change the kasp.db location and change Datastore in conf.xml accordingly

if [ -n "$HAVE_MYSQL" ]; then
	return 0
fi &&

ods_reset_env &&
ods_start_ods-control &&

log_this ods-enforcer-zone-list-1 ods-enforcer zone list &&
log_grep ods-enforcer-zone-list-1 stdout "Database set to: .*kasp.db" &&

ods_stop_ods-control &&


ods_setup_conf conf.xml conf2.xml &&
mv -- "$INSTALL_ROOT/var/opendnssec/kasp.db" "$INSTALL_ROOT/var/opendnssec/kasp2.db" &&

ods_start_ods-control &&

log_this ods-enforcer-zone-list-2 ods-enforcer zone list &&
log_grep ods-enforcer-zone-list-2 stdout "Database set to: .*kasp2.db" &&

ods_stop_ods-control &&
return 0

ods_kill
return 1
