#!/usr/bin/env bash

size=$3
if [ "$size" -eq "$size" ] 2>/dev/null; then
	true
else
	size=10000
fi

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

rm -f $INSTALL_ROOT/var/opendnssec/unsigned/* &&
rm -f $INSTALL_ROOT/var/opendnssec/tmp/* &&
ods_reset_env && 

sleep 10 &&

ods_start_ods-control &&

cp zonefiles/z$size $INSTALL_ROOT/var/opendnssec/unsigned/z$size &&
timestart=`date '+%s'` &&
ods-enforcer zone add --zone z$size &&
syslog_waitfor 20000 "ods-signerd: .*\[STATS\] z$size " &&
timestop=`date '+%s'` &&
memusage=`ps -C ods-signerd -o vsz= || true` &&
echo -n "STATISTICS	$size	$memusage	" &&
expr $timestop - $timestart &&

test -f "$INSTALL_ROOT/var/opendnssec/signed/z$size" &&

ods_stop_ods-control 1800 &&
return 0

ods_kill
return 1
