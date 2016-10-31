#!/usr/bin/env bash

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

testvalidity() {
	local until
	local starting
	until=`awk < $INSTALL_ROOT/var/opendnssec/signed/ods '($4=="RRSIG"&&$5=="DNSKEY") {print $9;}'`
	starting=`awk < $INSTALL_ROOT/var/opendnssec/signed/ods '($4=="RRSIG"&&$5=="DNSKEY") {print $10;}'`
	# Skip the real check if no GNU date command present that accepts --date option
	if date 2>/dev/null >/dev/null --date 0 ; then
	until=`echo $until       | sed 's/\(....\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3 \4:\5/'`
	starting=`echo $starting | sed 's/\(....\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3 \4:\5/'`
	until=`date --date "$until" +%s`
	starting=`date --date "$starting" +%s`
	    if [ "`expr $until - $starting`" -lt "`expr $1 - 121`" ]; then
		echo "`expr $1 - 121` <= `expr $until - $starting` <= `expr $1 + 121`"
		return 1
	    fi
	    if [ "`expr $until - $starting`" -gt "`expr $1 + 121`" ]; then
		echo "`expr $1 - 121` <= `expr $until - $starting` <= `expr $1 + 121`"
		return 1
	    fi
	else
	    until=`echo $until       | sed 's/\(....\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1\2\3\4\5/'`
	    starting=`echo $starting | sed 's/\(....\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1\2\3\4\5/'`
	    until=`date -j "$until" +%s`
	    starting=`date -j "$starting" +%s`
	    if [ "`expr $until - $starting`" -lt "`expr $1 - 121`" ]; then
		echo "`expr $1 - 121` <= `expr $until - $starting` <= `expr $1 + 121`"
		return 1
	    fi
	    if [ "`expr $until - $starting`" -gt "`expr $1 + 121`" ]; then
		echo "`expr $1 - 121` <= `expr $until - $starting` <= `expr $1 + 121`"
		return 1
	    fi
	fi
	return 0
}

ods_reset_env && 
ods_start_ods-control &&

echo "verifying without keyset validity set" &&
ods-enforcer zone add -z ods -p plainkeysetvalidity &&
syslog_waitfor_count 60 1 'ods-signerd: .*\[STATS\] ods' &&
ods_enforcer_leap_over 3600 &&
syslog_waitfor_count 60 2 'ods-signerd: .*\[STATS\] ods' &&
echo "  there should be no keyset entry in signconf" &&
! grep -q "<Keyset>.*</Keyset>" $INSTALL_ROOT/var/opendnssec/signconf/ods.xml &&
echo "  validity of keyset signature should be around 8H (per per default validity)" &&
testvalidity 28800 &&

ods-enforcer zone delete -z ods &&
ods_enforcer_idle &&
rm -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo "verifying with keyset validity explicitly set" &&
ods-enforcer zone add -z ods -p explicitkeysetvalidity &&
syslog_waitfor_count 60 3 'ods-signerd: .*\[STATS\] ods' &&
ods_enforcer_leap_over 3600 &&
syslog_waitfor_count 60 4 'ods-signerd: .*\[STATS\] ods' &&
echo "  there should be a keyset entry in signconf" &&
grep -q "<Keyset>.*</Keyset>" $INSTALL_ROOT/var/opendnssec/signconf/ods.xml &&
echo "  validity of keyset signature should be around 12H (per explicitly defined)" &&
testvalidity 43200 &&

ods_stop_ods-control &&
return 0

ods_kill
return 1
