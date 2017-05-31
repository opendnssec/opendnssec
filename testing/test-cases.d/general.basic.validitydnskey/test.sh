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

echo -n "LINE: ${LINENO} " && ods_reset_env -i &&
echo -n "LINE: ${LINENO} " && ods_start_enforcer &&

echo -n "LINE: ${LINENO} " && echo "verifying without keyset validity set" &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add -z ods -p plainkeysetvalidity &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo -n "LINE: ${LINENO} " && ods_start_signer &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 60 1 'ods-signerd: .*\[STATS\] ods' &&
echo -n "LINE: ${LINENO} " && echo "  there should be no keyset entry in signconf" &&
echo -n "LINE: ${LINENO} " && ! grep -q "<Keyset>.*</Keyset>" $INSTALL_ROOT/var/opendnssec/signconf/ods.xml &&
echo -n "LINE: ${LINENO} " && echo "  validity of keyset signature should be around 8H (per per default validity)" &&
echo -n "LINE: ${LINENO} " && testvalidity 28800 &&

echo -n "LINE: ${LINENO} " && ods-enforcer zone delete -z ods &&
echo -n "LINE: ${LINENO} " && rm -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && rm -f "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer &&

echo -n "LINE: ${LINENO} " && echo "verifying with keyset validity explicitly set" &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add -z ods -p explicitkeysetvalidity &&
echo -n "LINE: ${LINENO} " && sleep 1 &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo -n "LINE: ${LINENO} " && ods-enforcer queue &&
echo -n "LINE: ${LINENO} " && ods_start_signer &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 60 2 'ods-signerd: .*\[STATS\] ods' &&
echo -n "LINE: ${LINENO} " && echo "  there should be a keyset entry in signconf" &&
echo -n "LINE: ${LINENO} " && grep -q "<Keyset>.*</Keyset>" $INSTALL_ROOT/var/opendnssec/signconf/ods.xml &&
echo -n "LINE: ${LINENO} " && echo "  validity of keyset signature should be around 12H (per explicitly defined)" &&
echo -n "LINE: ${LINENO} " && testvalidity 43200 &&

echo -n "LINE: ${LINENO} " && ods_stop_ods-control &&
return 0

echo "################## ERROR: CURRENT STATE ###########################"
echo "DEBUG: " && ods-enforcer zone list
echo "DEBUG: " && ods-enforcer key list -d -p
echo "DEBUG: " && ods-enforcer key list -v
echo "DEBUG: " && ods-enforcer queue
echo
echo "************ERROR******************"
echo
ods_kill
return 1
