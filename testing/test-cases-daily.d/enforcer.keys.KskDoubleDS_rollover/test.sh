#!/usr/bin/env bash

#TEST: KSK Rollover - Double-DS Mechanism

case "$DISTRIBUTION" in
        redhat )
                append_path /usr/sbin
                ;;
esac

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env && 

echo &&
echo "#################### START AND LEAP TIME #################### " &&
echo -n "LINE: ${LINENO} " && ods_start_enforcer && sleep 1 &&
echo -n "LINE: ${LINENO} " && KSK1=`ods-enforcer key list -v -p --all | grep "KSK" | cut -d ";" -f9` &&

# Leap to the time that both KSK and ZSK are used for signing
echo -n "LINE: ${LINENO} " && sleep 2 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && sleep 2 && ods-enforcer time leap && sleep 3 &&

echo -n "LINE: ${LINENO} " && ods-enforcer key ds-submit -z ods --keytag $KSK1 && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-seen -z ods --keytag $KSK1 && sleep 3 &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-enforcer time leap && sleep 3 &&

# KSK must be active now
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v -p | grep KSK | grep active &&

echo &&
echo "########### VERIFY SIGNATURES IN THE SIGNED FILE ############ " &&
echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&

echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 1 'ods-signerd: .*\[STATS\] ods' &&
echo -n "LINE: ${LINENO} " && test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo -n "LINE: ${LINENO} " && validns -t $time "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo &&
echo "############## ROLL KSK: DOUBLE-DS METHOD ############## " &&
echo -n "LINE: ${LINENO} " && ods-enforcer key rollover -z ods --keytype ksk && sleep 5 &&

# in Double DS mechanism, DS is published before publishing the DNSKEY
# Pub and Act have 0 value
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v -p --all &&
echo -n "LINE: ${LINENO} " && KSK2=`ods-enforcer key list -v -p --all | grep "KSK" | grep "publish" | cut -d ";" -f9` &&
ods-enforcer key list -d -p | grep "KSK" | grep "rumoured;hidden;hidden;NA;0;0" &&

echo &&
echo "############# CHECK SIGNATURES AFTER ROLLOVER ############# " &&
echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer update --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 3 'ods-signerd: .*\[STATS\] ods' &&

# Check that there must be only one DNSKEY and one RRSIG for DNSKEY 
echo -n "LINE: ${LINENO} " && count=`grep -c "DNSKEY[[:space:]]*257" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&

echo -n "LINE: ${LINENO} " && count=`grep -c "IN[[:space:]]*RRSIG[[:space:]]*DNSKEY" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&

echo -n "LINE: ${LINENO} " && validns -t $time "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 4 &&

echo &&
echo "######## LEAP TIME TILL THE ROLLOVER IS COMPLETED ############ " &&
# New KSK is waiting for ds-seen 
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-submit -z ods --keytag $KSK2 && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-seen -z ods --keytag $KSK2 && sleep 3 &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-enforcer time leap && sleep 3 &&

echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep "ods;KSK;omnipresent;rumoured;rumoured;NA;1;1" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep "ods;KSK;omnipresent;unretentive;unretentive;NA;0;0" &&

echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer update --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 5 'ods-signerd: .*\[STATS\] ods' &&

echo -n "LINE: ${LINENO} " && count=`grep -c "IN[[:space:]]*RRSIG[[:space:]]*DNSKEY" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&

echo -n "LINE: ${LINENO} " && grep "RRSIG[[:space:]]*DNSKEY" "$INSTALL_ROOT/var/opendnssec/signed/ods" | grep $KSK2 &&

echo -n "LINE: ${LINENO} " && validns -t $time "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-retract -z ods --keytag $KSK1 && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-gone -z ods --keytag $KSK1 && sleep 3 &&

echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer update --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 7 'ods-signerd: .*\[STATS\] ods' &&

echo -n "LINE: ${LINENO} " && validns -t $time "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-enforcer time leap && sleep 3 &&

echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer update --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 9 'ods-signerd: .*\[STATS\] ods' &&

echo -n "LINE: ${LINENO} " && validns -t $time "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-enforcer time leap && sleep 3 &&

echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer update --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 11 'ods-signerd: .*\[STATS\] ods' &&

echo -n "LINE: ${LINENO} " && validns -t $time "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo &&
echo "############################ STOP ############################ " &&
echo -n "LINE: ${LINENO} " && ods_stop_ods-control &&
return 0

echo "#################### ERROR: CURRENT STATE ####################"
echo "DEBUG: " && ods-enforcer key list -d
echo "DEBUG: " && ods-enforcer key list -v
echo "DEBUG: " && ods-enforcer queue

ods_kill
return 1

