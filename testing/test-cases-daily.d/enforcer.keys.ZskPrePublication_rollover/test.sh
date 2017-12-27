#!/usr/bin/env bash

#TEST: ZSK Rollover - Pre-Publication Mechanism


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

echo -n "LINE: ${LINENO} " && ods-enforcer key list -v -p &&
echo -n "LINE: ${LINENO} " && ZSK1=`ods-enforcer key list -v -p | grep "ZSK" | cut -d ";" -f7` &&
echo -n "LINE: ${LINENO} " && KSK1=`ods-enforcer key list -v -p | grep "KSK" | cut -d ";" -f7` &&

# Leap to the time that both KSK and ZSK are used for signing
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer key ds-submit -z ods --cka_id $KSK1 && sleep 3 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer key ds-seen -z ods --cka_id $KSK1 && sleep 3 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&

echo &&
echo "########### VERIFY SIGNATURES IN THE SIGNED FILE ############ " &&
echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&

echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 1 'ods-signerd: .*\[STATS\] ods' &&
echo -n "LINE: ${LINENO} " && test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo -n "LINE: ${LINENO} " && count=`grep -c "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&

echo -n "LINE: ${LINENO} " && validns -t $time "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo &&
echo "############## ROLL ZSK: PRE-PUBLICATION METHOD ############## " &&
echo -n "LINE: ${LINENO} " && ods-enforcer key rollover -z ods --keytype zsk && sleep 5 &&

# In the PrePublication mechanism, DNSKEY is published before the RRSIG
# Check DNSKEY must be rumoured while RRSIG is hidden, also Pub is 1 and Act is 0 which means
# before using the new key for signign, DNSKEY must be published
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p --all &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v -p --all &&
echo -n "LINE: ${LINENO} " && ZSK2=`ods-enforcer key list -d -p | grep "ZSK" | grep "rumoured;NA;hidden;1;0"| cut -d ";" -f9` &&

echo &&
echo "############## CHECK SIGNATURES AFTER ROLLOVER ############## " &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 3 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 3 'ods-signerd: .*\[STATS\] ods' &&

# There must be 2 ZSKs
echo -n "LINE: ${LINENO} " && count=`grep -c "DNSKEY[[:space:]]*256" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 2 ] &&

# There must be one signature signed with the old ZSK
echo -n "LINE: ${LINENO} " && count=`grep -c "RRSIG[[:space:]]*SOA" "$INSTALL_ROOT/var/opendnssec/signed/ods" ` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&
echo -n "LINE: ${LINENO} " && grep "RRSIG[[:space:]]*SOA" "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2"| grep -v $ZSK2 | grep $ZSK1 &&
 
echo -n "LINE: ${LINENO} " && count=`grep -c "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signed/ods" ` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&
echo -n "LINE: ${LINENO} " && grep "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2" | grep -v $ZSK2 | grep $ZSK1 &&

echo -n "LINE: ${LINENO} " && validns -t $time "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&

echo &&
echo "######### LEAP TIME TILL THE ROLLOVER IS COMPLETED ######### " &&
# The new zsk becomes active
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 5 &&

echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 5 'ods-signerd: .*\[STATS\] ods' &&

# The old signature is still valid
echo -n "LINE: ${LINENO} " && count=`grep -c "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&
echo -n "LINE: ${LINENO} " && grep "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2"| grep -v $ZSK2 | grep $ZSK1 &&

# But SOA must be signed with the new ZSK
echo -n "LINE: ${LINENO} " && count=`grep -c "RRSIG[[:space:]]*SOA" "$INSTALL_ROOT/var/opendnssec/signed/ods" ` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&
echo -n "LINE: ${LINENO} " && grep "RRSIG[[:space:]]*SOA" "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2"| grep -v $ZSK1 | grep $ZSK2 &&

echo -n "LINE: ${LINENO} " && validns -t $time "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&

echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&

echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 8 'ods-signerd: .*\[STATS\] ods' &&

echo -n "LINE: ${LINENO} " && count=`grep -c "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&

echo "time is $time" &&
echo -n "LINE: ${LINENO} " && validns -t $time "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&

echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&

echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 10 'ods-signerd: .*\[STATS\] ods' &&

echo -n "LINE: ${LINENO} " && validns -t $time "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&

echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&

echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
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

