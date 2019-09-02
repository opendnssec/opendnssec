#!/usr/bin/env bash

#TEST: ZSK Rollover - Double RR Signature Mechanism


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
echo -n "LINE: ${LINENO} " && ZSK1=`ods-enforcer key list -v -p | grep "ZSK" | cut -d ";" -f9` &&
echo -n "LINE: ${LINENO} " && KSK1=`ods-enforcer key list -v -p | grep "KSK" | cut -d ";" -f9` &&

# Leap to the time that both KSK and ZSK are used for signing
echo -n "LINE: ${LINENO} " && sleep 3 && ods_enforcer_leap_to 90000 && sleep 3 &&

echo -n "LINE: ${LINENO} " && ods-enforcer key ds-submit -z ods --keytag $KSK1 && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-seen -z ods --keytag $KSK1 && sleep 3 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&

echo &&
echo "########### VERIFY SIGNATURES IN THE SIGNED FILE ############ " &&
echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signer start && sleep 10 && ods-signer time leap `date --date=@$time +%Y-%m-%d-%H:%M:%S` && ods-signer clear ods &&
echo -n "LINE: ${LINENO} " && verifydate=`date --date=@$time +%Y%m%d%H%M%S` &&

echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 2 'ods-signerd: .*\[STATS\] ods' &&
echo -n "LINE: ${LINENO} " && test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo -n "LINE: ${LINENO} " && count=`grep -c "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&

echo -n "LINE: ${LINENO} " && ldns-verify-zone -t $verifydate "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo &&
echo "############## ROLL ZSK: DOUBLE-RR-SIGNATURE METHOD ############## " &&
echo -n "LINE: ${LINENO} " && ods-enforcer key rollover -z ods --keytype zsk && sleep 5 &&

# in Double RRsig mechanism, RRSIG is published before DNSKEY
# Pub must be 0 and Act must be 1 which means although the key is not published, it is used for signing.
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep "ZSK" | grep "hidden;NA;rumoured;0;1" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v -p &&
echo -n "LINE: ${LINENO} " && ZSK2=`ods-enforcer key list -v -p | grep "ZSK" | grep "publish"| cut -d ";" -f9` &&

echo &&
echo "############# CHECK SIGNATURES AFTER ROLLOVER ############# " &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 3 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer clear ods && sleep 3 && 
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 4 'ods-signerd: .*\[STATS\] ods' &&

# There must be one published ZSK
echo -n "LINE: ${LINENO} " && count=`grep -c "DNSKEY[[:space:]]*256" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&
echo -n "LINE: ${LINENO} " && grep "DNSKEY[[:space:]]*256" "$INSTALL_ROOT/var/opendnssec/signed/ods" | grep $ZSK1 &&

# There must be two signature for resource records except for DNSKEY
echo -n "LINE: ${LINENO} " && count=`grep -c "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " &&  [ $count -eq 2 ] &&

echo -n "LINE: ${LINENO} " && grep "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2" | grep $ZSK2 &&
echo -n "LINE: ${LINENO} " && grep "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2" | grep $ZSK1 &&

# unable to verify zone because ldns-verify-zone rejects zones with more signatures than strictly needed.
# echo -n "LINE: ${LINENO} " && ldns-verify-zone -t $verifydate "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo &&
echo "########## LEAP TIME TILL THE ROLLOVER IS COMPLETED ######### " &&
# After the rollover the new ZSK will be published
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 5 &&

echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signer time leap `date --date=@$time +%Y-%m-%d-%H:%M:%S` && ods-signer queue &&
echo -n "LINE: ${LINENO} " && verifydate=`date --date=@$time +%Y%m%d%H%M%S` &&

echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 6 'ods-signerd: .*\[STATS\] ods' &&

echo -n "LINE: ${LINENO} " && count=`grep -c "DNSKEY[[:space:]]*256" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&
echo -n "LINE: ${LINENO} " && grep "DNSKEY[[:space:]]*256" "$INSTALL_ROOT/var/opendnssec/signed/ods" | grep $ZSK2 &&

# echo -n "LINE: ${LINENO} " && ldns-verify-zone -t $verifydate "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 5 &&
echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signer time leap `date --date=@$time +%Y-%m-%d-%H:%M:%S` && ods-signer queue &&
echo -n "LINE: ${LINENO} " && verifydate=`date --date=@$time +%Y%m%d%H%M%S` &&

echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 8 'ods-signerd: .*\[STATS\] ods' &&

echo -n "LINE: ${LINENO} " && ldns-verify-zone -t $verifydate "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 5 &&
echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signer time leap `date --date=@$time +%Y-%m-%d-%H:%M:%S` && ods-signer queue &&
echo -n "LINE: ${LINENO} " && verifydate=`date --date=@$time +%Y%m%d%H%M%S` &&

echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 10 'ods-signerd: .*\[STATS\] ods' &&

echo -n "LINE: ${LINENO} " && ldns-verify-zone -t $verifydate "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 5 &&
echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signer time leap `date --date=@$time +%Y-%m-%d-%H:%M:%S` && ods-signer queue &&
echo -n "LINE: ${LINENO} " && verifydate=`date --date=@$time +%Y%m%d%H%M%S` &&

echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 11 'ods-signerd: .*\[STATS\] ods' &&

echo -n "LINE: ${LINENO} " && ldns-verify-zone -t $verifydate "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

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

