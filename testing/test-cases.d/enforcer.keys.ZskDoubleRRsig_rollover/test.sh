#!/usr/bin/env bash

#TEST: ZSK Rollover - Double RR Signature Mechanism


ods_signer_start () {
        rm -f "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2" 
        rm -f "$INSTALL_ROOT/var/opendnssec/signed/ods" 

        ods_start_signer &&
        sleep 5
}

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

# Leap to the time that both KSK and ZSK are used for signing
echo -n "LINE: ${LINENO} " && ods-enforcer time leap && sleep 1 &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap && sleep 1 &&


echo &&
echo "########### VERIFY SIGNATURES IN THE SIGNED FILE ############ " &&
echo -n "LINE: ${LINENO} " && ods_signer_start &&


echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
echo -n "LINE: ${LINENO} " && test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo -n "LINE: ${LINENO} " && count=`grep -c "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&

echo -n "LINE: ${LINENO} " && ldns-verify-zone "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 4 &&

echo &&
echo "############## ROLL ZSK: DOUBLE-RR-SIGNATURE METHOD ############## " &&
echo -n "LINE: ${LINENO} " && ods-enforcer key rollover -z ods --keytype zsk && sleep 5 &&

# in Double RRsig mechanism, RRSIG is published before DNSKEY
# also the Pub must be 0 and Act must be 1 which means although the key is not published, it is used for signing.
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep "ZSK" | grep "hidden;NA;rumoured;0;1" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v -p &&
echo -n "LINE: ${LINENO} " && ZSK2=`ods-enforcer key list -v -p | grep "ZSK" | grep "publish"| cut -d ";" -f9` &&

echo &&
echo "############# CHECK SIGNATURES AFTER ROLLOVER-1 ############# " &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods_signer_start && sleep 3 &&

# There must be one published ZSK
echo -n "LINE: ${LINENO} " && count=`grep -c "DNSKEY[[:space:]]*256" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&
echo -n "LINE: ${LINENO} " && grep "DNSKEY[[:space:]]*256" "$INSTALL_ROOT/var/opendnssec/signed/ods" | grep $ZSK1 &&

# There must be two signature for resource records except for DNSKEY
echo -n "LINE: ${LINENO} " && count=`grep -c "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " &&  [ $count -eq 2 ] &&

echo -n "LINE: ${LINENO} " && grep "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2" | grep $ZSK2 &&
echo -n "LINE: ${LINENO} " && grep "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2" | grep $ZSK1 &&

echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 4 &&

echo &&
echo "############# CHECK SIGNATURES AFTER ROLLOVER-2 ############# " &&
# The new zsk is now published and the old one is retired
echo -n "LINE: ${LINENO} " && ods-enforcer time leap && sleep 1 &&

echo -n "LINE: ${LINENO} " && ods_signer_start &&
echo -n "LINE: ${LINENO} " && count=`grep -c "DNSKEY[[:space:]]*256" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&
echo -n "LINE: ${LINENO} " && grep "DNSKEY[[:space:]]*256" "$INSTALL_ROOT/var/opendnssec/signed/ods" | grep $ZSK2 &&

echo &&
echo "############################ STOP ############################ " &&
echo -n "LINE: ${LINENO} " && ods_stop_ods-control &&
return 0

echo "#################### ERROR: CURRENT STATE ####################"
echo "DEBUG: " && ods-enforcer key list -d -p
echo "DEBUG: " && ods-enforcer key list -v
echo "DEBUG: " && ods-enforcer queue

ods_kill
return 1
