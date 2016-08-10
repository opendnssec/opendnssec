#!/usr/bin/env bash

#TEST: KSK Rollover - Double Signature Mechanism


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
echo -n "LINE: ${LINENO} " && ods_start_enforcer && sleep 4 &&

echo -n "LINE: ${LINENO} " && ods-enforcer key list -v -p --all &&
echo -n "LINE: ${LINENO} " && KSK1=`ods-enforcer key list -v -p --all | grep "KSK" | cut -d ";" -f7` &&

# Leap to the time that both KSK and ZSK are used for signing
echo -n "LINE: ${LINENO} " && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap && sleep 3 &&

echo -n "LINE: ${LINENO} " && ods-enforcer key ds-seen -z ods --cka_id $KSK1 && sleep 5 &&

echo -n "LINE: ${LINENO} " && ods-enforcer time leap && sleep 3 &&

# KSK must be active now
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v -p | grep KSK | grep active &&

echo &&
echo "########### VERIFY SIGNATURES IN THE SIGNED FILE ############ " &&
echo -n "LINE: ${LINENO} " && ods_signer_start &&

echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
echo -n "LINE: ${LINENO} " && test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo -n "LINE: ${LINENO} " && ldns-verify-zone "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 4 &&

echo &&
echo "############## ROLL KSK: DOUBLE-SIGNATURE METHOD ############## " &&
echo -n "LINE: ${LINENO} " && ods-enforcer key rollover -z ods --keytype ksk && sleep 5 &&

# in Double Signature mechanism, DNSKEY is published before publishing the DS
# Pub and Act are 1 which means the key is published and also used for signing.
echo -n "LINE: ${LINENO} " && KSK2=`ods-enforcer key list -d -p | grep "KSK" | grep "hidden;rumoured;rumoured;NA;1;1"| cut -d ";" -f9` &&

echo &&
echo "############# CHECK SIGNATURES AFTER ROLLOVER-1 ############# " &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods_signer_start && sleep 3 &&

# There must be two DNSKEY and also two RRSIGs for DNSKEY 
echo -n "LINE: ${LINENO} " && count=`grep -c "DNSKEY[[:space:]]*257" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 2 ] &&

echo -n "LINE: ${LINENO} " && count=`grep -c "IN[[:space:]]*RRSIG[[:space:]]*DNSKEY" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 2 ] &&

echo -n "LINE: ${LINENO} " && ldns-verify-zone "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 10 &&

echo &&
echo "############# CHECK SIGNATURES AFTER ROLLOVER-2 ############# " &&
# New KSK becomes ready
echo -n "LINE: ${LINENO} " && ods-enforcer time leap && sleep 1 &&

echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep "ods;KSK;rumoured;omnipresent;omnipresent;NA;1;1;$KSK2" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep "ods;KSK;unretentive;omnipresent;omnipresent;NA;1;1;$KSK1" &&

echo -n "LINE: ${LINENO} " && ods_signer_start && sleep 5 &&
echo -n "LINE: ${LINENO} " && count=`grep -c "IN[[:space:]]*RRSIG[[:space:]]*DNSKEY" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 2 ] &&

echo -n "LINE: ${LINENO} " && grep "RRSIG[[:space:]]*DNSKEY" "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2" | grep $KSK2 &&
echo -n "LINE: ${LINENO} " && grep "RRSIG[[:space:]]*DNSKEY" "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2" | grep $KSK1 &&

echo -n "LINE: ${LINENO} " && ldns-verify-zone "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_ods-control &&
return 0

echo "#################### ERROR: CURRENT STATE ####################"
echo "DEBUG: " && ods-enforcer key list -d -p
echo "DEBUG: " && ods-enforcer key list -v
echo "DEBUG: " && ods-enforcer queue

ods_kill
return 1
