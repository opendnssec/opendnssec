#!/usr/bin/env bash

#TEST: KSK Rollover - Double-RRset Mechanism

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
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v -p --all &&
echo -n "LINE: ${LINENO} " && KSK1=`ods-enforcer key list -v -p --all | grep "KSK" | cut -d ";" -f7` && sleep 1 &&

# Leap to the time that both KSK and ZSK are used for signing
echo -n "LINE: ${LINENO} " && sleep 2 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && sleep 2 && ods-enforcer time leap && sleep 3 &&

echo -n "LINE: ${LINENO} " && ods-enforcer key ds-seen -z ods --cka_id $KSK1 && sleep 3 &&
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
echo "############## ROLL KSK: DOUBLE-RRset METHOD ############## " &&
echo -n "LINE: ${LINENO} " && ods-enforcer key rollover -z ods --keytype ksk && sleep 5 &&

# In Double-RRset mechanism, DS and DNSKEY are published in parallel
# Pub and Act must be 1 
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p --all &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v -p --all &&
echo -n "LINE: ${LINENO} " && KSK2=`ods-enforcer key list -d -p | grep "KSK" | grep "rumoured;rumoured;rumoured;NA;1;1"| cut -d ";" -f9` &&

echo &&
echo "############# CHECK SIGNATURES AFTER ROLLOVER ############# " &&
echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer update --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 3 'ods-signerd: .*\[STATS\] ods' &&

# Check that there must be two DNSKEYs and also two RRSIGs for DNSKEYs 
echo -n "LINE: ${LINENO} " && count=`grep -c "DNSKEY[[:space:]]*257" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 2 ] &&

echo -n "LINE: ${LINENO} " && count=`grep -c "IN[[:space:]]*RRSIG[[:space:]]*DNSKEY" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 2 ] &&

echo -n "LINE: ${LINENO} " && validns -t $time "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 4 &&

echo &&
echo "########## LEAP TIME TILL THE ROLLOVER IS COMPLETED ######### " &&
# New KSK is waiting for ds-seen 
ods-enforcer key ds-seen -z ods --cka_id $KSK2 && sleep 3 &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && sleep 2 && ods-enforcer time leap && sleep 3 &&

echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep "ods;KSK;omnipresent;omnipresent;omnipresent;NA;1;1;$KSK2" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep "ods;KSK;unretentive;unretentive;unretentive;NA;0;0;$KSK1" &&

echo -n "LINE: ${LINENO} " && ods-enforcer key ds-gone -z ods --cka_id $KSK1 && sleep 3 &&

echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 5 'ods-signerd: .*\[STATS\] ods' &&

echo -n "LINE: ${LINENO} " && count=`grep -c "IN[[:space:]]*RRSIG[[:space:]]*DNSKEY" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&

echo -n "LINE: ${LINENO} " && grep "RRSIG[[:space:]]*DNSKEY" "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2" | grep $KSK2 &&

echo -n "LINE: ${LINENO} " && validns -t $time "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 4 &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer sign --all && sleep 3 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 7 'ods-signerd: .*\[STATS\] ods' &&

echo -n "LINE: ${LINENO} " && validns -t $time "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 4 &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&

echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 2 && ods-signer sign --all && sleep 3 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 900 8 'ods-signerd: .*\[STATS\] ods' &&

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

