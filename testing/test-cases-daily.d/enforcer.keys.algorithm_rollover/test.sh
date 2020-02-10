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
echo -n "LINE: ${LINENO} " && KSK1=`ods-enforcer key list -v -p --all | grep "KSK" | cut -d ";" -f7` &&


# Leap to the time that both KSK and ZSK are used for signing
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer key ds-seen -z ods --cka_id $KSK1 && sleep 3 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&

echo &&
echo "########### VERIFY SIGNATURES IN THE SIGNED FILE ############ " &&
echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&

echo -n "LINE: ${LINENO} " && syslog_waitfor 900 'ods-signerd: .*\[STATS\] ods 1001' &&
echo -n "LINE: ${LINENO} " && test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo -n "LINE: ${LINENO} " && count=`grep -c "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 1 ] &&

echo -n "LINE: ${LINENO} " && ldns-verify-zone -t `date --date=@$time '+%Y%m%d%H%M%S'` "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&

echo &&
echo "#################### CHANGE ALGORITHM ################## " &&
echo -n "LINE: ${LINENO} " && cp kasp2.xml "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
echo -n "LINE: ${LINENO} " && ods-enforcer policy import && sleep 5 &&
# Now the new keys with new algorithm must be introduced
ods-enforcer key list -v &&
echo -n "LINE: ${LINENO} " && ZSK2=`ods-enforcer key list -v -p | grep "ZSK" | grep "ready" | cut -d ";" -f7` &&
echo -n "LINE: ${LINENO} " && KSK2=`ods-enforcer key list -v -p --all | grep "KSK" | grep "publish" | cut -d ";" -f7` &&

echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p --all &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v -p --all | grep "$ZSK1" | grep "1024;7;" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v -p --all | grep "$ZSK2" | grep "1024;8;" &&

echo &&
echo "######### CHECK SIGNATURES AFTER ALGORITHM ROLLOVER ######### " &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 5 &&  
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 3 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 900 'ods-signerd: .*\[STATS\] ods 1003' &&

# Both ZSK keys are used for signing but the new key is still not published
echo -n "LINE: ${LINENO} " && count=`grep -c "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 2 ] &&
echo -n "LINE: ${LINENO} " && grep "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2" | grep $ZSK2 &&
echo -n "LINE: ${LINENO} " && grep "RRSIG[[:space:]]*MX" "$INSTALL_ROOT/var/opendnssec/signer/ods.backup2" | grep $ZSK1 &&

echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&

echo &&
echo "######### LEAP TIME TILL THE ROLLOVER IS COMPLETED ######### " &&
# After time leap the new KSK is used for signing
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 5 &&

echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&
echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 900 'ods-signerd: .*\[STATS\] ods 1005' &&

# Check RRSIGs of DNSKEYs, we must see two signatures signed by old and new algorithms
echo -n "LINE: ${LINENO} " && count=`grep -c "IN[[:space:]]*RRSIG[[:space:]]*DNSKEY" "$INSTALL_ROOT/var/opendnssec/signed/ods"` &&
echo -n "LINE: ${LINENO} " && [ $count -eq 2 ] &&
echo -n "LINE: ${LINENO} " &&  grep "IN[[:space:]]*RRSIG[[:space:]]*DNSKEY 8" "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " &&  grep "IN[[:space:]]*RRSIG[[:space:]]*DNSKEY 7" "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo -n "LINE: ${LINENO} " && ldns-verify-zone -t `date --date=@$time '+%Y%m%d%H%M%S'` "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&

echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&

echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 900 'ods-signerd: .*\[STATS\] ods 1007' &&

echo -n "LINE: ${LINENO} " && ldns-verify-zone -t `date --date=@$time '+%Y%m%d%H%M%S'` "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&

# Now we are sure the new DS is published everywhere
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer key ds-seen -z ods --cka_id $KSK2 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer key ds-gone -z ods --cka_id $KSK1 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p --all | grep "$KSK2" | grep "omnipresent;omnipresent;omnipresent;NA" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p --all | grep "$KSK1" | grep "hidden;unretentive;unretentive;NA" &&

echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 900 'ods-signerd: .*\[STATS\] ods 1009' &&

echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&

# Time to start retracting old keys and signature gradually
# Note: The old ZSK cannot be withdrawn before the KSK  
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p --all | grep "$KSK1" | grep "hidden;hidden;hidden;NA" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p --all | grep "$ZSK1" | grep "NA;hidden;NA;unretentive" &&

echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 900 'ods-signerd: .*\[STATS\] ods 1011' &&

echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&

# The old KSK must be removed after time leap
echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p --all | grep -v "$KSK1" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p --all | grep "$ZSK1" | grep "NA;hidden;NA;unretentive" &&

echo -n "LINE: ${LINENO} " && time=`ods-enforcer queue | grep "It is now" | cut -d "(" -f2 | cut -d " " -f1` &&

echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 900 'ods-signerd: .*\[STATS\] ods 1012' &&

echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&

echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p --all | grep "$ZSK1" | grep "NA;hidden;NA;hidden" &&

echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 900 'ods-signerd: .*\[STATS\] ods 1014' &&

echo -n "LINE: ${LINENO} " && ods_stop_signer && sleep 5 &&


echo -n "LINE: ${LINENO} " && sleep 3 && ods-enforcer time leap && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p --all | grep -v "$ZSK1" &&

echo -n "LINE: ${LINENO} " && ods-signerd --set-time $time && sleep 10 && ods-signer queue &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer update --all && sleep 10 &&
echo -n "LINE: ${LINENO} " && sleep 3 && ods-signer sign --all && sleep 5 &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 900 'ods-signerd: .*\[STATS\] ods 1015' &&


echo &&
echo "############################ STOP ############################ " &&
echo -n "LINE: ${LINENO} " && ods_stop_ods-control &&
return 0

echo "#################### ERROR: CURRENT STATE ####################"
echo "DEBUG: " && ods-enforcer key list -d --all
echo "DEBUG: " && ods-enforcer key list -v --all
echo "DEBUG: " && ods-enforcer queue
 
ods_kill
return 1

