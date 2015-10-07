#!/usr/bin/env bash
#
#TEST: Test to track key rollovers in real time from the enforcer side only. 
#TEST: Configured with short key lifetimes and 1 min enforcer interval.
#TEST: unlike parent test this uses TIMESHIFT to hopefully keep things deterministic
#TEST: Checks the output of ods-enforcer key list and the signconf.xml contents
#TEST: Takes about 10 mins and follows several KSK and ZKK rollovers.

#TODO: - increase number of steps?
#TODO: - check more logging in syslog


###################################################################
#
# This test is a work in progress to be used for investigating issues
# with the key rollovers at the moment!
# Use hacky sleeps of 1 second at the moment 
#
###################################################################

ENFORCER_WAIT=90	# Seconds we wait for enforcer to run

cp_signconfs_at_timestep_Y () {

	for zone in 1 2; do
        # Used only to create a gold while setting up the test
        #cp $INSTALL_ROOT/var/opendnssec/signconf/ods$zone.xml gold/ods_signconf_ods"$zone"_"$1".xml        
        cp $INSTALL_ROOT/var/opendnssec/signconf/ods$zone.xml base/ods_signconf_ods"$zone"_"$1".xml 		
	done	

}

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

# rm -rf base &&
# mkdir  base &&

# Used only to create a gold while setting up the test
#rm -rf gold && mkdir gold &&

##################  SETUP TIME 0 ###########################
log_this ods-enforcer-output date &&
ods_start_enforcer &&
log_this ods-enforcer-output echo "------- Expect generate/publish" &&
log_this ods-enforcer-output ods-enforcer key list --verbose &&
log_this ods-enforcer-output ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list --verbose &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*generate" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*publish" &&

KSK1_CKA=`log_grep -o ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*generate" | awk '{print $8}'` &&

ZSK1_CKA=`log_grep -o ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*publish" | awk '{print $8}'` &&

rm -f _log.$BUILD_TAG.ods-enforcer-temp.stdout &&
#### TIME 1: Keys are Published/Ready
log_this ods-enforcer-output echo "--------------- TIME LEAP 1 -----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect publish/ready" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*publish.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*ready.*$ZSK1_CKA" &&
rm -f _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

#### TIME 2: Keys are Ready/Active -> do ds-seen
log_this ods-enforcer-output echo "--------------- TIME LEAP 2 -----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

#log_this ods-enforcer-output echo "----- Expect ready(ds-submit)/active" &&
#log_this ods-enforcer-output ods-enforcer key list  --verbose &&
#log_this ods-enforcer-output ods-enforcer rollover list &&

#log_this ods-enforcer-output echo "----- Do key export and ds-submit" &&
#log_this ods-enforcer-output 'ods-enforcer key export --zone ods1' &&
#log_this ods-enforcer-output 'ods-enforcer key ds-submit --zone ods1 --force' && sleep 1 &&

log_this ods-enforcer-output echo "----- Expect ready(ds-seen)/active" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*ready.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK1_CKA" &&
rm -f _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


log_this ods-enforcer-output echo "----- Do ds-seen" &&
sleep 5 && log_this ods-enforcer-output ods-enforcer key ds-seen --zone ods1 --cka_id $KSK1_CKA && sleep 1 &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

#### TIME 2.5: Keys are both active after DS TTL passed since ds-seen
log_this ods-enforcer-output echo "----- Wait for DS TTL to pass  " &&
log_this ods-enforcer-output echo "--------------- TIME LEAP 2.5 -----------------" &&
#log_this ods-enforcer-output 'ods-enforcer time leap' && 
sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect active/active " &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK1_CKA" &&
rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


#### TIME 3: Keys are finally both active
log_this ods-enforcer-output echo "----- Next event is ZSK auto rollover " &&
log_this ods-enforcer-output echo "--------------- TIME LEAP 3 ----------------" &&
sleep 5 && log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

ods_timeleap_search_key "ods1" "ZSK" "publish" &&
log_this ods-enforcer-output echo "----- Expect active/active/publish" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*publish" &&

ZSK2_CKA=`log_grep -o ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*publish" | awk '{print $8}'` &&

rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


#### TIME 4: New ZSK appears
log_this ods-enforcer-output echo "--------------- TIME LEAP 4 -----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect active/retire/ready " &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*retire.*$ZSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*ready.*$ZSK2_CKA" &&
rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

#### TIME 5: New ZSK should be ready
log_this ods-enforcer-output echo "--------------- TIME LEAP 5 ----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect active/retire (DNSKEY: unretentive, RRSIG: hidden)/active" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
log_this ods-enforcer-temp ods-enforcer key list --debug &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*retire.*$ZSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK.*unretentive.*hidden.*$ZSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK2_CKA" &&
rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

#### TIME 6: Rollover done
log_this ods-enforcer-output echo "--------------- TIME LEAP 6 ----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&
log_this ods-enforcer-output echo "----- Expect active/retire (DNSKEY: hidden, RRSIG: hidden)/active " &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
log_this ods-enforcer-temp ods-enforcer key list --debug &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*retire.*$ZSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK.*hidden.*hidden.*$ZSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK2_CKA" &&
rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


#### TIME 7: Active Keys
log_this ods-enforcer-output echo "--------------- TIME LEAP 7 ----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&
log_this ods-enforcer-output echo "----- Expect active/active" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&

log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
! log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*retire.*$ZSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK2_CKA" &&
rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


#### TIME 8: Next ZSK rollover starts
log_this ods-enforcer-output echo "--------------- TIME LEAP 8 ----------------" &&
sleep 5 && log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&
ods_timeleap_search_key "ods1" "ZSK" "publish" &&
log_this ods-enforcer-output echo "----- Expect active/active/publish " &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&

log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK2_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*publish" &&

ZSK3_CKA=`log_grep -o ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*publish" | awk '{print $8}'` &&
rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


#### TIME 9: Next ZSK rollover continues
log_this ods-enforcer-output echo "--------------- TIME LEAP 9 ----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&
log_this ods-enforcer-output echo "----- Expect active/retire/ready " &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&

log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*retire.*$ZSK2_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*ready.*$ZSK3_CKA" &&
rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


#### TIME 10: Next ZSK rollover starts
log_this ods-enforcer-output echo "--------------- TIME LEAP 10 ----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&
log_this ods-enforcer-output echo "----- Expect active/retire/active " &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*retire.*$ZSK2_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*ZSK[[:space:]]*active.*$ZSK3_CKA" &&
rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

#### Lets try to roll the KSK manually now
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

log_this ods-enforcer-output_manual echo "----- Do manual key rollover for KSK" &&
log_this ods-enforcer-output_manual ods-enforcer key rollover  --zone ods1 --keytype KSK && sleep 1 &&
log_this ods-enforcer-output_manual echo "----- Expect a new KSK to be published" &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual echo "----- The rollover list for manual roll.....!!!" &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*publish" &&

KSK2_CKA=`log_grep -o ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*publish" | awk '{print $8}'` &&

rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

#### TIME 11: Expect KSK to be ready 
log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 11 ----------------" &&
log_this ods-enforcer-output_manual 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output_manual echo "--------------------------------------------" &&
log_this ods-enforcer-output_manual echo "----- Expect a new KSK to be ready ..." &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*retire.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*ready.*$KSK2_CKA" &&
rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


log_this ods-enforcer-output_manual echo "----- Do ds-seen" &&
sleep 5 && log_this ods-enforcer-output_manual ods-enforcer key ds-seen --zone ods1 --cka_id $KSK2_CKA && sleep 1 &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

#### TIME 11.5: Expect KSK to be active 
log_this ods-enforcer-output_manual echo "----- Wait for DS TTL to pass  " &&
log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 11.5 ----------------" &&
#log_this ods-enforcer-output_manual 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output_manual echo "--------------------------------------------" &&
log_this ods-enforcer-output_manual echo "----- Expect a new KSK to be active since DS TTL has passed?" &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list  --verbose &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*retire.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*active.*$KSK2_CKA" &&
rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

log_this ods-enforcer-output_manual echo "----- Do ds-retract" &&
log_this ods-enforcer-output_manual ods-enforcer key ds-gone --zone ods1 --cka_id $KSK1_CKA && sleep 1 &&


#### TIME 12
log_this ods-enforcer-output_manual echo "----- Wait for DS TTL to pass  " &&
log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 12 -----------------" &&
log_this ods-enforcer-output_manual 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output_manual echo "--------------------------------------------" &&

log_this ods-enforcer-output_manual echo "----- Expect hidden DS for old KSK " &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list  --debug &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*hidden[[:space:]]*unretentive[[:space:]]*unretentive.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*omnipresent.*$KSK2_CKA" &&
rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&

#### TIME 13: hidden DNSKEY and RRSIGDNSKEY
log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 13 -----------------" &&
log_this ods-enforcer-output_manual 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output_manual echo "--------------------------------------------" &&

log_this ods-enforcer-output_manual echo "----- Expect hidden DNSKEY and RRSIGDNSKEY" &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list  --debug &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*hidden[[:space:]]*hidden[[:space:]]*hidden.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*omnipresent.*$KSK2_CKA" &&
rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&


#### TIME 14: old KSK has been removed
log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 14 -----------------" &&
log_this ods-enforcer-output_manual 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output_manual echo "--------------------------------------------" &&

log_this ods-enforcer-output_manual echo "----- Expect old KSK has been removed from the list " &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

log_this ods-enforcer-temp ods-enforcer key list  --debug &&
! log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK.*$KSK1_CKA" &&
log_grep ods-enforcer-temp stdout "ods1[[:space:]]*KSK[[:space:]]*omnipresent[[:space:]]*omnipresent[[:space:]]*omnipresent.*$KSK2_CKA" &&
rm _log.$BUILD_TAG.ods-enforcer-temp.stdout &&



ods_stop_enforcer &&
echo "**** OK" &&
# Change this line to return 1 even on succeess if you want to leave the output files around for inspection
return 0

echo  "**** FAILED"
ods_kill
return 1
