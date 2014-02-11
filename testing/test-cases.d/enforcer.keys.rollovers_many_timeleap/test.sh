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

ods_reset_env 20 &&

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

#### TIME 1: Keys are Published/Ready
log_this ods-enforcer-output echo "--------------- TIME LEAP 1 -----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect publish/ready" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer rollover list &&

#### TIME 2: Keys are Ready/Active -> do ds-submit and ds-seen
log_this ods-enforcer-output echo "--------------- TIME LEAP 2 -----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect ready(ds-submit)/active" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer rollover list &&

log_this ods-enforcer-output echo "----- Do key export and ds-submit" &&
log_this ods-enforcer-output 'ods-enforcer key export --zone ods1' &&
log_this ods-enforcer-output 'ods-enforcer key ds-submit --zone ods1 --force' && sleep 1 &&

log_this ods-enforcer-output echo "----- Expect ready(ds-seen)/active" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

log_this ods-enforcer-output echo "----- Do ds-seen" &&
KSK_CKA_ID1=`log_grep -o ods-enforcer-output stdout "ods1[[:space:]].*KSK[[:space:]].*ready     waiting for ds-submit" | awk '{print $9}'` &&
log_this ods-enforcer-output ods-enforcer key ds-seen --zone ods1 --cka_id $KSK_CKA_ID1 && sleep 1 &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

#### TIME 2.5: Keys are both active after DS TTL passed since ds-seen
log_this ods-enforcer-output echo "----- Wait for DS TTL to pass  " &&
log_this ods-enforcer-output echo "--------------- TIME LEAP 2.5 -----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect active/active " &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&
 

#### TIME 3: Keys are finally both active
log_this ods-enforcer-output echo "----- Next event is ZSK auto rollover " &&
log_this ods-enforcer-output echo "--------------- TIME LEAP 3 ----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect active/active/publish" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

#### TIME 4: New ZSK appears
log_this ods-enforcer-output echo "--------------- TIME LEAP 4 -----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect active/active/ready [BUG? Original ZSK should not be retired!]" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

#### TIME 5: New ZSK should be ready
log_this ods-enforcer-output echo "--------------- TIME LEAP 5 ----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect active/retire/active" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

#### TIME 6: Rollover done, back to 2 active keys?
log_this ods-enforcer-output echo "--------------- TIME LEAP 6 ----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&
log_this ods-enforcer-output echo "----- Expect active/active [BUG? I see dead keys!]" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

#### TIME 7: Next ZSK rollover starts
log_this ods-enforcer-output echo "--------------- TIME LEAP 7 ----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&
log_this ods-enforcer-output echo "----- Expect active/active/publish [I see dead keys!]" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&

#### TIME 8: Next ZSK rollover continues
log_this ods-enforcer-output echo "--------------- TIME LEAP 8 ----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&
log_this ods-enforcer-output echo "----- Expect active/active/ready [I see dead keys!]" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&

#### TIME 9: Next ZSK rollover starts
log_this ods-enforcer-output echo "--------------- TIME LEAP 9 ----------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&
log_this ods-enforcer-output echo "----- Expect active/retire/active [I see dead keys!]" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

#### Lets try to roll the KSK manually now
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

log_this ods-enforcer-output_manual echo "----- Do manual key rollover for KSK" &&
log_this ods-enforcer-output_manual ods-enforcer key rollover  --zone ods1 --keytype KSK &&
log_this ods-enforcer-output_manual echo "----- Expect a new KSK to be published? Check." &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual echo "----- BUG? The rollover list doesn't seem to know about manual roll.....!!!" &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

#### TIME 10: Expect KSK to be ready 
log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 10 ----------------" &&
log_this ods-enforcer-output_manual 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output_manual echo "--------------------------------------------" &&
log_this ods-enforcer-output_manual echo "----- Expect a new KSK to be ready? Hmm - actually all that happened was one of the ZSKs changed state in debug..." &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

#### TIME 11: Expect KSK to be ready 
log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 11 ----------------" &&
log_this ods-enforcer-output_manual 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output_manual echo "--------------------------------------------" &&
log_this ods-enforcer-output_manual echo "----- Expect a new KSK to be ready/ds-submit? Check. BUG? But as before I now have no active KSK here...." &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

log_this ods-enforcer-output_manual echo "----- Do ds-submit" &&
log_this ods-enforcer-output_manual 'ods-enforcer key ds-submit --zone ods1 --force' && sleep 1 &&

log_this ods-enforcer-output_manual echo "----- Expect KSKs to be active/ready(ds-seen)" &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

log_this ods-enforcer-output_manual echo "----- Do ds-seen" &&
KSK_CKA_ID2=`log_grep -o ods-enforcer-output_manual stdout "ods1[[:space:]].*KSK[[:space:]].*ready     waiting for ds-submit" | awk '{print $9}'` &&
log_this ods-enforcer-output_manual ods-enforcer key ds-seen --zone ods1 --cka_id $KSK_CKA_ID2 && sleep 1 &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

#### TIME 12: Expect KSK to be active 
log_this ods-enforcer-output_manual echo "----- Wait for DS TTL to pass  " &&
log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 12 ----------------" &&
log_this ods-enforcer-output_manual 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output_manual echo "--------------------------------------------" &&
log_this ods-enforcer-output_manual echo "----- Expect a new KSK to be active since DS TTL has passed?" &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

log_this ods-enforcer-output_manual echo "----- Do ds-retract" &&
log_this ods-enforcer-output_manual 'ods-enforcer key ds-retract --zone ods1 --force' && sleep 1 &&

log_this ods-enforcer-output_manual echo "----- Expect old KSK to be ??? BUG? State doesn't seem to have changed?" &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&

#### TIME 12.5: ???
log_this ods-enforcer-output_manual echo "--------------- TIME LEAP 12.5 -----------------" &&
log_this ods-enforcer-output_manual 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output_manual echo "--------------------------------------------" &&

log_this ods-enforcer-output_manual echo "----- Expect active KSK " &&
log_this ods-enforcer-output_manual ods-enforcer key list  --verbose &&
log_this ods-enforcer-output_manual ods-enforcer key list --debug &&
log_this ods-enforcer-output_manual ods-enforcer rollover list &&


ods_stop_enforcer &&
echo "**** OK" &&
# Change this line to return 1 even on succeess if you want to leave the output files around for inspection
return 0

echo  "**** FAILED"
ods_kill
return 1
