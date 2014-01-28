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
log_this ods-enforcer-output echo "----- Expect generate/publish" &&
log_this ods-enforcer-output ods-enforcer key list --verbose &&
log_this ods-enforcer-output ods-enforcer rollover list &&

#### TIME 1: Keys are Published/Ready
log_this ods-enforcer-output echo "--------------------------------------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect publish/ready" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer rollover list &&

#### TIME 2: Keys are Ready/Active -> do ds-submit and ds-seen
log_this ods-enforcer-output echo "--------------------------------------------" &&
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

log_this ods-enforcer-output echo "----- Expect active/active [Doesn't happen]" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&
 
log_this ods-enforcer-output echo "----- Sleep then enforce, Expect active/active [Still doesn't happen]" &&
sleep 2 && log_this ods-enforcer-output ods-enforcer enforce && sleep 2 &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

#### TIME 3: Keys are finally both active
log_this ods-enforcer-output echo "--------------------------------------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect active/active" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

#### TIME 4: New KSK appears
log_this ods-enforcer-output echo "--------------------------------------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect active/active/publish" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

#### TIME 5: New KSK should be ready
log_this ods-enforcer-output echo "--------------------------------------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect active/active/publish [Oops - active ZSK is now retired....]" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&


#### Lets try to roll the KSK manually now
log_this ods-enforcer-output echo "----- Do manual key rollover for KSK" &&
log_this ods-enforcer-output ods-enforcer key rollover  --zone ods1 --keytype KSK &&

log_this ods-enforcer-output echo "----- Expect a new KSK to be published?" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&

#### TIME 6: 
log_this ods-enforcer-output echo "--------------------------------------------" &&
log_this ods-enforcer-output 'ods-enforcer time leap' && sleep 1 &&
log_this ods-enforcer-output echo "--------------------------------------------" &&

log_this ods-enforcer-output echo "----- Expect a new KSK to be published?" &&
log_this ods-enforcer-output ods-enforcer key list  --verbose &&
log_this ods-enforcer-output ods-enforcer key list --debug &&
log_this ods-enforcer-output ods-enforcer rollover list &&


ods_stop_enforcer &&
echo "**** OK" &&
# Change this line to return 1 even on succeess if you want to leave the output files around for inspection
return 0

echo  "**** FAILED"
ods_kill
return 1
