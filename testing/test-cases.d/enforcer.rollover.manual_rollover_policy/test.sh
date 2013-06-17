#!/usr/bin/env bash
#
#TEST: Test to make sure a manual key rollover can be done
#TEST: Roll the ZSK and then the KSK and use the policy option
#TEST: We use TIMESHIFT to hurry things along

#TODO: Test the no-retire on the ds-seen command
#TODO: Test error cases/more complicated scenarios e.g.
#TODO: do a manual rollover when a scheduled one is due

#OPENDNSSEC-91: Make the keytype flag required when rolling keys

ENFORCER_WAIT=90	# Seconds we wait for enforcer to run

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

##################  SETUP ###########################
# Start enforcer (Zone already exists and we let it generate keys itself)
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*all done' &&

# Make sure TIMESHIFT worked:
syslog_grep "ods-enforcerd: .*Timeshift mode detected, running once only!" &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:00" &&

# Check that we have 2 keys for each zone
log_this ods-ksmutil-key-list1 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list1 stdout 'ods                             KSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'ods                             ZSK           active' &&
log_grep ods-ksmutil-key-list1 stdout 'ods2                            KSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'ods2                            ZSK           active' &&

# Make sure nothing happens for a non-existant policy
! log_this ods-ksmutil-key-rollover_bad ods-ksmutil key rollover --policy bob --keytype ZSK &&
log_grep ods-ksmutil-key-rollover_bad stdout "Error, can't find policy : bob" &&

# ******************* Roll the ZSK first ************************ 
echo "y" | log_this ods-ksmutil-key-rollover1 ods-ksmutil key rollover --policy default --keytype ZSK &&
syslog_waitfor 5 "ods-ksmutil: .*Manual key rollover for key type zsk on policy default initiated" &&
# *************************************************************** 

# Run the enforcer and check for a published ZSK on our policy
# and make sure the zone on the other policy hasn't rolled
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 2 'ods-enforcerd: .*all done' &&

log_this ods-ksmutil-key-list2 ods-ksmutil key list --verbose  &&
log_grep ods-ksmutil-key-list2 stdout 'ods                             KSK           publish' &&
log_grep ods-ksmutil-key-list2 stdout 'ods                             ZSK           active' &&
log_grep ods-ksmutil-key-list2 stdout 'ods                             ZSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'ods2                            KSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'ods2                            ZSK           active' &&
! log_grep ods-ksmutil-key-list2 stdout 'ods2                            ZSK           publish' &&
KSK_CKA_ID1=`log_grep -o ods-ksmutil-key-list2 stdout "ods                             KSK           publish" | awk '{print $9}'` &&
ZSK_CKA_ID1=`log_grep -o ods-ksmutil-key-list2 stdout "ods                             ZSK           active" | awk '{print $9}'` &&
ZSK_CKA_ID2=`log_grep -o ods-ksmutil-key-list2 stdout "ods                             ZSK           publish" | awk '{print $9}'` &&

syslog_grep "WARNING: ZSK rollover for zone 'ods' not completed as there are no keys in the 'ready' state;" &&

##################  STEP 1: Time = 1hrs ###########################
export ENFORCER_TIMESHIFT='01-01-2010 13:00' &&
# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 3 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 13:00" &&

# Check the published key is now active and the old key is retired
log_this ods-ksmutil-key-list3 ods-ksmutil key list --verbose &&
log_grep ods-ksmutil-key-list3 stdout "ods                             KSK           ready.*$KSK_CKA_ID1" &&
log_grep ods-ksmutil-key-list3 stdout "ods                             ZSK           retire.*$ZSK_CKA_ID1" &&
log_grep ods-ksmutil-key-list3 stdout "ods                             ZSK           active.*$ZSK_CKA_ID2" &&
syslog_grep "INFO: ZSK has been rolled for ods" && 

# Run the ds-seen on the KSK and check the output (enforcer won't HUP as it isn't running)
log_this ods-ksmutil-dsseen_ods1   ods-ksmutil key ds-seen --zone ods --cka_id $KSK_CKA_ID1 &&
log_grep ods-ksmutil-dsseen_ods1 stdout "Cannot find PID file" &&
log_grep ods-ksmutil-dsseen_ods1 stdout "Found key with CKA_ID $KSK_CKA_ID1" &&
log_grep ods-ksmutil-dsseen_ods1 stdout "Key $KSK_CKA_ID1 made active" &&

##################  STEP 2: Time = 3hrs ###########################
export ENFORCER_TIMESHIFT='01-01-2010 15:00' &&
# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 4 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 15:00" &&

# Make sure the old key is now retired
log_this ods-ksmutil-key-list4 ods-ksmutil key list --verbose &&
log_grep ods-ksmutil-key-list4 stdout "ods                             KSK           active.*$KSK_CKA_ID1" &&
log_grep ods-ksmutil-key-list4 stdout "ods                             ZSK           active.*$ZSK_CKA_ID2" &&
! log_grep ods-ksmutil-key-list4 stdout 'ods                             ZSK           retire' &&

##################  STEP 3: Time = 13hrs ###########################
export ENFORCER_TIMESHIFT='02-01-2010 01:00' &&
# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 5 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 02-01-2010 01:00" &&

# Check the next scheduled rollover starts for the ZSK
log_this ods-ksmutil-key-list5 ods-ksmutil key list --verbose &&
log_grep ods-ksmutil-key-list5 stdout "ods                             KSK           active.*$KSK_CKA_ID1" &&
log_grep ods-ksmutil-key-list5 stdout "ods                             ZSK           active.*$ZSK_CKA_ID2" &&
log_grep ods-ksmutil-key-list5 stdout 'ods                             ZSK           publish' &&
ZSK_CKA_ID3=`log_grep -o ods-ksmutil-key-list5 stdout "ods                             ZSK           publish" | awk '{print $9}'` &&

# ******************* Roll the KSK now ************************ 
echo "y" | log_this ods-ksmutil-key-rollover2 ods-ksmutil key rollover --policy default --keytype KSK &&
syslog_waitfor 5 "ods-ksmutil: .*Manual key rollover for key type ksk on policy default initiated" &&
# *************************************************************

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 6 'ods-enforcerd: .*all done' &&

# Look for a published KSK
log_this ods-ksmutil-key-list6 ods-ksmutil key list --verbose &&
log_grep ods-ksmutil-key-list6 stdout "ods                             KSK           active.*$KSK_CKA_ID1" &&
log_grep ods-ksmutil-key-list6 stdout 'ods                             KSK           publish' &&
log_grep ods-ksmutil-key-list6 stdout "ods                             ZSK           active.*$ZSK_CKA_ID2" &&
log_grep ods-ksmutil-key-list6 stdout 'ods                             ZSK           publish' &&
KSK_CKA_ID2=`log_grep -o ods-ksmutil-key-list6 stdout "ods                             KSK           publish" | awk '{print $9}'` &&

syslog_grep "WARNING: KSK rollover for zone 'ods' not completed as there are no keys in the 'ready' state;" &&

# ##################  STEP 4: Time = 14hrs ###########################
export ENFORCER_TIMESHIFT='02-01-2010 02:00' &&
# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 7 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 02-01-2010 02:00" &&

# Look for a ready KSK
log_this ods-ksmutil-key-list7 ods-ksmutil key list --verbose &&
log_grep ods-ksmutil-key-list7 stdout "ods                             KSK           active.*$KSK_CKA_ID1" &&
log_grep ods-ksmutil-key-list7 stdout "ods                             KSK           ready     waiting for ds-seen.*$KSK_CKA_ID2" &&
log_grep ods-ksmutil-key-list7 stdout "ods                             ZSK           retire.*$ZSK_CKA_ID2" &&
log_grep ods-ksmutil-key-list7 stdout "ods                             ZSK           active.*$ZSK_CKA_ID3" &&

syslog_grep "ods-enforcerd: .*Once the new DS records are seen in DNS please issue the ds-seen command for zone ods with the following cka_ids, $KSK_CKA_ID2" &&

# Run a ds-seen on this new key and check the output (enforcer won't HUP as it isn't running)
log_this ods-ksmutil-dsseen_ods2   ods-ksmutil key ds-seen --zone ods --cka_id $KSK_CKA_ID2 &&
log_grep ods-ksmutil-dsseen_ods2 stdout "Cannot find PID file" &&
log_grep ods-ksmutil-dsseen_ods2 stdout "Found key with CKA_ID $KSK_CKA_ID2" &&
log_grep ods-ksmutil-dsseen_ods2 stdout "Key $KSK_CKA_ID2 made active" &&

# Key list should reflect this
log_this ods-ksmutil-key-list8 ods-ksmutil key list --verbose &&
log_grep ods-ksmutil-key-list8 stdout "ods                             KSK           retire.*$KSK_CKA_ID1" &&
log_grep ods-ksmutil-key-list8 stdout "ods                             KSK           active.*$KSK_CKA_ID2" &&
log_grep ods-ksmutil-key-list8 stdout "ods                             ZSK           retire.*$ZSK_CKA_ID2" &&
log_grep ods-ksmutil-key-list8 stdout "ods                             ZSK           active.*$ZSK_CKA_ID3" &&

# ##################  STEP 5: Time = 15hrs ###########################
export ENFORCER_TIMESHIFT='02-01-2010 03:00' &&
# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 8 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 02-01-2010 03:00" &&

# Look for only an active KSK
log_this ods-ksmutil-key-list9 ods-ksmutil key list --verbose &&
log_grep ods-ksmutil-key-list9 stdout "ods                             KSK           active.*$KSK_CKA_ID2" &&
! log_grep ods-ksmutil-key-list9 stdout "ods                             KSK           retire" &&
! log_grep ods-ksmutil-key-list9 stdout "ods                             KSK           publish" &&
log_grep ods-ksmutil-key-list9 stdout "ods                             ZSK           retire.*$ZSK_CKA_ID2" &&
log_grep ods-ksmutil-key-list9 stdout "ods                             ZSK           active.*$ZSK_CKA_ID3" &&
! log_grep ods-ksmutil-key-list9 stdout "ods                             ZSK           publish" &&

# ********Lets roll for a policy and all key types now ************** 
echo "y" | log_this ods-ksmutil-key-rollover_all ods-ksmutil key rollover --policy default --all &&
syslog_waitfor 5 "ods-ksmutil: .*Manual key rollover for key type all on policy default initiated" &&
# ******************************************************************* 

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 9 'ods-enforcerd: .*all done' &&

# Check both keys have started rolling
log_this ods-ksmutil-key-list10 ods-ksmutil key list --verbose &&
log_grep ods-ksmutil-key-list10 stdout "ods                             KSK           active.*$KSK_CKA_ID2" &&
log_grep ods-ksmutil-key-list10 stdout "ods                             KSK           publish" &&
log_grep ods-ksmutil-key-list10 stdout "ods                             ZSK           retire.*$ZSK_CKA_ID2" &&
log_grep ods-ksmutil-key-list10 stdout "ods                             ZSK           active.*$ZSK_CKA_ID3" &&
log_grep ods-ksmutil-key-list10 stdout "ods                             ZSK           publish" &&


return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

