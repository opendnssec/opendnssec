#!/usr/bin/env bash
#
#TEST: Test to make sure a manual key rollover can be done
#TEST: Roll the ZSK and then the KSK and use the zone option
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
ods_start_enforcer_timeshift &&

# Make sure TIMESHIFT worked:
syslog_grep "ods-enforcerd: .*Timeshift mode detected, running once only!" &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:00" &&

# Check that we have 2 keys per zone
log_this ods-ksmutil-key-list1 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list1 stdout 'ods                             KSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'ods                             ZSK           active' &&
log_grep ods-ksmutil-key-list1 stdout 'ods2                            KSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'ods2                            ZSK           active' &&
log_grep ods-ksmutil-key-list1 stdout 'ods3                            KSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'ods3                            ZSK           active' &&

#OPENDNSSEC-91. Make sure either a keytype or the all option are required
! log_this ods-ksmutil-key-rollover_bad1 ods-ksmutil key rollover --zone ods &&
log_grep ods-ksmutil-key-rollover_bad1 stdout 'Please specify either a keytype, KSK or ZSK, with the --keytype <type> option or use the --all option' &&

# Make sure nothing happens for a non-existant zone
! log_this ods-ksmutil-key-rollover_bad2 ods-ksmutil key rollover --zone bob --keytype ZSK &&
log_grep ods-ksmutil-key-rollover_bad2 stdout "Error, can't find zone : bob" &&

# ******************* Roll the ZSK first ************************ 
log_this ods-ksmutil-key-rollover1 ods-ksmutil key rollover --zone ods --keytype ZSK &&
syslog_waitfor 5 "ods-ksmutil: .*Manual key rollover for key type zsk on zone ods initiated" &&
# *************************************************************** 

# Run the enforcer and check for a published ZSK for our zone
# and check nothing happens to the other zone
ods_start_enforcer_timeshift &&

log_this ods-ksmutil-key-list2 ods-ksmutil key list --verbose  &&
log_grep ods-ksmutil-key-list2 stdout 'ods                             KSK           publish' &&
log_grep ods-ksmutil-key-list2 stdout 'ods                             ZSK           active' &&
log_grep ods-ksmutil-key-list2 stdout 'ods                             ZSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'ods2                            KSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'ods2                            ZSK           active' &&
! log_grep ods-ksmutil-key-list2 stdout 'ods2                            ZSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'ods3                            KSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'ods3                            ZSK           active' &&
! log_grep ods-ksmutil-key-list2 stdout 'ods3                            ZSK           publish' &&
KSK_CKA_ID1=`log_grep -o ods-ksmutil-key-list2 stdout "ods                             KSK           publish" | awk '{print $9}'` &&
ZSK_CKA_ID1=`log_grep -o ods-ksmutil-key-list2 stdout "ods                             ZSK           active" | awk '{print $9}'` &&
ZSK_CKA_ID2=`log_grep -o ods-ksmutil-key-list2 stdout "ods                             ZSK           publish" | awk '{print $9}'` &&

syslog_grep "WARNING: ZSK rollover for zone 'ods' not completed as there are no keys in the 'ready' state;" &&

##################  STEP 1: Time = 1hrs ###########################
export ENFORCER_TIMESHIFT='01-01-2010 13:00' &&
# Run the enforcer
ods_start_enforcer_timeshift &&
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
ods_start_enforcer_timeshift &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 15:00" &&

# Make sure the old key is now retired
log_this ods-ksmutil-key-list4 ods-ksmutil key list --verbose &&
log_grep ods-ksmutil-key-list4 stdout "ods                             KSK           active.*$KSK_CKA_ID1" &&
log_grep ods-ksmutil-key-list4 stdout "ods                             ZSK           active.*$ZSK_CKA_ID2" &&
! log_grep ods-ksmutil-key-list4 stdout 'ods                             ZSK           retire' &&

##################  STEP 3: Time = 13hrs ###########################
export ENFORCER_TIMESHIFT='02-01-2010 01:00' &&
# Run the enforcer
ods_start_enforcer_timeshift &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 02-01-2010 01:00" &&

# Check the next scheduled rollover starts for the ZSK
log_this ods-ksmutil-key-list5 ods-ksmutil key list --verbose &&
log_grep ods-ksmutil-key-list5 stdout "ods                             KSK           active.*$KSK_CKA_ID1" &&
log_grep ods-ksmutil-key-list5 stdout "ods                             ZSK           active.*$ZSK_CKA_ID2" &&
log_grep ods-ksmutil-key-list5 stdout 'ods                             ZSK           publish' &&
ZSK_CKA_ID3=`log_grep -o ods-ksmutil-key-list5 stdout "ods                             ZSK           publish" | awk '{print $9}'` &&

# ******************* Roll the KSK now ************************ 
log_this ods-ksmutil-key-rollover2 ods-ksmutil key rollover --zone ods --keytype KSK &&
syslog_waitfor 5 "ods-ksmutil: .*Manual key rollover for key type ksk on zone ods initiated" &&
# *************************************************************

# Run the enforcer
ods_start_enforcer_timeshift &&

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
ods_start_enforcer_timeshift &&
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
ods_start_enforcer_timeshift &&
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
log_this ods-ksmutil-key-rollover_all ods-ksmutil key rollover --zone ods --all &&
#echo "y" | log_this ods-ksmutil-key-rollover_all ods-ksmutil key rollover --policy default --all &&
syslog_waitfor 5 "ods-ksmutil: .*Manual key rollover for key type all on zone ods initiated" &&
# ******************************************************************* 

# Run the enforcer
ods_start_enforcer_timeshift &&

# Check both keys have started rolling
log_this ods-ksmutil-key-list10 ods-ksmutil key list --verbose &&
log_grep ods-ksmutil-key-list10 stdout "ods                             KSK           active.*$KSK_CKA_ID2" &&
log_grep ods-ksmutil-key-list10 stdout "ods                             KSK           publish" &&
log_grep ods-ksmutil-key-list10 stdout "ods                             ZSK           retire.*$ZSK_CKA_ID2" &&
log_grep ods-ksmutil-key-list10 stdout "ods                             ZSK           active.*$ZSK_CKA_ID3" &&
log_grep ods-ksmutil-key-list10 stdout "ods                             ZSK           publish" &&
log_grep ods-ksmutil-key-list10 stdout 'ods2                            KSK           ready' &&
log_grep ods-ksmutil-key-list10 stdout 'ods2                            ZSK           active' &&
log_grep ods-ksmutil-key-list10 stdout 'ods3                            KSK           ready' &&
log_grep ods-ksmutil-key-list10 stdout 'ods3                            ZSK           active' &&

# ******************* Now roll a zone which shares keys ************************ 
echo "y" | log_this ods-ksmutil-key-rollover3 ods-ksmutil key rollover --zone ods2 --keytype ZSK &&
log_grep ods-ksmutil-key-rollover3 stdout "This zone shares keys with others, all instances of the active key on this zone will be retired; are you sure?" &&
syslog_waitfor 5 "ods-ksmutil: .*Manual key rollover for key type zsk on zone ods2 initiated" &&
# ***************************************************************

# Run the enforcer
ods_start_enforcer_timeshift &&

# Check both keys have started rolling on ods2
log_this ods-ksmutil-key-list11 ods-ksmutil key list --verbose &&
log_grep ods-ksmutil-key-list11 stdout "ods                             KSK           active.*$KSK_CKA_ID2" &&
log_grep ods-ksmutil-key-list11 stdout "ods                             KSK           publish" &&
log_grep ods-ksmutil-key-list11 stdout "ods                             ZSK           retire.*$ZSK_CKA_ID2" &&
log_grep ods-ksmutil-key-list11 stdout "ods                             ZSK           active.*$ZSK_CKA_ID3" &&
log_grep ods-ksmutil-key-list11 stdout "ods                             ZSK           publish" &&
log_grep ods-ksmutil-key-list11 stdout 'ods2                            KSK           ready' &&
log_grep ods-ksmutil-key-list11 stdout 'ods2                            ZSK           active' &&
log_grep ods-ksmutil-key-list11 stdout 'ods2                            ZSK           publish' &&
log_grep ods-ksmutil-key-list11 stdout 'ods3                            KSK           ready' &&
log_grep ods-ksmutil-key-list11 stdout 'ods3                            ZSK           active' &&
log_grep ods-ksmutil-key-list11 stdout 'ods3                            ZSK           publish' &&

return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

