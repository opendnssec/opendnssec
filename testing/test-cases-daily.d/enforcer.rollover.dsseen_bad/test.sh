#!/usr/bin/env bash
#
#TEST: Test to see that the DSSEEN command is dealt with as expected
#TEST: We use TIMESHIFT to get to the point where the KSK moves to the ready state

ENFORCER_WAIT=90	# Seconds we wait for enforcer to run
ENFORCER_COUNT=2	# How many log lines we expect to see

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

# Check that we have 2 keys
log_this ods-ksmutil-key-list0_1 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list0_1 stdout 'ods                             KSK           publish' &&
log_grep ods-ksmutil-key-list0_1 stdout 'ods                             ZSK           active' &&
! log_grep ods-ksmutil-key-list0_1 stdout 'ods                             KSK           active' &&

# Grab the CKA_ID of the KSK
log_this ods-ksmutil-cka_id ods-ksmutil key list --all --verbose &&
KSK_CKA_ID=`log_grep -o ods-ksmutil-cka_id stdout "ods                             KSK           publish" | awk '{print $9}'` &&

## TEST 1 -- run the ds-seen command now and expect to be told off
! log_this ods-ksmutil-dsseen_ods1   ods-ksmutil key ds-seen --zone ods --cka_id $KSK_CKA_ID &&
log_grep ods-ksmutil-dsseen_ods1 stdout "No keys in the READY state matched your parameters, please check the parameters" &&

# Check that the KSK didn't move
log_this ods-ksmutil-key-list0_2 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list0_2 stdout 'ods                             KSK           publish' &&
log_grep ods-ksmutil-key-list0_2 stdout 'ods                             ZSK           active' &&
! log_grep ods-ksmutil-key-list0_2 stdout 'ods                             KSK           active' &&

## Jump forward a couple of hours so the KSK will be ready
##################  STEP 1: Time = 2hrs ###########################
export ENFORCER_TIMESHIFT='01-01-2010 14:00' &&

# Run the enforcer
ods_start_enforcer_timeshift &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 14:00" &&

# We should be ready for a ds-seen on ods
syslog_grep "ods-enforcerd: .*Once the new DS records are seen in DNS please issue the ds-seen command for zone ods with the following cka_ids, $KSK_CKA_ID" &&

# Key list should show KSK in ready state
log_this ods-ksmutil-key-list1_1 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list1_1 stdout 'ods                             KSK           ready     waiting for ds-seen' &&
log_grep ods-ksmutil-key-list1_1 stdout 'ods                             ZSK           active' &&
! log_grep ods-ksmutil-key-list1_1 stdout 'ods                             KSK           active' &&

## TEST 2 we have a key in the correct state but run ds-seen on something else
! log_this ods-ksmutil-dsseen_ods2   ods-ksmutil key ds-seen --zone ods --cka_id deadbeef &&
log_grep ods-ksmutil-dsseen_ods2 stdout "No keys in the READY state matched your parameters, please check the parameters" &&

# Key list should show KSK still in ready state
log_this ods-ksmutil-key-list1_2 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list1_2 stdout 'ods                             KSK           ready     waiting for ds-seen' &&
log_grep ods-ksmutil-key-list1_2 stdout 'ods                             ZSK           active' &&
! log_grep ods-ksmutil-key-list1_2 stdout 'ods                             KSK           active' &&

return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

