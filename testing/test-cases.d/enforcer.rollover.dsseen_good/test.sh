#!/usr/bin/env bash
#
#TEST: Test to see that the DSSEEN command is dealt with as expected
#TEST: We use TIMESHIFT to get to the point where the KSK moves to the ready state

#ENFORCER_WAIT=90	# Seconds we wait for enforcer to run
#ENFORCER_COUNT=2	# How many log lines we expect to see

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&
ods_start_enforcer

##################  SETUP ###########################
# Start enforcer (Zone already exists and we let it generate keys itself)
#export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
#ods_start_enforcer_timeshift &&

sleep 1 &&
log_this ods-enforcer-time-leap ods-enforcer time leap &&
sleep 1 &&

# Make sure TIMESHIFT worked:
#syslog_grep "ods-enforcerd: .*Timeshift mode detected, running once only!" &&
#syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:00" &&

# Check that we have 2 keys
log_this ods-enforcer-key-list1 ods-enforcer key list &&
log_grep ods-enforcer-key-list1 stdout 'ods[[:space:]]*KSK[[:space:]]*publish' &&
log_grep ods-enforcer-key-list1 stdout 'ods[[:space:]]*ZSK[[:space:]]*ready' &&

# Grab the CKA_ID of the KSK
log_this ods-enforcer-cka_id ods-enforcer key list --verbose &&
KSK_CKA_ID=`log_grep -o ods-enforcer-cka_id stdout "ods[[:space:]]*KSK[[:space:]]*publish" | awk '{print $8}'` &&

## Jump forward a couple of hours so the KSK will be ready
##################  STEP 1: Time = 2hrs ###########################
#export ENFORCER_TIMESHIFT='01-01-2010 14:00' &&
log_this ods-enforcer-time-leap ods-enforcer time leap &&
sleep 1 &&

# Run the enforcer
#ods_start_enforcer_timeshift &&
#syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 14:00" &&

# We should be ready for a ds-seen on ods
#syslog_grep "ods-enforcerd: .*Once the new DS records are seen in DNS please issue the ds-seen command for zone ods with the following cka_ids, $KSK_CKA_ID" &&

# Key list should show KSK in ready state
log_this ods-enforcer-key-list1_1 ods-enforcer key list &&
log_grep ods-enforcer-key-list1_1 stdout 'ods[[:space:]]*KSK[[:space:]]*ready[[:space:]]*waiting for ds-seen' &&
log_grep ods-enforcer-key-list1_1 stdout 'ods[[:space:]]*ZSK[[:space:]]*active' &&

# Run the ds-seen on ods and check the output (enforcer won't HUP as it isn't running)
log_this ods-enforcer-dsseen_ods1   ods-enforcer key ds-seen --zone ods --cka_id $KSK_CKA_ID &&
#log_grep ods-ksmutil-dsseen_ods1 stdout "Cannot find PID file" &&
log_grep ods-enforcer-dsseen_ods1 stdout "1 KSK matches found." &&
log_grep ods-enforcer-dsseen_ods1 stdout "1 KSKs changed." &&

# Key list should reflect this
log_this ods-enforcer-key-list1_2 ods-enforcer key list &&
log_grep ods-enforcer-key-list1_2 stdout 'ods[[:space:]]*KSK[[:space:]]*active' &&
log_grep ods-enforcer-key-list1_2 stdout 'ods[[:space:]]*ZSK[[:space:]]*active' &&

return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

