#!/usr/bin/env bash
#
#TEST: Test to see that the DSSEEN command is dealt with as expected

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

##################  SETUP ###########################
# Start enforcer (Zone already exists and we let it generate keys itself)
ods_start_enforcer &&
sleep 1 && ods_enforcer_idle &&
log_this ods-enforcer-time-leap ods-enforcer time leap &&
sleep 1 && ods_enforcer_idle &&


# Check that we have 2 keys
log_this ods-enforcer-key-list1 ods-enforcer key list &&
log_grep ods-enforcer-key-list1 stdout 'ods[[:space:]]*KSK[[:space:]]*publish' &&
log_grep ods-enforcer-key-list1 stdout 'ods[[:space:]]*ZSK[[:space:]]*ready' &&

# Grab the CKA_ID of the KSK
log_this ods-enforcer-keytag ods-enforcer key list --verbose &&
KSK_KEY_TAG=`log_grep -o ods-enforcer-keytag stdout "ods[[:space:]]*KSK[[:space:]]*publish" | awk '{print $10}'` &&

## Jump forward a couple of hours so the KSK will be ready
##################  STEP 1: Time = 2hrs ###########################
sleep 1 && ods_enforcer_idle &&
log_this ods-enforcer-time-leap ods-enforcer time leap &&
sleep 1 && ods_enforcer_idle &&


# We should be ready for a ds-seen on ods
syslog_waitfor 60 "ods-enforcerd: .*\[enforce_task\] please submit DS with keytag $KSK_KEY_TAG for zone ods" &&

# Key list should show KSK in ready state
log_this ods-enforcer-key-list1_1 ods-enforcer key list &&
log_grep ods-enforcer-key-list1_1 stdout 'ods[[:space:]]*KSK[[:space:]]*ready[[:space:]]*waiting for ds-submit' &&
log_grep ods-enforcer-key-list1_1 stdout 'ods[[:space:]]*ZSK[[:space:]]*active' &&

log_this ods-enforcer-dssubmit_ods1 ods-enforcer key ds-submit --zone ods --keytag $KSK_KEY_TAG &&
log_grep ods-enforcer-dssubmit_ods1 stdout "1 KSK matches found." &&
log_grep ods-enforcer-dssubmit_ods1 stdout "1 KSKs changed" &&

sleep 1 && ods_enforcer_idle &&

# Key list should show KSK in ready state
log_this ods-enforcer-key-list1_1 ods-enforcer key list &&
log_grep ods-enforcer-key-list1_1 stdout 'ods[[:space:]]*KSK[[:space:]]*ready[[:space:]]*waiting for ds-seen' &&
log_grep ods-enforcer-key-list1_1 stdout 'ods[[:space:]]*ZSK[[:space:]]*active' &&

# Run the ds-seen on ods and check the output (enforcer won't HUP as it isn't running)
log_this ods-enforcer-dsseen_ods1   ods-enforcer key ds-seen --zone ods --keytag $KSK_KEY_TAG &&
log_grep ods-enforcer-dsseen_ods1 stdout "1 KSK matches found." &&
log_grep ods-enforcer-dsseen_ods1 stdout "1 KSKs changed" &&

# Key list should reflect this
log_this ods-enforcer-key-list1_2 ods-enforcer key list &&
log_grep ods-enforcer-key-list1_2 stdout 'ods[[:space:]]*KSK[[:space:]]*active' &&
log_grep ods-enforcer-key-list1_2 stdout 'ods[[:space:]]*ZSK[[:space:]]*active' &&

ods_stop_enforcer &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1


