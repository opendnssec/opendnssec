#!/usr/bin/env bash
#
#TEST: Test to see that the DSSEEN command is dealt with as expected

ENFORCER_WAIT=90	# Seconds we wait for enforcer to run
ENFORCER_COUNT=2	# How many log lines we expect to see

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

##################  SETUP ###########################
# Start enforcer (Zone already exists and we let it generate keys itself)
ods_start_enforcer &&

ods_timeleap_search_key "ods" "KSK" "publish" &&


# Check that we have 2 keys
log_this ods-enforcer-key-list0_1 ods-enforcer key list &&
log_grep ods-enforcer-key-list0_1 stdout 'ods[[:space:]]*KSK[[:space:]]*publish' &&
log_grep ods-enforcer-key-list0_1 stdout 'ods[[:space:]]*ZSK[[:space:]]*ready' &&
! log_grep ods-enforcer-key-list0_1 stdout 'ods[[:space:]]*KSK[[:space:]]*active' &&

# Grab the KEYTAG of the KSK
log_this ods-enforcer-keytag ods-enforcer key list --verbose &&
KSK_KEYTAG=`log_grep -o ods-enforcer-keytag stdout "ods[[:space:]]*KSK[[:space:]]*publish" | awk '{print $10}'` &&

## TEST 1 -- run the ds-seen command now and expect to be told off
! log_this ods-enforcer-dsseen_ods1   ods-enforcer key ds-seen --zone ods --keytag $KSK_KEYTAG &&
#log_grep ods-enforcer-dsseen_ods1 stdout "No keys in the READY state matched your parameters, please check the parameters" &&

# Check that the KSK didn't move
log_this ods-enforcer-key-list0_2 ods-enforcer key list &&
log_grep ods-enforcer-key-list0_2 stdout 'ods[[:space:]]*KSK[[:space:]]*publish' &&
log_grep ods-enforcer-key-list0_2 stdout 'ods[[:space:]]*ZSK[[:space:]]*ready' &&
! log_grep ods-enforcer-key-list0_2 stdout 'ods[[:space:]]*KSK[[:space:]]*active' &&

## Jump forward a couple of hours so the KSK will be ready
##################  STEP 1: Time = 26hrs ###########################
ods_enforcer_leap_to 93600 &&

# We should be ready for a ds-submit and ds-seen on ods
syslog_grep "ods-enforcerd: .*please submit DS with keytag $KSK_KEYTAG for zone ods" &&

log_this ods-enforcer-dssubmit_ods1   ods-enforcer key ds-submit --zone ods --keytag $KSK_KEYTAG &&

# Key list should show KSK in ready state
log_this ods-enforcer-key-list1_1 ods-enforcer key list &&
log_grep ods-enforcer-key-list1_1 stdout 'ods[[:space:]]*KSK[[:space:]]*ready     waiting for ds-seen' &&
log_grep ods-enforcer-key-list1_1 stdout 'ods[[:space:]]*ZSK[[:space:]]*active' &&
! log_grep ods-enforcer-key-list1_1 stdout 'ods[[:space:]]*KSK[[:space:]]*active' &&

## TEST 2 we have a key in the correct state but run ds-seen on something else
! log_this ods-enforcer-dsseen_ods2   ods-enforcer key ds-seen --zone ods --cka_id deadbeef &&
#log_grep ods-enforcer-dsseen_ods2 stdout "No keys in the READY state matched your parameters, please check the parameters" &&

# Key list should show KSK still in ready state
log_this ods-enforcer-key-list1_2 ods-enforcer key list &&
log_grep ods-enforcer-key-list1_2 stdout 'ods[[:space:]]*KSK[[:space:]]*ready     waiting for ds-seen' &&
log_grep ods-enforcer-key-list1_2 stdout 'ods[[:space:]]*ZSK[[:space:]]*active' &&
! log_grep ods-enforcer-key-list1_2 stdout 'ods[[:space:]]*KSK[[:space:]]*active' &&
ods_stop_enforcer &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

