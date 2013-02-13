#!/usr/bin/env bash
#
#TEST: Test to track key rollovers in real time from the enforcer side only. 
#TEST: Configured with short key lifetimes and 1 min enforcer interval.
#TEST: unlike parent test this uses TIMESHIFT to hopefully keep things deterministic
#TEST: Checks the output of ods-ksmutil key list and the signconf.xml contents
#TEST: Takes about 10 mins and follows several KSK and ZKK rollovers.

#TODO: - increase number of steps?
#TODO: - check more logging in syslog
#TODO: - fix the compare script to directly compare the key ids in the signconf

ENFORCER_WAIT=90	# Seconds we wait for enforcer to run

compare_files_ignore_locator () {

        if [ -z "$1" -o -z "$2" ]; then
                echo "usage: compare_files_ignore_locator <file1> <file2> " >&2
                exit 1
        fi

        local file1="$1"
        local file2="$2"
        local file1_tmp="tmp/file1.tmp"
        local file2_tmp="tmp/file2.tmp"

        sed 's#<Locator>.*#<Locator></Locator>#g' $file1 > $file1_tmp
        sed 's#<Locator>.*#<Locator></Locator>#g' $file2 > $file2_tmp
        diff $file1_tmp $file2_tmp
}

case "$DISTRIBUTION" in
	freebsd )
		return 0
		;;
esac

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

# Check that we have 2 keys per zone
log_this ods-ksmutil-key-list0 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list0 stdout 'ods1                            KSK           publish   2010-01-01 12:03:40' &&
log_grep ods-ksmutil-key-list0 stdout 'ods1                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list0 stdout 'ods2                            KSK           publish   2010-01-01 12:14:30' &&
log_grep ods-ksmutil-key-list0 stdout 'ods2                            ZSK           active    2010-01-01 12:25:00' &&
# No retired keys either
! log_grep ods-ksmutil-key-list0 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list0 stdout 'ods1                            ZSK           retire' &&
! log_grep ods-ksmutil-key-list0 stdout 'ods2                            KSK           retire' &&
! log_grep ods-ksmutil-key-list0 stdout 'ods2                            ZSK           retire' &&

#TODO Check that no other keys were allocated
# HOW???

# Grab the CKA_IDs of the 2 KSKs
log_this ods-ksmutil-cka_id1 ods-ksmutil key list --all --verbose &&
KSK_CKA_ID_1=`log_grep -o ods-ksmutil-cka_id1 stdout "ods1                            KSK           publish" | awk '{print $6}'` &&
KSK_CKA_ID_2=`log_grep -o ods-ksmutil-cka_id1 stdout "ods2                            KSK           publish" | awk '{print $6}'` &&

## Next event is KSK for ods1 -> ready (should be 12:03:40)
##################  STEP 1: Time = 3min40 ###########################
export ENFORCER_TIMESHIFT='01-01-2010 12:03:40' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 2 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:03:40" &&

# We should be ready for a ds-seen on ods1 but not ods2 (not ready until 12:15)
syslog_grep "ods-enforcerd: .*Once the new DS records are seen in DNS please issue the ds-seen command for zone ods1 with the following cka_ids, $KSK_CKA_ID_1" &&
! syslog_grep "ods-enforcerd: .*Once the new DS records are seen in DNS please issue the ds-seen command for zone ods2 with the following cka_ids" &&

# Key list should show KSK in ready state
# Check that we have 2 keys per zone
log_this ods-ksmutil-key-list1_1 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list1_1 stdout 'ods1                            KSK           ready     waiting for ds-seen' &&
log_grep ods-ksmutil-key-list1_1 stdout 'ods1                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list1_1 stdout 'ods2                            KSK           publish   2010-01-01 12:14:30' &&
log_grep ods-ksmutil-key-list1_1 stdout 'ods2                            ZSK           active    2010-01-01 12:25:00' &&
# No retired keys either
! log_grep ods-ksmutil-key-list1_1 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list1_1 stdout 'ods1                            ZSK           retire' &&
! log_grep ods-ksmutil-key-list1_1 stdout 'ods2                            KSK           retire' &&
! log_grep ods-ksmutil-key-list1_1 stdout 'ods2                            ZSK           retire' &&

# Run the ds-seen on ods1 and check the output (enforcer won't HUP as it isn't running)
log_this ods-ksmutil-dsseen_ods1   ods-ksmutil key ds-seen --zone ods1 --cka_id $KSK_CKA_ID_1 &&
log_grep ods-ksmutil-dsseen_ods1 stdout "Cannot find PID file" &&
log_grep ods-ksmutil-dsseen_ods1 stdout "Found key with CKA_ID $KSK_CKA_ID_1" &&
log_grep ods-ksmutil-dsseen_ods1 stdout "Key $KSK_CKA_ID_1 made active" &&

# Key list should reflect this
# Check that we have 2 keys per zone
log_this ods-ksmutil-key-list1_2 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list1_2 stdout 'ods1                            KSK           active    2010-01-01 12:33:40' &&
log_grep ods-ksmutil-key-list1_2 stdout 'ods1                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list1_2 stdout 'ods2                            KSK           publish   2010-01-01 12:14:30' &&
log_grep ods-ksmutil-key-list1_2 stdout 'ods2                            ZSK           active    2010-01-01 12:25:00' &&
# No retired keys either
! log_grep ods-ksmutil-key-list1_2 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list1_2 stdout 'ods1                            ZSK           retire' &&
! log_grep ods-ksmutil-key-list1_2 stdout 'ods2                            KSK           retire' &&
! log_grep ods-ksmutil-key-list1_2 stdout 'ods2                            ZSK           retire' &&

## Next event is prepublish of ZSK for ods2 12:10
##################  STEP 2: Time = 10min ###########################
export ENFORCER_TIMESHIFT='01-01-2010 12:10' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 3 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:10" &&

# We should be still not expect a ds-seen on ods2 (not ready until 12:15)
! syslog_grep "ods-enforcerd: .*Once the new DS records are seen in DNS please issue the ds-seen command for zone ods2 with the following cka_ids" &&

# Key list should reflect this new key
# Check that we have 2/3 keys per zone
log_this ods-ksmutil-key-list2 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list2 stdout 'ods1                            KSK           active    2010-01-01 12:33:40' &&
log_grep ods-ksmutil-key-list2 stdout 'ods1                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list2 stdout 'ods2                            KSK           publish   2010-01-01 12:14:30' &&
log_grep ods-ksmutil-key-list2 stdout 'ods2                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list2 stdout 'ods2                            ZSK           publish   2010-01-01 12:24:30' &&
# No retired keys yet
! log_grep ods-ksmutil-key-list2 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list2 stdout 'ods1                            ZSK           retire' &&
! log_grep ods-ksmutil-key-list2 stdout 'ods2                            KSK           retire' &&
! log_grep ods-ksmutil-key-list2 stdout 'ods2                            ZSK           retire' &&


## Next event is KSK for ods2 -> ready at 12:14:30
##################  STEP 3: Time = 15min ###########################
export ENFORCER_TIMESHIFT='01-01-2010 12:14:30' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 4 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:14:30" &&

# Key list should show KSK in ready state
# Check that we have 2 keys per zone
log_this ods-ksmutil-key-list3_1 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list3_1 stdout 'ods1                            KSK           active    2010-01-01 12:33:40' &&
log_grep ods-ksmutil-key-list3_1 stdout 'ods1                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list3_1 stdout 'ods2                            KSK           ready     waiting for ds-seen' &&
log_grep ods-ksmutil-key-list3_1 stdout 'ods2                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list3_1 stdout 'ods2                            ZSK           publish   2010-01-01 12:24:30' &&
# No retired keys either
! log_grep ods-ksmutil-key-list3_1 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list3_1 stdout 'ods1                            ZSK           retire' &&
! log_grep ods-ksmutil-key-list3_1 stdout 'ods2                            KSK           retire' &&
! log_grep ods-ksmutil-key-list3_1 stdout 'ods2                            ZSK           retire' &&

# We should be ready for a ds-seen on ods2
syslog_grep "ods-enforcerd: .*Once the new DS records are seen in DNS please issue the ds-seen command for zone ods2 with the following cka_ids, $KSK_CKA_ID_2" &&

# Run the ds-seen on ods2 and check the output (enforcer won't HUP as it isn't running)
log_this ods-ksmutil-dsseen_ods3   ods-ksmutil key ds-seen --zone ods2 --cka_id $KSK_CKA_ID_2 &&
log_grep ods-ksmutil-dsseen_ods3 stdout "Cannot find PID file" &&
log_grep ods-ksmutil-dsseen_ods3 stdout "Found key with CKA_ID $KSK_CKA_ID_2" &&
log_grep ods-ksmutil-dsseen_ods3 stdout "Key $KSK_CKA_ID_2 made active" &&

# Key list should reflect this
# Check that we have 2/3 keys per zone
log_this ods-ksmutil-key-list3_2 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list3_2 stdout 'ods1                            KSK           active    2010-01-01 12:33:40' &&
log_grep ods-ksmutil-key-list3_2 stdout 'ods1                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list3_2 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list3_2 stdout 'ods2                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list3_2 stdout 'ods2                            ZSK           publish   2010-01-01 12:24:30' &&
# No retired keys yet
! log_grep ods-ksmutil-key-list3_2 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list3_2 stdout 'ods1                            ZSK           retire' &&
! log_grep ods-ksmutil-key-list3_2 stdout 'ods2                            KSK           retire' &&
! log_grep ods-ksmutil-key-list3_2 stdout 'ods2                            ZSK           retire' &&


## Next event is prepublish of ZSK for ods1 12:21
##################  STEP 4: Time = 21min ###########################
export ENFORCER_TIMESHIFT='01-01-2010 12:21' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 5 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:21" &&

# Key list should reflect this new key
# Check that we have 3 keys per zone
log_this ods-ksmutil-key-list4 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list4 stdout 'ods1                            KSK           active    2010-01-01 12:33:40' &&
log_grep ods-ksmutil-key-list4 stdout 'ods1                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list4 stdout 'ods1                            ZSK           publish   2010-01-01 12:24:40' &&
log_grep ods-ksmutil-key-list4 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list4 stdout 'ods2                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list4 stdout 'ods2                            ZSK           publish   2010-01-01 12:24:30' &&
# No retired keys yet
! log_grep ods-ksmutil-key-list4 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list4 stdout 'ods1                            ZSK           retire' &&
! log_grep ods-ksmutil-key-list4 stdout 'ods2                            KSK           retire' &&
! log_grep ods-ksmutil-key-list4 stdout 'ods2                            ZSK           retire' &&


## Next event is ZSK ready for ods2 12:24:30
##################  STEP 5: Time = 24min30 ###########################
export ENFORCER_TIMESHIFT='01-01-2010 12:24:30' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 6 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:24:30" &&

# Key list should reflect ready key
# Check that we have 3 keys per zone
log_this ods-ksmutil-key-list5 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list5 stdout 'ods1                            KSK           active    2010-01-01 12:33:40' &&
log_grep ods-ksmutil-key-list5 stdout 'ods1                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list5 stdout 'ods1                            ZSK           publish   2010-01-01 12:24:40' &&
log_grep ods-ksmutil-key-list5 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list5 stdout 'ods2                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list5 stdout 'ods2                            ZSK           ready     next rollover' &&
# No retired keys yet
! log_grep ods-ksmutil-key-list5 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list5 stdout 'ods1                            ZSK           retire' &&
! log_grep ods-ksmutil-key-list5 stdout 'ods2                            KSK           retire' &&
! log_grep ods-ksmutil-key-list5 stdout 'ods2                            ZSK           retire' &&



## Next event is ZSK ready for ods1 12:24:40
##################  STEP 6: Time = 24min40 ###########################
export ENFORCER_TIMESHIFT='01-01-2010 12:24:40' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 7 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:24:40" &&

# Key list should reflect both ready keys
# Check that we have 3 keys per zone
log_this ods-ksmutil-key-list6 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list6 stdout 'ods1                            KSK           active    2010-01-01 12:33:40' &&
log_grep ods-ksmutil-key-list6 stdout 'ods1                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list6 stdout 'ods1                            ZSK           ready     next rollover' &&
log_grep ods-ksmutil-key-list6 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list6 stdout 'ods2                            ZSK           active    2010-01-01 12:25:00' &&
log_grep ods-ksmutil-key-list6 stdout 'ods2                            ZSK           ready     next rollover' &&
# No retired keys yet
! log_grep ods-ksmutil-key-list6 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list6 stdout 'ods1                            ZSK           retire' &&
! log_grep ods-ksmutil-key-list6 stdout 'ods2                            KSK           retire' &&
! log_grep ods-ksmutil-key-list6 stdout 'ods2                            ZSK           retire' &&


## Next event is ZSK roll for both zones 12:25
##################  STEP 7: Time = 25min ###########################
export ENFORCER_TIMESHIFT='01-01-2010 12:25' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 8 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:25" &&

# Key list should reflect these rolls
# Check that we have 3 keys per zone
log_this ods-ksmutil-key-list7 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list7 stdout 'ods1                            KSK           active    2010-01-01 12:33:40' &&
log_grep ods-ksmutil-key-list7 stdout 'ods1                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list7 stdout 'ods1                            ZSK           retire    2010-01-01 12:42:40' &&
log_grep ods-ksmutil-key-list7 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list7 stdout 'ods2                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list7 stdout 'ods2                            ZSK           retire    2010-01-01 12:44:30' &&
# No retired KSKs yet
! log_grep ods-ksmutil-key-list7 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list7 stdout 'ods2                            KSK           retire' &&


## Next event is prepublish of KSK for ods1 12:30
##################  STEP 8: Time = 30min ###########################
export ENFORCER_TIMESHIFT='01-01-2010 12:30' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 9 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:30" &&

# Key list should reflect these rolls
# Check that we have 3 keys per zone
log_this ods-ksmutil-key-list8 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list8 stdout 'ods1                            KSK           active    2010-01-01 12:33:40' &&
log_grep ods-ksmutil-key-list8 stdout 'ods1                            KSK           publish   2010-01-01 12:33:40' &&
log_grep ods-ksmutil-key-list8 stdout 'ods1                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list8 stdout 'ods1                            ZSK           retire    2010-01-01 12:42:40' &&
log_grep ods-ksmutil-key-list8 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list8 stdout 'ods2                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list8 stdout 'ods2                            ZSK           retire    2010-01-01 12:44:30' &&
# No retired KSKs yet
! log_grep ods-ksmutil-key-list8 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list8 stdout 'ods2                            KSK           retire' &&



## Next event is KSK for ods1 -> ready (should be 12:33:40)
##################  STEP 9: Time = 33min40 ###########################
# Grab the CKA_ID of the KSK
log_this ods-ksmutil-cka_id9 ods-ksmutil key list --all --verbose &&
KSK_CKA_ID_3=`log_grep -o ods-ksmutil-cka_id9 stdout "ods1                            KSK           publish" | awk '{print $6}'` &&

export ENFORCER_TIMESHIFT='01-01-2010 12:33:40' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 10 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:33:40" &&

# We should be ready for a ds-seen on ods1 but not ods2 (not ready until 12:15)
syslog_grep "ods-enforcerd: .*Once the new DS records are seen in DNS please issue the ds-seen command for zone ods1 with the following cka_ids, $KSK_CKA_ID_3" &&

# Key list should show KSK in ready state
log_this ods-ksmutil-key-list9_1 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list9_1 stdout 'ods1                            KSK           active    2010-01-01 12:33:40' &&
log_grep ods-ksmutil-key-list9_1 stdout 'ods1                            KSK           ready     waiting for ds-seen' &&
log_grep ods-ksmutil-key-list9_1 stdout 'ods1                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list9_1 stdout 'ods1                            ZSK           retire    2010-01-01 12:42:40' &&
log_grep ods-ksmutil-key-list9_1 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list9_1 stdout 'ods2                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list9_1 stdout 'ods2                            ZSK           retire    2010-01-01 12:44:30' &&
# No retired keys either
! log_grep ods-ksmutil-key-list9_1 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list9_1 stdout 'ods2                            KSK           retire' &&

# Run the ds-seen on ods1 and check the output (enforcer won't HUP as it isn't running)
log_this ods-ksmutil-dsseen_ods9   ods-ksmutil key ds-seen --zone ods1 --cka_id $KSK_CKA_ID_3 &&
log_grep ods-ksmutil-dsseen_ods9 stdout "Cannot find PID file" &&
log_grep ods-ksmutil-dsseen_ods9 stdout "Found key with CKA_ID $KSK_CKA_ID_3" &&
log_grep ods-ksmutil-dsseen_ods9 stdout "Key $KSK_CKA_ID_3 made active" &&

# Key list should reflect this
log_this ods-ksmutil-key-list9_2 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list9_2 stdout 'ods1                            KSK           retire    2010-01-01 12:38:50' &&
log_grep ods-ksmutil-key-list9_2 stdout 'ods1                            KSK           active    2010-01-01 13:03:40' &&
log_grep ods-ksmutil-key-list9_2 stdout 'ods1                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list9_2 stdout 'ods1                            ZSK           retire    2010-01-01 12:42:40' &&
log_grep ods-ksmutil-key-list9_2 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list9_2 stdout 'ods2                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list9_2 stdout 'ods2                            ZSK           retire    2010-01-01 12:44:30' &&
# Only ods2 KSK has no retired keys
! log_grep ods-ksmutil-key-list9_2 stdout 'ods2                            KSK           retire' &&



## Next event is prepublish of ZSK for ods2 12:35:30
##################  STEP 10: Time = 35min30 ###########################
export ENFORCER_TIMESHIFT='01-01-2010 12:35:30' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 11 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:35:30" &&

# Key list should reflect this new key
# Check that we have 4 keys per zone
log_this ods-ksmutil-key-list10 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list10 stdout 'ods1                            KSK           retire    2010-01-01 12:38:50' &&
log_grep ods-ksmutil-key-list10 stdout 'ods1                            KSK           active    2010-01-01 13:03:40' &&
log_grep ods-ksmutil-key-list10 stdout 'ods1                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list10 stdout 'ods1                            ZSK           retire    2010-01-01 12:42:40' &&
log_grep ods-ksmutil-key-list10 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list10 stdout 'ods2                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list10 stdout 'ods2                            ZSK           retire    2010-01-01 12:44:30' &&
log_grep ods-ksmutil-key-list10 stdout 'ods2                            ZSK           publish   2010-01-01 12:50:00' &&
# Only ods2 KSK has no retired keys
! log_grep ods-ksmutil-key-list10 stdout 'ods2                            KSK           retire' &&


## Next event is KSK for ods1 -> dead 12:38:50
##################  STEP 11: Time = 38min50 ###########################
export ENFORCER_TIMESHIFT='01-01-2010 12:38:50' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 12 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:38:50" &&

# Key list
# Check that we have 3 keys per zone
log_this ods-ksmutil-key-list11 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list11 stdout 'ods1                            KSK           active    2010-01-01 13:03:40' &&
log_grep ods-ksmutil-key-list11 stdout 'ods1                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list11 stdout 'ods1                            ZSK           retire    2010-01-01 12:42:40' &&
log_grep ods-ksmutil-key-list11 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list11 stdout 'ods2                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list11 stdout 'ods2                            ZSK           retire    2010-01-01 12:44:30' &&
log_grep ods-ksmutil-key-list11 stdout 'ods2                            ZSK           publish   2010-01-01 12:50:00' &&
# No retired KSKs any more
! log_grep ods-ksmutil-key-list11 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list11 stdout 'ods2                            KSK           retire' &&


## Next event is ZSK for ods1 -> dead 12:42:40
##################  STEP 12: Time = 42min40 ###########################
export ENFORCER_TIMESHIFT='01-01-2010 12:42:40' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 13 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:42:40" &&

# Key list
# Check that we have 2/4 keys per zone
log_this ods-ksmutil-key-list12 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list12 stdout 'ods1                            KSK           active    2010-01-01 13:03:40' &&
log_grep ods-ksmutil-key-list12 stdout 'ods1                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list12 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list12 stdout 'ods2                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list12 stdout 'ods2                            ZSK           retire    2010-01-01 12:44:30' &&
log_grep ods-ksmutil-key-list12 stdout 'ods2                            ZSK           publish   2010-01-01 12:50:00' &&
# No retired KSKs or ZSK on ods1
! log_grep ods-ksmutil-key-list12 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list12 stdout 'ods1                            ZSK           retire' &&
! log_grep ods-ksmutil-key-list12 stdout 'ods2                            KSK           retire' &&


## Next event is ZSK for ods2 -> dead 12:44:30 (plus KSK prepublish for ods2)
##################  STEP 13: Time = 44min30 ###########################
export ENFORCER_TIMESHIFT='01-01-2010 12:44:30' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 14 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:44:30" &&

# Key list
# Check that we have 2/4 keys per zone
log_this ods-ksmutil-key-list13 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list13 stdout 'ods1                            KSK           active    2010-01-01 13:03:40' &&
log_grep ods-ksmutil-key-list13 stdout 'ods1                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list13 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list13 stdout 'ods2                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list13 stdout 'ods2                            ZSK           publish   2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list13 stdout 'ods2                            KSK           publish   2010-01-01 12:59:00' &&
# No retired Keys
! log_grep ods-ksmutil-key-list13 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list13 stdout 'ods1                            ZSK           retire' &&
! log_grep ods-ksmutil-key-list13 stdout 'ods2                            KSK           retire' &&
! log_grep ods-ksmutil-key-list13 stdout 'ods2                            ZSK           retire' &&


## Next event is prepublish of ZSK for ods1 12:46:20
##################  STEP 14: Time = 46min20 ###########################
export ENFORCER_TIMESHIFT='01-01-2010 12:46:20' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 15 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:46:20" &&

# Key list
# Check that we have 3/4 keys per zone
log_this ods-ksmutil-key-list14 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list14 stdout 'ods1                            KSK           active    2010-01-01 13:03:40' &&
log_grep ods-ksmutil-key-list14 stdout 'ods1                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list14 stdout 'ods1                            ZSK           publish   2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list14 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list14 stdout 'ods2                            ZSK           active    2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list14 stdout 'ods2                            ZSK           publish   2010-01-01 12:50:00' &&
log_grep ods-ksmutil-key-list14 stdout 'ods2                            KSK           publish   2010-01-01 12:59:00' &&
# No retired Keys
! log_grep ods-ksmutil-key-list14 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list14 stdout 'ods1                            ZSK           retire' &&
! log_grep ods-ksmutil-key-list14 stdout 'ods2                            KSK           retire' &&
! log_grep ods-ksmutil-key-list14 stdout 'ods2                            ZSK           retire' &&



## Next event is ZSK roll for both zones 12:50:00
##################  STEP 15: Time = 50min ###########################
export ENFORCER_TIMESHIFT='01-01-2010 12:50' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 16 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:50" &&

# Key list
# Check that we have 3/4 keys per zone
log_this ods-ksmutil-key-list15 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list15 stdout 'ods1                            KSK           active    2010-01-01 13:03:40' &&
log_grep ods-ksmutil-key-list15 stdout 'ods1                            ZSK           retire    2010-01-01 13:07:40' &&
log_grep ods-ksmutil-key-list15 stdout 'ods1                            ZSK           active    2010-01-01 13:15:00' &&
log_grep ods-ksmutil-key-list15 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list15 stdout 'ods2                            ZSK           retire    2010-01-01 13:09:30' &&
log_grep ods-ksmutil-key-list15 stdout 'ods2                            ZSK           active    2010-01-01 13:15:00' &&
log_grep ods-ksmutil-key-list15 stdout 'ods2                            KSK           publish   2010-01-01 12:59:00' &&
# No retired KSKs
! log_grep ods-ksmutil-key-list15 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list15 stdout 'ods2                            KSK           retire' &&



## Next event is KSK for ods2 -> ready 12:59:00 will also prepublish a KSK for ods1
##################  STEP 16: Time = 59min ###########################
# Grab the CKA_ID of the KSK
log_this ods-ksmutil-cka_id16 ods-ksmutil key list --all --verbose &&
KSK_CKA_ID_4=`log_grep -o ods-ksmutil-cka_id16 stdout "ods2                            KSK           publish" | awk '{print $6}'` &&

export ENFORCER_TIMESHIFT='01-01-2010 12:59' &&

# Run the enforcer
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor_count $ENFORCER_WAIT 17 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 12:59" &&

# Key list
# Check that we have 4 keys per zone
log_this ods-ksmutil-key-list16_1 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list16_1 stdout 'ods1                            KSK           active    2010-01-01 13:03:40' &&
log_grep ods-ksmutil-key-list16_1 stdout 'ods1                            ZSK           retire    2010-01-01 13:07:40' &&
log_grep ods-ksmutil-key-list16_1 stdout 'ods1                            ZSK           active    2010-01-01 13:15:00' &&
log_grep ods-ksmutil-key-list16_1 stdout 'ods1                            KSK           publish   2010-01-01 13:02:40' &&
log_grep ods-ksmutil-key-list16_1 stdout 'ods2                            KSK           active    2010-01-01 12:59:30' &&
log_grep ods-ksmutil-key-list16_1 stdout 'ods2                            ZSK           retire    2010-01-01 13:09:30' &&
log_grep ods-ksmutil-key-list16_1 stdout 'ods2                            ZSK           active    2010-01-01 13:15:00' &&
log_grep ods-ksmutil-key-list16_1 stdout 'ods2                            KSK           ready     waiting for ds-seen' &&
# No retired KSKs
! log_grep ods-ksmutil-key-list16_1 stdout 'ods1                            KSK           retire' &&
! log_grep ods-ksmutil-key-list16_1 stdout 'ods2                            KSK           retire' &&

# We should be ready for a ds-seen on ods2
syslog_grep "ods-enforcerd: .*Once the new DS records are seen in DNS please issue the ds-seen command for zone ods2 with the following cka_ids, $KSK_CKA_ID_4" &&

# Run the ds-seen on ods2 and check the output (enforcer won't HUP as it isn't running)
log_this ods-ksmutil-dsseen_ods16   ods-ksmutil key ds-seen --zone ods2 --cka_id $KSK_CKA_ID_4 &&
log_grep ods-ksmutil-dsseen_ods16 stdout "Cannot find PID file" &&
log_grep ods-ksmutil-dsseen_ods16 stdout "Found key with CKA_ID $KSK_CKA_ID_4" &&
log_grep ods-ksmutil-dsseen_ods16 stdout "Key $KSK_CKA_ID_4 made active" &&

# Key list should reflect this
# Check that we have 4 keys per zone
log_this ods-ksmutil-key-list16_2 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list16_2 stdout 'ods1                            KSK           active    2010-01-01 13:03:40' &&
log_grep ods-ksmutil-key-list16_2 stdout 'ods1                            ZSK           retire    2010-01-01 13:07:40' &&
log_grep ods-ksmutil-key-list16_2 stdout 'ods1                            ZSK           active    2010-01-01 13:15:00' &&
log_grep ods-ksmutil-key-list16_2 stdout 'ods1                            KSK           publish   2010-01-01 13:02:40' &&
log_grep ods-ksmutil-key-list16_2 stdout 'ods2                            KSK           active    2010-01-01 13:44:00' &&
log_grep ods-ksmutil-key-list16_2 stdout 'ods2                            ZSK           retire    2010-01-01 13:09:30' &&
log_grep ods-ksmutil-key-list16_2 stdout 'ods2                            ZSK           active    2010-01-01 13:15:00' &&
log_grep ods-ksmutil-key-list16_2 stdout 'ods2                            KSK           retire    2010-01-01 13:04:30' &&
# No retired KSKs on ods1
! log_grep ods-ksmutil-key-list16_2 stdout 'ods1                            KSK           retire' &&


return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

