#!/usr/bin/env bash
#
#TEST: Test to check the -no-notify option on dsseen works
#TEST: The enforcer has an interval of 10 mins set so is should not run apart from when notified
#TEST: or triggered from a command


# Lets use parameters for the timing intervals so they are easy to change
SHORT_TIMEOUT=11    # Timeout when checking log output. DS lock out wait is 10 sec so use 11 for this
LONG_TIMEOUT=20     # Timeout when waiting for enforcer run to have happened
SLEEP_INTERVAL=50   # This should be just shorter than the enforcer run interval in conf.xml

ENFORCER_RUNS=1


if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

ods_start_enforcer && 

##################  STEP 0: First job is to get a KZKs active ###########################
echo "* Setting up keys" &&
log_this ods-ksmutil-check-1   date && 
log_this ods-ksmutil-check-1   ods-ksmutil key list --all --verbose &&
KSK_CKA_ID_1=`log_grep -o ods-ksmutil-check-1 stdout "ods1.*KSK           publish" | awk '{print $6}'` &&

sleep 10 &&
echo "* Notifying enforcer 1" &&
log_this ods-enforcer-notify-1 ods-control enforcer notify &&
ENFORCER_RUNS=$(($ENFORCER_RUNS+1))  &&
ods_enforcer_waitfor_starts $ENFORCER_RUNS &&

# We should have a ready key now
log_this ods-ksmutil-check-2   date &&
log_this ods-ksmutil-check-2   ods-ksmutil key list --all --verbose &&

log_grep ods-ksmutil-check-2   stdout "ods1.*KSK           ready.*$KSK_CKA_ID_1" &&

# Issue ds_seen for KSK1. This will cause the enforcer to run.
echo "* Issue first DSSEEN" &&
log_this ods-ksmutil-dsseen_1   ods-ksmutil key ds-seen --zone ods1 --cka_id  $KSK_CKA_ID_1 &&
log_grep ods-ksmutil-dsseen_1 stdout "Performed a HUP ods-enforcerd" &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_CKA_ID_1 made active" &&
ENFORCER_RUNS=$(($ENFORCER_RUNS+1)) &&
ods_enforcer_waitfor_starts $ENFORCER_RUNS &&

# We should have an active (and a published) key now
log_this ods-ksmutil-check-3   date &&
log_this ods-ksmutil-check-3   ods-ksmutil key list --all --verbose &&

log_grep ods-ksmutil-check-3   stdout "ods1.*KSK           active.*$KSK_CKA_ID_1" &&
KSK_CKA_ID_2=`log_grep -o ods-ksmutil-check-3 stdout "ods1.*KSK           publish" | awk '{print $6}'` &&

sleep 10 &&
##################  STEP 1: Now get the next key ready ###########################
echo "* Notifying enforcer 2" &&
log_this ods-enforcer-notify-1 ods-control enforcer notify && 
ENFORCER_RUNS=$(($ENFORCER_RUNS+1))  &&
ods_enforcer_waitfor_starts $ENFORCER_RUNS &&

# We should have an active (and a ready) keys now
log_this ods-ksmutil-check-4   date &&
log_this ods-ksmutil-check-4   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-check-4   stdout "ods1.*KSK           active.*$KSK_CKA_ID_1" &&
log_grep ods-ksmutil-check-4   stdout "ods1.*KSK           ready.*$KSK_CKA_ID_2" &&

##################  STEP 2: Now use the -no-notify flag ###########################
# Issue ds_seen for KSK2 with no-notify. This should not cause the enforcer to run.
echo "* Issue second DSSEEN" &&
log_this ods-ksmutil-dsseen_2   ods-ksmutil key ds-seen --zone ods1 --cka_id  $KSK_CKA_ID_2 --no-notify &&
log_grep ods-ksmutil-dsseen_2 stdout "No HUP ods-enforcerd was performed as the '--no-notify' flag was specified." &&
log_grep ods-ksmutil-dsseen_2 stdout "Warning: The enforcer must be manually notified or the changes will not take full effect until the next scheduled enforcer run." &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_CKA_ID_2 made active" &&
# check the enforcer hasn't run
sleep 10 &&
ods_enforcer_waitfor_starts $ENFORCER_RUNS &&

# we should have 1 retired and 1 active key now but no published key as the enforcer hasn't run
log_this ods-ksmutil-check-5   date &&
log_this ods-ksmutil-check-5   ods-ksmutil key list --all --verbose &&

log_grep ods-ksmutil-check-5   stdout "ods1.*KSK           retire.*$KSK_CKA_ID_1" &&
log_grep ods-ksmutil-check-5   stdout "ods1.*KSK           active.*$KSK_CKA_ID_2" &&
! log_grep ods-ksmutil-check-5   stdout "ods1.*KSK           publish" &&

# Now kick it manually
echo "* Notify enforcer 3" &&
log_this ods-enforcer-notify-1 ods-control enforcer notify && 
ENFORCER_RUNS=$(($ENFORCER_RUNS+1))  &&
ods_enforcer_waitfor_starts $ENFORCER_RUNS &&

# Now a published KSK should appear because the enforcer just generated it
log_this ods-ksmutil-check-6   date &&
log_this ods-ksmutil-check-6   ods-ksmutil key list --all --verbose &&

log_grep ods-ksmutil-check-6   stdout "ods1.*KSK           retire.*$KSK_CKA_ID_1" &&
log_grep ods-ksmutil-check-6   stdout "ods1.*KSK           active.*$KSK_CKA_ID_2" &&
log_grep ods-ksmutil-check-6   stdout "ods1.*KSK           publish" &&

echo "* All done" &&
ods_stop_enforcer &&

echo &&
echo "************ OK ******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

