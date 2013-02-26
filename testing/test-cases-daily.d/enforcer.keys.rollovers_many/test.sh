#!/usr/bin/env bash
#
#TEST: Test to track key rollovers in real time from the enforcer side only. 
#TEST: Configured with very short key lifetimes and 1 min enforcer interval.
#TEST: Checks the output of ods-ksmutil key list and the signconf.xml contents
#TEST: Takes about 10 mins and follows several KSK and ZKK rollovers.

#TODO: - increase number of steps?
#TODO: - check more logging in syslog

# Lets use parameters for the timing intervals so they are easy to change
SHORT_TIMEOUT=11    # Timeout when checking log output. DS lock out wait is 10 sec so use 11 for this
LONG_TIMEOUT=20     # Timeout when waiting for enforcer run to have happened
SLEEP_INTERVAL=50   # This should be just shorter than the enforcer run interval in conf.xml


if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

rm -rf base &&
mkdir  base &&

# Used only to create a gold while setting up the test
# rm -rf gold && mkdir gold &&

##################  SETUP ###########################
# Add a zone
log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil zone add --zone ods --input $INSTALL_ROOT/var/opendnssec/unsigned/ods.xml --policy Policy1 --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods.xml &&
log_grep ods-ksmutil-setup_zone_and_keys   stdout "Imported zone: ods" &&
log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil zone list &&
log_grep ods-ksmutil-setup_zone_and_keys   stdout "Found Zone: ods; on policy Policy1" &&

# Generate keys
echo "y" | log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil key generate --interval PT40M --policy  Policy1 &&
log_grep ods-ksmutil-setup_zone_and_keys   stdout "This will create 10 KSKs" &&
log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil update conf &&
log_grep ods-ksmutil-setup_zone_and_keys   stdout "RequireBackup NOT set; " &&

# Start enforcer
log_this_timeout ods-control-enforcer-startart $SHORT_TIMEOUT   ods-control enforcer start &&
syslog_waitfor $SHORT_TIMEOUT 'ods-enforcerd: .*Sleeping for' &&

##################  STEP 0: Time = 0 ###########################
# Check the output
log_this ods-ksmutil-check-0   date && log_this ods-ksmutil-check-0   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-check-0   stdout "ZSK           active" && 
log_grep ods-ksmutil-check-0   stdout "ZSK           publish" && 
log_grep ods-ksmutil-check-0   stdout "KSK           dssub" && 
log_grep ods-ksmutil-check-0   stdout "KSK           publish" &&
#cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml gold/ods_signconf_0.xml &&  
cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml base/ods_signconf_0.xml &&  

# Get the key tags and issue the DS sub on the standby key. This will cause the enforcer to run again.
ZSK_CKA_ID_1=`log_grep -o ods-ksmutil-check-0 stdout "ZSK           active" | awk '{print $9}'` &&
ZSK_CKA_ID_2=`log_grep -o ods-ksmutil-check-0 stdout "ZSK           publish" | awk '{print $9}'` &&
KSK_CKA_ID_STANDBY=`log_grep -o ods-ksmutil-check-0 stdout "KSK           dssub" | awk '{print $10}'` &&
KSK_CKA_ID_1=`log_grep -o ods-ksmutil-check-0 stdout "KSK           publish" | awk '{print $9}'` &&
log_this ods-ksmutil-dsseen_standby   ods-ksmutil key ds-seen --zone ods --cka_id $KSK_CKA_ID_STANDBY &&

# Check it was made standby
syslog_waitfor $SHORT_TIMEOUT         "ods-ksmutil: .*Key $KSK_CKA_ID_STANDBY made into standby" &&
syslog_waitfor_count $SHORT_TIMEOUT 2 'ods-enforcerd: .*Sleeping for' &&
log_this ods-ksmutil-dsseen_standby   date &&
log_this ods-ksmutil-dsseen_standby   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-dsseen_standby   stdout "KSK           dspublish.*$KSK_CKA_ID_STANDBY" &&

# Wait for the enforcer to run again
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 3 'ods-enforcerd: .*Sleeping for' &&

##################  STEP 1: Time ~ 1 x enforcer interval ###########################
log_this ods-ksmutil-check-1   date && log_this ods-ksmutil-check-1   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-check-1   stdout "ZSK           active.*$ZSK_CKA_ID_1" &&
log_grep ods-ksmutil-check-1   stdout "ZSK           ready.*$ZSK_CKA_ID_2" &&
log_grep ods-ksmutil-check-1   stdout "KSK           dspublish.*$KSK_CKA_ID_STANDBY" &&
log_grep ods-ksmutil-check-1   stdout "KSK           ready.*$KSK_CKA_ID_1" &&
#cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml gold/ods_signconf_1.xml &&
cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml base/ods_signconf_1.xml &&

# Issue ds_seen for KSK1. This will cause the enforcer to run.
log_this ods-ksmutil-dsseen_1   ods-ksmutil key ds-seen --zone ods --cka_id $KSK_CKA_ID_1 &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_CKA_ID_1 made active" &&
syslog_waitfor_count $LONG_TIMEOUT 4 'ods-enforcerd: .*Sleeping for' &&

# WAIT for the enforcer to run
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 5 'ods-enforcerd: .*Sleeping for' &&

##################  STEP 2 ###########################
log_this ods-ksmutil-check-2   date && log_this ods-ksmutil-check-2   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-check-2   stdout "ZSK           active.*$ZSK_CKA_ID_1" &&
log_grep ods-ksmutil-check-2   stdout "ZSK           ready.*$ZSK_CKA_ID_2" &&
log_grep ods-ksmutil-check-2   stdout "ZSK           publish" &&
log_grep ods-ksmutil-check-2   stdout "KSK           dsready.*$KSK_CKA_ID_STANDBY" &&
log_grep ods-ksmutil-check-2   stdout "KSK           active.*$KSK_CKA_ID_1" &&
ZSK_CKA_ID_3=`log_grep -o ods-ksmutil-check-2 stdout "ZSK           publish" | awk '{print $9}'` &&
#cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml gold/ods_signconf_2.xml &&  
cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml base/ods_signconf_2.xml && 

# Wait for the enforcer to run
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 6 'ods-enforcerd: .*Sleeping for' &&

##################  STEP 3 ###########################
log_this ods-ksmutil-check-3   date && log_this ods-ksmutil-check-3   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-check-3   stdout "ZSK           retire.*$ZSK_CKA_ID_1" &&
log_grep ods-ksmutil-check-3   stdout "ZSK           active.*$ZSK_CKA_ID_2" &&
log_grep ods-ksmutil-check-3   stdout "ZSK           ready.*$ZSK_CKA_ID_3" &&
log_grep ods-ksmutil-check-3   stdout "KSK           dsready.*$KSK_CKA_ID_STANDBY" &&
log_grep ods-ksmutil-check-3   stdout "KSK           active.*$KSK_CKA_ID_1" &&
#cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml gold/ods_signconf_3.xml &&
cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml base/ods_signconf_3.xml &&

# Wait for the enforcer to run
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 7 'ods-enforcerd: .*Sleeping for' &&

##################  STEP 4 ###########################
# Expect a new KSK to be published
log_this ods-ksmutil-check-4   date && log_this ods-ksmutil-check-4   ods-ksmutil key list --all --verbose &&
! log_grep ods-ksmutil-check-4  stdout "ZSK           retire.*$ZSK_CKA_ID_1" &&
log_grep ods-ksmutil-check-4   stdout "ZSK           active.*$ZSK_CKA_ID_2" &&
log_grep ods-ksmutil-check-4   stdout "ZSK           ready.*$ZSK_CKA_ID_3" &&
log_grep ods-ksmutil-check-4   stdout "KSK           dsready.*$KSK_CKA_ID_STANDBY" &&
log_grep ods-ksmutil-check-4   stdout "KSK           active.*$KSK_CKA_ID_1" &&
log_grep ods-ksmutil-check-4   stdout "KSK           publish" &&
KSK_CKA_ID_2=`log_grep -o ods-ksmutil-check-4 stdout "KSK           publish" | awk '{print $9}'` &&
#cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml gold/ods_signconf_4.xml &&
cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml base/ods_signconf_4.xml &&

# Wait for the enforcer to run.
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 8 'ods-enforcerd: .*Sleeping for' &&

##################  STEP 5 ###########################
# Expect the new KSK to be ready now
log_this ods-ksmutil-check-5   date && log_this ods-ksmutil-check-5   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-check-5   stdout "ZSK           active.*$ZSK_CKA_ID_2" &&
log_grep ods-ksmutil-check-5   stdout "ZSK           ready.*$ZSK_CKA_ID_3" &&
log_grep ods-ksmutil-check-5   stdout "ZSK           publish" &&
log_grep ods-ksmutil-check-5   stdout "KSK           dsready.*$KSK_CKA_ID_STANDBY" &&
log_grep ods-ksmutil-check-5   stdout "KSK           active.*$KSK_CKA_ID_1" &&
log_grep ods-ksmutil-check-5   stdout "KSK           ready.*$KSK_CKA_ID_2" &&
ZSK_CKA_ID_4=`log_grep -o ods-ksmutil-check-5 stdout "ZSK           publish" | awk '{print $9}'` &&
#cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml gold/ods_signconf_5.xml &&
cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml base/ods_signconf_5.xml &&

# Issue ds_seen for KSK2
log_this ods-ksmutil-dsseen_2   ods-ksmutil key ds-seen --zone ods --cka_id $KSK_CKA_ID_2 &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_CKA_ID_2 made active" &&
syslog_waitfor_count $LONG_TIMEOUT 9 'ods-enforcerd: .*Sleeping for' &&

# Check it is activated
log_this ods-ksmutil-check-5_1   date && log_this ods-ksmutil-check-5_1   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-check-5_1   stdout "KSK           dsready.*$KSK_CKA_ID_STANDBY" &&
log_grep ods-ksmutil-check-5_1   stdout "KSK           retire.*$KSK_CKA_ID_1" &&
log_grep ods-ksmutil-check-5_1   stdout "KSK           active.*$KSK_CKA_ID_2" &&
#cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml gold/ods_signconf_5_1.xml &&
cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml base/ods_signconf_5_1.xml &&

# Wait for the enforcer to run
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 10 'ods-enforcerd: .*Sleeping for' &&

##################  STEP 6 ###########################
log_this ods-ksmutil-check-6   date && log_this ods-ksmutil-check-6   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-check-6   stdout "ZSK           retire.*$ZSK_CKA_ID_2" &&
log_grep ods-ksmutil-check-6   stdout "ZSK           active.*$ZSK_CKA_ID_3" &&
log_grep ods-ksmutil-check-6   stdout "ZSK           ready.*$ZSK_CKA_ID_4" &&
log_grep ods-ksmutil-check-6   stdout "KSK           dsready.*$KSK_CKA_ID_STANDBY" &&
log_grep ods-ksmutil-check-6   stdout "KSK           retire.*$KSK_CKA_ID_1" &&
log_grep ods-ksmutil-check-6   stdout "KSK           active.*$KSK_CKA_ID_2" &&
#cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml gold/ods_signconf_6.xml &&
cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml base/ods_signconf_6.xml &&

# Wait for the enforcer to run
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 11 'ods-enforcerd: .*Sleeping for' &&

# ##################  STEP 7 ###########################
log_this ods-ksmutil-check-7   date && log_this ods-ksmutil-check-7   ods-ksmutil key list --all --verbose &&
! log_grep ods-ksmutil-check-7   stdout "ZSK           retire.*$ZSK_CKA_ID_2" &&
log_grep ods-ksmutil-check-7   stdout "ZSK           active.*$ZSK_CKA_ID_3" &&
log_grep ods-ksmutil-check-7   stdout "ZSK           ready.*$ZSK_CKA_ID_4" &&
log_grep ods-ksmutil-check-7   stdout "KSK           dsready.*$KSK_CKA_ID_STANDBY" &&
! log_grep ods-ksmutil-check-7   stdout "KSK           retire.*$KSK_CKA_ID_1" &&
log_grep ods-ksmutil-check-7   stdout "KSK           active.*$KSK_CKA_ID_2" &&
#cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml gold/ods_signconf_7.xml &&
cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml base/ods_signconf_7.xml &&

# Wait for the enforcer to run
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 12 'ods-enforcerd: .*Sleeping for' &&
 
# ##################  STEP 8 ###########################
# Expect a new KSK to be published
log_this ods-ksmutil-check-8   date && log_this ods-ksmutil-check-8   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-check-8   stdout "ZSK           active.*$ZSK_CKA_ID_3" &&
log_grep ods-ksmutil-check-8   stdout "ZSK           ready.*$ZSK_CKA_ID_4" &&
log_grep ods-ksmutil-check-8   stdout "ZSK           publish" &&
log_grep ods-ksmutil-check-8   stdout "KSK           dsready.*$KSK_CKA_ID_STANDBY" &&
log_grep ods-ksmutil-check-8   stdout "KSK           active.*$KSK_CKA_ID_2" &&
log_grep ods-ksmutil-check-8   stdout "KSK           publish" &&
ZSK_CKA_ID_5=`log_grep -o ods-ksmutil-check-8 stdout "ZSK           publish" | awk '{print $9}'` &&
KSK_CKA_ID_3=`log_grep -o ods-ksmutil-check-8 stdout "KSK           publish" | awk '{print $9}'` &&
#cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml gold/ods_signconf_8.xml &&
cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml base/ods_signconf_8.xml &&

# Wait for the enforcer to run
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 13 'ods-enforcerd: .*Sleeping for' &&

# ##################  STEP 9 ###########################
# Expect the new KSK to be ready now
log_this ods-ksmutil-check-9   date && log_this ods-ksmutil-check-9   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-check-9   stdout "ZSK           retire.*$ZSK_CKA_ID_3" &&
log_grep ods-ksmutil-check-9   stdout "ZSK           active.*$ZSK_CKA_ID_4" &&
log_grep ods-ksmutil-check-9   stdout "ZSK           ready.*$ZSK_CKA_ID_5" &&
log_grep ods-ksmutil-check-9   stdout "KSK           dsready.*$KSK_CKA_ID_STANDBY" &&
log_grep ods-ksmutil-check-9   stdout "KSK           active.*$KSK_CKA_ID_2" &&
log_grep ods-ksmutil-check-9   stdout "KSK           ready.*$KSK_CKA_ID_3" &&
#cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml gold/ods_signconf_9.xml &&
cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml base/ods_signconf_9.xml &&

# Issue ds_seen for KSK3
log_this ods-ksmutil-dsseen_3   ods-ksmutil key ds-seen --zone ods --cka_id $KSK_CKA_ID_3 &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_CKA_ID_3 made active" &&
syslog_waitfor_count $LONG_TIMEOUT 14 'ods-enforcerd: .*Sleeping for' &&

# Check it is activated
log_this ods-ksmutil-check-9_1   date && log_this ods-ksmutil-check-9_1   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-check-9_1   stdout "KSK           dsready.*$KSK_CKA_ID_STANDBY" &&
log_grep ods-ksmutil-check-9_1   stdout "KSK           retire.*$KSK_CKA_ID_2" &&
log_grep ods-ksmutil-check-9_1   stdout "KSK           active.*$KSK_CKA_ID_3" &&
#cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml gold/ods_signconf_9_1.xml &&
cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml base/ods_signconf_9_1.xml &&

# Wait for the enforcer to run
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 15 'ods-enforcerd: .*Sleeping for' &&

##################  STEP 10 ###########################
log_this ods-ksmutil-check-10   date && log_this ods-ksmutil-check-10   ods-ksmutil key list --all --verbose &&
! log_grep ods-ksmutil-check-10   stdout "ZSK           retire.*$ZSK_CKA_ID_3" &&
log_grep ods-ksmutil-check-10   stdout "ZSK           active.*$ZSK_CKA_ID_4" &&
log_grep ods-ksmutil-check-10   stdout "ZSK           ready.*$ZSK_CKA_ID_5" &&
log_grep ods-ksmutil-check-10   stdout "KSK           dsready.*$KSK_CKA_ID_STANDBY" &&
log_grep ods-ksmutil-check-10   stdout "KSK           retire.*$KSK_CKA_ID_2" &&
log_grep ods-ksmutil-check-10   stdout "KSK           active.*$KSK_CKA_ID_3" &&
#cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml gold/ods_signconf_10.xml &&
cp $INSTALL_ROOT/var/opendnssec/signconf/ods.xml base/ods_signconf_10.xml &&
 
# ##################  SHUTDOWN ###########################
log_this_timeout ods-control-enforcer-stop $SHORT_TIMEOUT    ods-control enforcer stop &&
syslog_waitfor $SHORT_TIMEOUT   'ods-enforcerd: .*all done' &&

log_this ods-compare-signconfs  ods_compare_gold_vs_base_signconf &&

rm -rf base &&

return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

