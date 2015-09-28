#!/usr/bin/env bash
#
#TEST: Test to see the enforcer will enforcer multiple policies normally
#TEST: but will only work on one policy when prompted

ENFORCER_WAIT=40

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

################## Check all 3 policies where enforced
syslog_grep_count 1 "ods-enforcerd: .*Policy default found\." &&
syslog_grep_count 1 "ods-enforcerd: .*2 zone(s) found on policy \"default\"" &&
syslog_grep_count 1 "ods-enforcerd: .*Policy other found\." &&
syslog_grep_count 1 "ods-enforcerd: .*1 zone(s) found on policy \"other\"" &&

syslog_grep_count 1 "ods-enforcerd: .*Policy for ods set to default." &&
syslog_grep_count 1 "ods-enforcerd: .*Config will be output to $INSTALL_ROOT/var/opendnssec/signconf/ods.xml." &&

syslog_grep_count 1 "ods-enforcerd: .*Policy for ods1 set to default." &&
syslog_grep_count 1 "ods-enforcerd: .*Config will be output to $INSTALL_ROOT/var/opendnssec/signconf/ods1.xml." &&

syslog_grep_count 1 "ods-enforcerd: .*Policy for ods2 set to other." &&
syslog_grep_count 1 "ods-enforcerd: .*Config will be output to $INSTALL_ROOT/var/opendnssec/signconf/ods2.xml." &&

# Key the key ids and check there are no published ZSKs
log_this ods_key_list1  ods-ksmutil key list --verbose &&
ZSK_ODS_1=`log_grep -o ods_key_list1 stdout "ods .*ZSK           active" | awk '{print $9}'` &&
ZSK_ODS1_1=`log_grep -o ods_key_list1 stdout "ods1 .*ZSK           active" | awk '{print $9}'` &&
ZSK_ODS2_1=`log_grep -o ods_key_list1 stdout "ods2 .*ZSK           active" | awk '{print $9}'` &&
! log_grep ods_key_list1 stdout "ods.*ZSK.*publish" &&


################## Run again on just a single policy
export ENFORCER_TIMESHIFT='02-01-2010 13:00' &&
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -p default &&
syslog_waitfor_count $ENFORCER_WAIT 2 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*Timeshift mode detected, running once only!" &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 02-01-2010 13:00" &&

################## Check only 1 policies was enforced
syslog_grep_count 1 "ods-enforcerd: .*Will only process policy \"default\" as specified on the command line with the --policy option" &&
syslog_grep_count 2 "ods-enforcerd: .*Policy default found\." &&
syslog_grep_count 2 "ods-enforcerd: .*2 zone(s) found on policy \"default\"" &&
syslog_grep_count 1 "ods-enforcerd: .*Policy other found\." &&
syslog_grep_count 1 "ods-enforcerd: .*1 zone(s) found on policy \"other\"" &&

syslog_grep_count 2 "ods-enforcerd: .*Policy for ods set to default." &&
syslog_grep_count 2 "ods-enforcerd: .*Config will be output to $INSTALL_ROOT/var/opendnssec/signconf/ods.xml." &&

syslog_grep_count 2 "ods-enforcerd: .*Policy for ods1 set to default." &&
syslog_grep_count 2 "ods-enforcerd: .*Config will be output to $INSTALL_ROOT/var/opendnssec/signconf/ods1.xml." &&

syslog_grep_count 2 "ods-enforcerd: .*Policy for ods2 set to other." &&
syslog_grep_count 1 "ods-enforcerd: .*Skipping zone ods2 as not on specified policy \"default\"." && 
syslog_grep_count 1 "ods-enforcerd: .*Config will be output to $INSTALL_ROOT/var/opendnssec/signconf/ods2.xml." &&

#Check the keys are still active and the enforced 2 zones also have published ZSKs
log_this ods_key_list2 ods-ksmutil key list --verbose &&
log_grep ods_key_list2  stdout "ods .*ZSK           active.*$ZSK_ODS_1" &&
log_grep ods_key_list2  stdout "ods1 .*ZSK           active.*$ZSK_ODS1_1" &&
log_grep ods_key_list2  stdout "ods2 .*ZSK           active.*$ZSK_ODS2_1" &&
log_grep ods_key_list2  stdout "ods .*ZSK           publish" &&
log_grep ods_key_list2  stdout "ods1 .*ZSK           publish" &&
! log_grep ods_key_list2  stdout "ods2 .*ZSK           publish" &&

################## Run again on just the other policy
export ENFORCER_TIMESHIFT='03-01-2010 14:00' &&
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -p other &&
syslog_waitfor_count $ENFORCER_WAIT 3 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*Timeshift mode detected, running once only!" &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 03-01-2010 14:00" &&

################## Check only 1 policies was enforced
syslog_grep_count 1 "ods-enforcerd: .*Will only process policy \"other\" as specified on the command line with the --policy option" &&
syslog_grep_count 2 "ods-enforcerd: .*Policy default found\." &&
syslog_grep_count 2 "ods-enforcerd: .*2 zone(s) found on policy \"default\"" &&
syslog_grep_count 2 "ods-enforcerd: .*Policy other found\." &&
syslog_grep_count 2 "ods-enforcerd: .*1 zone(s) found on policy \"other\"" &&

syslog_grep_count 3 "ods-enforcerd: .*Zone ods found." &&
syslog_grep_count 1 "ods-enforcerd: .*Skipping zone ods as not on specified policy \"other\"." &&
syslog_grep_count 2 "ods-enforcerd: .*Config will be output to $INSTALL_ROOT/var/opendnssec/signconf/ods.xml." && 

syslog_grep_count 3 "ods-enforcerd: .*Zone ods1 found." &&
syslog_grep_count 1 "ods-enforcerd: .*Skipping zone ods1 as not on specified policy \"other\"." &&
syslog_grep_count 2 "ods-enforcerd: .*Config will be output to $INSTALL_ROOT/var/opendnssec/signconf/ods1.xml." && 

syslog_grep_count 3 "ods-enforcerd: .*Zone ods2 found." &&
syslog_grep_count 1 "ods-enforcerd: .*Skipping zone ods2 as not on specified policy \"default\"." && 
syslog_grep_count 2 "ods-enforcerd: .*Config will be output to $INSTALL_ROOT/var/opendnssec/signconf/ods2.xml." &&

# Check the keys 2 ignored zones haven't changed (which they would have if they had been enforced given the key lifetimes used) 
# but the one processed zone has changed
log_this ods_key_list2 ods-ksmutil key list --verbose &&
log_grep ods_key_list2  stdout "ods .*ZSK           active.*$ZSK_ODS_1" &&
log_grep ods_key_list2  stdout "ods1 .*ZSK           active.*$ZSK_ODS1_1" &&
log_grep ods_key_list2  stdout "ods2 .*ZSK           active.*$ZSK_ODS2_1" &&
log_grep ods_key_list2  stdout "ods .*ZSK           publish" &&
log_grep ods_key_list2  stdout "ods1 .*ZSK           publish" &&
log_grep ods_key_list2  stdout "ods2 .*ZSK           publish" &&

################## And now on a policy that doesn't exist
! log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -p bob &&

syslog_waitfor_count $ENFORCER_WAIT 1 "ods-enforcerd: .*Will only process policy \"bob\" as specified on the command line with the --policy option" &&
syslog_waitfor_count $ENFORCER_WAIT 1 "ods-enforcerd: .*Policy \"bob\" not found. Exiting." &&

################# Paranoid check that running the enforcer again now processes all 3 zones...
export ENFORCER_TIMESHIFT='04-01-2010 12:00' &&
ods_start_enforcer_timeshift &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 04-01-2010 12:00" &&

syslog_grep_count 3 "ods-enforcerd: .*Policy default found\." &&
syslog_grep_count 3 "ods-enforcerd: .*2 zone(s) found on policy \"default\"" &&
syslog_grep_count 3 "ods-enforcerd: .*Policy other found\." &&
syslog_grep_count 3 "ods-enforcerd: .*1 zone(s) found on policy \"other\"" &&

syslog_grep_count 4 "ods-enforcerd: .*Zone ods found." &&
syslog_grep_count 1 "ods-enforcerd: .*Skipping zone ods as not on specified policy \"other\"." &&
syslog_grep_count 3 "ods-enforcerd: .*Config will be output to $INSTALL_ROOT/var/opendnssec/signconf/ods.xml." && 

syslog_grep_count 4 "ods-enforcerd: .*Zone ods1 found." &&
syslog_grep_count 1 "ods-enforcerd: .*Skipping zone ods1 as not on specified policy \"other\"." &&
syslog_grep_count 3 "ods-enforcerd: .*Config will be output to $INSTALL_ROOT/var/opendnssec/signconf/ods1.xml." && 

syslog_grep_count 4 "ods-enforcerd: .*Zone ods2 found." &&
syslog_grep_count 1 "ods-enforcerd: .*Skipping zone ods2 as not on specified policy \"default\"." && 
syslog_grep_count 3 "ods-enforcerd: .*Config will be output to $INSTALL_ROOT/var/opendnssec/signconf/ods2.xml." &&


# Now check all the zones have had the active key retired
log_this ods_key_list2 ods-ksmutil key list --verbose &&
log_grep ods_key_list2  stdout "ods .*ZSK           retire.*$ZSK_ODS_1" &&
log_grep ods_key_list2  stdout "ods1 .*ZSK           retire.*$ZSK_ODS1_1" &&
log_grep ods_key_list2  stdout "ods2 .*ZSK           retire.*$ZSK_ODS2_1" &&


echo &&
echo "************ OK ******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

