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
syslog_grep_count 1 "ods-enforcerd: .*Config will be output to /home/sara/jenkins/1.3_s/workspace/root/local-test/var/opendnssec/signconf/ods.xml." &&

syslog_grep_count 1 "ods-enforcerd: .*Policy for ods1 set to default." &&
syslog_grep_count 1 "ods-enforcerd: .*Config will be output to /home/sara/jenkins/1.3_s/workspace/root/local-test/var/opendnssec/signconf/ods1.xml." &&

syslog_grep_count 1 "ods-enforcerd: .*Policy for ods2 set to other." &&
syslog_grep_count 1 "ods-enforcerd: .*Config will be output to /home/sara/jenkins/1.3_s/workspace/root/local-test/var/opendnssec/signconf/ods2.xml." &&


################## Run again on just a single policy
export ENFORCER_TIMESHIFT='01-01-2010 22:00' &&
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -p default &&
syslog_waitfor_count $ENFORCER_WAIT 2 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*Timeshift mode detected, running once only!" &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 01-01-2010 22:00" &&

################## Check only 1 policies was enforced
syslog_grep_count 1 "ods-enforcerd: .*Will only process policy \"default\" as specified on the command line with the --policy option" &&
syslog_grep_count 2 "ods-enforcerd: .*Policy default found\." &&
syslog_grep_count 2 "ods-enforcerd: .*2 zone(s) found on policy \"default\"" &&
syslog_grep_count 1 "ods-enforcerd: .*Policy other found\." &&
syslog_grep_count 1 "ods-enforcerd: .*1 zone(s) found on policy \"other\"" &&

syslog_grep_count 2 "ods-enforcerd: .*Policy for ods set to default." &&
syslog_grep_count 2 "ods-enforcerd: .*Config will be output to /home/sara/jenkins/1.3_s/workspace/root/local-test/var/opendnssec/signconf/ods.xml." &&

syslog_grep_count 2 "ods-enforcerd: .*Policy for ods1 set to default." &&
syslog_grep_count 2 "ods-enforcerd: .*Config will be output to /home/sara/jenkins/1.3_s/workspace/root/local-test/var/opendnssec/signconf/ods1.xml." &&

syslog_grep_count 2 "ods-enforcerd: .*Policy for ods2 set to other." &&
syslog_grep_count 1 "ods-enforcerd: .*Skipping zone ods2 as not on specified policy \"default\"." && 
syslog_grep_count 1 "ods-enforcerd: .*Config will be output to /home/sara/jenkins/1.3_s/workspace/root/local-test/var/opendnssec/signconf/ods2.xml." &&


################## Run again on just the other policy
export ENFORCER_TIMESHIFT='02-01-2010 12:00' &&
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -p other &&
syslog_waitfor_count $ENFORCER_WAIT 3 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*Timeshift mode detected, running once only!" &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 02-01-2010 12:00" &&

################## Check only 1 policies was enforced
syslog_grep_count 1 "ods-enforcerd: .*Will only process policy \"other\" as specified on the command line with the --policy option" &&
syslog_grep_count 2 "ods-enforcerd: .*Policy default found\." &&
syslog_grep_count 2 "ods-enforcerd: .*2 zone(s) found on policy \"default\"" &&
syslog_grep_count 2 "ods-enforcerd: .*Policy other found\." &&
syslog_grep_count 2 "ods-enforcerd: .*1 zone(s) found on policy \"other\"" &&

syslog_grep_count 3 "ods-enforcerd: .*Zone ods found." &&
syslog_grep_count 1 "ods-enforcerd: .*Skipping zone ods as not on specified policy \"other\"." &&
syslog_grep_count 2 "ods-enforcerd: .*Config will be output to /home/sara/jenkins/1.3_s/workspace/root/local-test/var/opendnssec/signconf/ods.xml." && 

syslog_grep_count 3 "ods-enforcerd: .*Zone ods1 found." &&
syslog_grep_count 1 "ods-enforcerd: .*Skipping zone ods1 as not on specified policy \"other\"." &&
syslog_grep_count 2 "ods-enforcerd: .*Config will be output to /home/sara/jenkins/1.3_s/workspace/root/local-test/var/opendnssec/signconf/ods1.xml." && 

syslog_grep_count 3 "ods-enforcerd: .*Zone ods2 found." &&
syslog_grep_count 1 "ods-enforcerd: .*Skipping zone ods2 as not on specified policy \"default\"." && 
syslog_grep_count 2 "ods-enforcerd: .*Config will be output to /home/sara/jenkins/1.3_s/workspace/root/local-test/var/opendnssec/signconf/ods2.xml." &&

################## And now on a policy that doesn't exist
! log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -p bob &&
syslog_waitfor_count $ENFORCER_WAIT 3 'ods-enforcerd: .*all done' &&

syslog_grep_count 1 "ods-enforcerd: .*Will only process policy \"bob\" as specified on the command line with the --policy option" &&
syslog_grep_count 1 "ods-enforcerd: .*Policy \"bob\" not found. Exiting." &&

################# Paranoid check that running the enforcer again now processes all 3 zones...
ods_start_enforcer_timeshift &&

syslog_grep_count 3 "ods-enforcerd: .*Policy default found\." &&
syslog_grep_count 3 "ods-enforcerd: .*2 zone(s) found on policy \"default\"" &&
syslog_grep_count 3 "ods-enforcerd: .*Policy other found\." &&
syslog_grep_count 3 "ods-enforcerd: .*1 zone(s) found on policy \"other\"" &&

syslog_grep_count 4 "ods-enforcerd: .*Zone ods found." &&
syslog_grep_count 1 "ods-enforcerd: .*Skipping zone ods as not on specified policy \"other\"." &&
syslog_grep_count 3 "ods-enforcerd: .*Config will be output to /home/sara/jenkins/1.3_s/workspace/root/local-test/var/opendnssec/signconf/ods.xml." && 

syslog_grep_count 4 "ods-enforcerd: .*Zone ods1 found." &&
syslog_grep_count 1 "ods-enforcerd: .*Skipping zone ods1 as not on specified policy \"other\"." &&
syslog_grep_count 3 "ods-enforcerd: .*Config will be output to /home/sara/jenkins/1.3_s/workspace/root/local-test/var/opendnssec/signconf/ods1.xml." && 

syslog_grep_count 4 "ods-enforcerd: .*Zone ods2 found." &&
syslog_grep_count 1 "ods-enforcerd: .*Skipping zone ods2 as not on specified policy \"default\"." && 
syslog_grep_count 3 "ods-enforcerd: .*Config will be output to /home/sara/jenkins/1.3_s/workspace/root/local-test/var/opendnssec/signconf/ods2.xml." &&



echo &&
echo "************ OK ******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

