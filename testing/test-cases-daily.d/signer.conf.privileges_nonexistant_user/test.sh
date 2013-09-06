#!/usr/bin/env bash

#TEST: Use privileges test:test for signer in config only and check if signer fails to run

#TEST: NOTE NOTE NOTE - Test system today runs under a normal user, this test needs to be changed or allowed root access to test setuid functionallity


ods_reset_env &&

echo 'Privileges have been adjusted for the signer in the conf.xml. User = opendnssec; Group = opendnssec. This user and group do not have acces to the correct folder.' &&
echo 'Stop the ODS-Enforcer and ODS-Signer' &&
log_this_timeout ods-control-start 60 ods-control stop &&
echo 'Clear the tmp and signed folder with the next 2 commands.' &&
echo 'Purge the keys in the SoftHSM repositories.' &&
echo 'Rebuild ODS with SQLlite database.' &&
echo 'Change the configuration with predefined xml config files.' &&
echo 'Run setup for rebuild of database' &&
echo 'Update all the configs.' &&
ods_reset_env &&
echo 'Change the configuration with predefined xml config files for this testcase.' &&
echo 'Update all the configs.' &&
ods_reset_env &&
echo 'Stop the ODS-Enforcer and ODS-Signer' &&
log_this_timeout ods-control-start 60 ods-control start &&
echo 'Stop the ODS-Enforcer and ODS-Signer' &&
log_this_timeout ods-control-start 60 ods-control stop &&
syslog_grep 'setup failed: unable to write pid file' &&
echo 'Change the configuration with predefined original conf.xml file.' &&
echo 'Update all the configs.' &&
ods_reset_env &&
return 0

ods-control stop
return 1
