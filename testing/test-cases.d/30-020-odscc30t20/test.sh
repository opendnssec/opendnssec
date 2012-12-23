#!/usr/bin/env bash

#TEST: Use privileges test: test for enforcer and kasp.db and check if enforcers runs without errors

#TEST: NOTE NOTE NOTE - Test system today runs under a normal user, this test needs to be changed or allowed root access to test setuid functionallity

#CATEGORY: enforcer-privileges-user_exists

ods_reset_env &&
echo 'Privileges have been adjusted in the conf.xml. User opendnssec is specified, which exists on the unix system.' &&
echo 'Stop the ODS-Enforcer and ODS-Signer' &&
log_this_timeout ods-control-start 30 ods-control stop &&
echo 'Clear the tmp and signed folder with the next 2 commands.' &&
echo 'Purge the keys in the SoftHSM repositories.' &&
echo 'Change the configuration with predefined xml config files.' &&
echo '' &&
echo 'Update all the configs.' &&
ods_reset_env &&
echo 'Start the ODS-Enforcer and ODS-Signer' &&
log_this_timeout ods-control-start 30 ods-control start &&
echo 'The Enforcer should start up succesfully when restarting ODS with the new conf.xml.' &&
syslog_grep 'enforcer started' &&
syslog_grep '' &&
return 0

ods-control stop
return 1
