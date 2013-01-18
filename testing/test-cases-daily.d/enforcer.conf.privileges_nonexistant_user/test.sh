#!/usr/bin/env bash

#TEST: Use privileges test: test for enforcer in config only and check if enforcers fails to run

#TEST: NOTE NOTE NOTE - Test system today runs under a normal user, this test needs to be changed or allowed root access to test setuid functionallity

ods_reset_env &&
echo 'Privileges have been adjusted in the conf.xml. User opendnssec1 is specified, which does not exist on the unix system.' &&
echo 'Stop the ODS-Enforcer and ODS-Signer' &&
log_this_timeout ods-control-start 60 ods-control stop &&
echo 'Clear the tmp and signed folder with the next 2 commands.' &&
echo 'Purge the keys in the SoftHSM repositories.' &&
echo 'Change the configuration with predefined xml config files.' &&
echo '' &&
echo 'Update all the configs.' &&
ods_reset_env &&
echo 'Start the ODS-Enforcer and ODS-Signer' &&
log_this_timeout ods-control-start 60 ods-control start &&
echo 'The Enforcer should fail to run when restarting ODS with the new conf.xml.' &&
echo 'Stop the ODS-Enforcer and ODS-Signer' &&
log_this_timeout ods-control-start 60 ods-control stop &&
syslog_grep 'Can'"'"'t change to opendnssec1, opendnssec to check DB write permissions' &&
return 0

ods-control stop
return 1
