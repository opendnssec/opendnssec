#!/usr/bin/env bash

#TEST: Use privileges test:test for signer and /tmp and check if signer runs without errors

#TEST: NOTE NOTE NOTE - Test system today runs under a normal user, this test needs to be changed or allowed root access to test setuid functionallity

#CATEGORY: signer-privileges-user_exists

ods_reset_env &&
echo 'Privileges have been adjusted for the signer in the conf.xml. User = ods; Group = ods. This user and group do not have acces to the correct folder.' &&
echo 'Stop the ODS-Enforcer and ODS-Signer' &&
log_this_timeout ods-control-start 30 ods-control stop &&
echo 'Clear the tmp and signed folder with the next 2 commands.' &&
echo 'Purge the keys in the SoftHSM repositories.' &&
echo 'Change the rights for the kasp.db file to user ods.' &&
sudo chown ods /var/lib/opendnssec/db/kasp.db &&
echo 'Change the configuration with predefined xml config files.' &&
echo 'Update all the configs.' &&
ods_reset_env &&
echo 'Start enforcer' &&
log_this_timeout ods-control-start 30 ods-control start &&
syslog_grep 'ods-signerd: cmdhandler: zone ods scheduled for immediate re-sign' &&
echo 'Stop the ODS-Enforcer and ODS-Signer' &&
log_this_timeout ods-control-start 30 ods-control stop &&
echo 'Change the configuration with predefined original conf.xml file and the original rights for the kasp.db file.' &&
sudo chown root/var/lib/opendnssec/db/kasp.db &&
echo 'Update all the configs.' &&
ods_reset_env &&
return 0

ods-control stop
return 1
