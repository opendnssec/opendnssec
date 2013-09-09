#!/usr/bin/env bash
#
#TEST: Test to add/delete zone. 

ods_reset_env &&
log_this_timeout ods-control-start 30 ods-control start &&
syslog_waitfor 60 'ods-enforcerd: .*\[engine\] enforcer started' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&
ods_setup_env &&

#no zone configured
log_this ods-enforcer-zone_list1 ods-enforcer zone list &&
log_grep ods-enforcer-zone_list1  stdout    "I have no zones configured" &&

#add zone ods1
log_this ods-enforcer-zone_add_ods1 ods-enforcer zone add -z ods1 -p default -i ${INSTALL_ROOT}/var/opendnssec/unsigned/ods1 -o ${INSTALL_ROOT}/var/opendnssec/signed/ods1 &&
log_grep ods-enforcer-zone_add_ods1 stdout "Imported zone:.*ods1" &&

#check if ods1 is in zone list
log_this ods-enforcer-zone_list2 ods-enforcer zone list &&
log_grep ods-enforcer-zone_list2 stdout "ods1.*default.*${INSTALL_ROOT}/var/opendnssec/signconf/ods1.xml" &&

#add zone ods2
log_this ods-enforcer-zone_add_ods2 ods-enforcer zone add -z ods2 -p default -i ${INSTALL_ROOT}/var/opendnssec/unsigned/ods2 -o ${INSTALL_ROOT}/var/opendnssec/signed/ods2 &&
log_grep ods-enforcer-zone_add_ods2 stdout "Imported zone:.*ods2" &&

#check if ods1 and ods2 are in zone list
log_this ods-enforcer-zone_list3 ods-enforcer zone list &&
log_grep ods-enforcer-zone_list3 stdout "ods2.*default.*${INSTALL_ROOT}/var/opendnssec/signconf/ods2.xml" &&
log_grep ods-enforcer-zone_list3 stdout "ods1.*default.*${INSTALL_ROOT}/var/opendnssec/signconf/ods1.xml" &&

#re-add exist zone
log_this ods-enforcer-zone_readd_ods2 ods-enforcer zone add -z ods2 -p default -i ${INSTALL_ROOT}/var/opendnssec/unsigned/ods2 -o ${INSTALL_ROOT}/var/opendnssec/signed/ods2 &&
log_grep ods-enforcer-zone_readd_ods2 stdout "Failed to Import zone ods2; it already exists" &&

#check if ods1 and ods2 are in zone list
log_this ods-enforcer-zone_list4 ods-enforcer zone list &&
log_grep ods-enforcer-zone_list4 stdout "ods2.*default.*${INSTALL_ROOT}/var/opendnssec/signconf/ods2.xml" &&
log_grep ods-enforcer-zone_list4 stdout "ods1.*default.*${INSTALL_ROOT}/var/opendnssec/signconf/ods1.xml" &&

#delete zone ods1
log_this ods-enforcer-zone_delete_ods1 ods-enforcer zone delete -z ods1 --force &&
log_grep ods-enforcer-zone_delete_ods1  stdout "zone.*ods1.*deleted successfully"

#check ods2 is in zone list
log_this ods-enforcer-zone_list5 ods-enforcer zone list &&
log_grep ods-enforcer-zone_list5 stdout "ods2.*default.*${INSTALL_ROOT}/var/opendnssec/signconf/ods2.xml" &&

#delete non-exist zone
log_this ods-enforcer-zone_delete_ods3 ods-enforcer zone delete -z ods3 --force &&
log_grep ods-enforcer-zone_delete_ods3 stdout "Couldn't find zone.*ods3"

#check ods2 is in zone list
log_this ods-enforcer-zone_list6 ods-enforcer zone list &&
log_grep ods-enforcer-zone_list6 stdout "ods2.*default.*${INSTALL_ROOT}/var/opendnssec/signconf/ods2.xml" &&

#delete zone ods2 
log_this ods-enforcer-zone_delete_ods2 ods-enforcer zone delete -z ods2 --force &&
log_grep ods-enforcer-zone_delete_ods2  stdout "zone.*ods2.*deleted successfully"

#no zone should be here
log_this ods-enforcer-zone_list7 ods-enforcer zone list &&
log_grep ods-enforcer-zone_list7  stdout    "I have no zones configured" &&

#shutdown
log_this_timeout ods-control-stop 30 ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*\[engine\] enforcer shutdown' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
return 0

ods_kill
return 1
