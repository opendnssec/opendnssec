#!/usr/bin/env bash
#
#TEST: Test to import/export zone list. 

#DISABLED: ON FREEBSD - due to pthread seg fault on freebsd64

case "$DISTRIBUTION" in
    freebsd )
        return 0
        ;;
esac

ods_reset_env &&
log_this_timeout ods-control-start 30 ods-control start &&
syslog_waitfor 60 'ods-enforcerd: .*\[engine\] enforcer started' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&
ods_setup_env &&

#export
log_this ods-enforcer-export_zonelist ods-enforcer zonelist export &&
log_grep ods-enforcer-export_zonelist   stdout "<Zone name=\"ods1\">" &&
log_grep ods-enforcer-export_zonelist   stdout "<Policy>default</Policy>" &&
log_grep ods-enforcer-export_zonelist   stdout "<SignerConfiguration>${INSTALL_ROOT}/var/opendnssec/signconf/ods1.xml</SignerConfiguration>" &&
log_grep ods-enforcer-export_zonelist   stdout "<Adapter type=\"File\">" &&
log_grep ods-enforcer-export_zonelist   stdout "${INSTALL_ROOT}/var/opendnssec/unsigned/ods1" &&
log_grep ods-enforcer-export_zonelist   stdout "${INSTALL_ROOT}/var/opendnssec/signed/ods1" &&

ods_setup_conf zonelist.xml zonelist2.xml &&

##import
log_this ods-enforcer-import_zonelist ods-enforcer zonelist import &&
log_grep ods-enforcer-import_zonelist   stdout "zonelist filename set to ${INSTALL_ROOT}/etc/opendnssec/zonelist.xml" &&
log_grep ods-enforcer-import_zonelist   stdout "Zone: ods1 not exist in zonelist.xml, delete it from database" &&
log_grep ods-enforcer-import_zonelist   stdout "zone 'ods1' deleted successfully" &&
log_grep ods-enforcer-import_zonelist   stdout "Zone ods3 found in zonelist.xml; policy set to default" &&
log_grep ods-enforcer-import_zonelist   stdout "Zone: ods3 not found in database, insert it" &&

log_this ods-enforcer-export_zonelist2 ods-enforcer zonelist export &&
log_grep ods-enforcer-export_zonelist2   stdout "<Zone name=\"ods3\">" &&
log_grep ods-enforcer-export_zonelist2   stdout "<Policy>default</Policy>" &&
log_grep ods-enforcer-export_zonelist2   stdout "<SignerConfiguration>${INSTALL_ROOT}/var/opendnssec/signconf/ods3.xml</SignerConfiguration>" &&
log_grep ods-enforcer-export_zonelist2   stdout "<Adapter type=\"File\">" &&
log_grep ods-enforcer-export_zonelist2   stdout "${INSTALL_ROOT}/var/opendnssec/unsigned/ods3" &&
log_grep ods-enforcer-export_zonelist2   stdout "${INSTALL_ROOT}/var/opendnssec/signed/ods3" &&

#shutdown
log_this_timeout ods-control-stop 30 ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*\[engine\] enforcer shutdown' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
return 0

ods_kill
return 1
