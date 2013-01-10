#!/usr/bin/env bash

#TEST: Test that a ksmutil update call HUPs the enforcerd

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

# Run the enforcer so that keys are created
log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&

# Add our new zone.
log_this_timeout ods-ksmutil-zone-add 5 ods-ksmutil zone add -z ods2 &&


# This zone should not have been picked up by the enforcer yet, so it should be in the list...
log_this ods-ksmutil-zone-list1 ods-ksmutil zone list &&
log_grep ods-ksmutil-zone-list1 stdout 'Found Zone: ods2; on policy default' &&

# ... but it shouldn't have keys
log_this ods-ksmutil-key-list1 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list1 stdout 'ods                             KSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'ods                             ZSK           active' &&
! log_grep ods-ksmutil-key-list1 stdout 'ods2                            KSK           publish' &&
! log_grep ods-ksmutil-key-list1 stdout 'ods2                            ZSK           active' &&

# Check the presence, and absence, of signconfs
test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
! test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&


# Now issue the update command
log_this ods-ksmutil-update ods-ksmutil update zonelist &&
log_grep ods-ksmutil-update stdout 'Zone ods2 found; policy set to default'
log_grep ods-ksmutil-update stdout 'Notifying enforcer of new database...'
! log_grep ods-ksmutil-update stdout 'Cannot find PID file'
! log_grep ods-ksmutil-update stdout 'Could not HUP ods-enforcerd'

# We should see the enforcer wake up ...
syslog_waitfor 5 'HSM connection open' &&

# ... and finish
syslog_waitfor_count 60 2 'ods-enforcerd: .*Sleeping for' &&

# Check the zone is there
log_this ods-ksmutil-zone-list2 ods-ksmutil zone list &&
log_grep ods-ksmutil-zone-list2 stdout 'Found Zone: ods2; on policy default' &&

# Check that we have 2 keys per zone
log_this ods-ksmutil-key-list2 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list2 stdout 'ods                             KSK           publish' &&
log_grep ods-ksmutil-key-list2 stdout 'ods                             ZSK           active' &&
log_grep ods-ksmutil-key-list2 stdout 'ods2                            KSK           publish' &&
log_grep ods-ksmutil-key-list2 stdout 'ods2                            ZSK           active' &&

# Check the presence of signconfs
test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&


log_this_timeout ods-control-enforcer-stop 60 ods-control enforcer stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
return 0

ods_kill
return 1
