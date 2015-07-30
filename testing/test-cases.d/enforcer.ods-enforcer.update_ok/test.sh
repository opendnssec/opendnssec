#!/usr/bin/env bash

#TEST: Test that enforcer update call HUPs the enforcerd

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

# Run the enforcer so that keys are created
ods_start_enforcer &&

# Add our new zone.
log_this_timeout ods-enforcer-zone-add 15 ods-enforcer zone add -z ods2 &&

# This zone should not have been picked up by the enforcer yet, so it should be in the list...
log_this ods-enforcer-zone-list1 ods-enforcer zone list &&
log_grep ods-enforcer-zone-list1 stdout 'ods2[[:space:]].*default' &&

# ... but it shouldn't have keys
#log_this ods-enforcer-key-list1 ods-enforcer key list &&
#log_grep ods-enforcer-key-list1 stdout 'ods                             KSK           publish' &&
#log_grep ods-enforcer-key-list1 stdout 'ods                             ZSK           active' &&
#! log_grep ods-enforcer-key-list1 stdout 'ods2                            KSK           publish' &&
#! log_grep ods-enforcer-key-list1 stdout 'ods2                            ZSK           active' &&

# Check the presence, and absence, of signconfs
#test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
#! test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&

# Count how many runs the enforcer has done
#ods_enforcer_count_starts &&

# Now issue the update command
#log_this ods-enforcer-update ods-enforcer update zonelist &&
#log_grep ods-enforcer-update stdout 'Zone ods2 found; policy set to default'
#log_grep ods-enforcer-update stdout 'Notifying enforcer of new database...'
#! log_grep ods-enforcer-update stdout 'Cannot find PID file'
#! log_grep ods-enforcer-update stdout 'Could not HUP ods-enforcerd'

# We should see the enforcer wake up and run
#ods_enforcer_waitfor_starts $(( ODS_ENFORCER_START_COUNT + 1 )) &&

# Check the zone is there
#log_this ods-enforcer-zone-list2 ods-enforcer zone list &&
#log_grep ods-enforcer-zone-list2 stdout 'ods2[[:space:]].*default' &&

# There need to be five leaps,
# - one to add the ods zone (the ods2 zone is added as a consequence of
# the zone add command)
# - one to put the ods2 ZSK from generated to publish state)
# - another one for the ods KSK to publish (since they are not
# added at the same time they will have separate transitions
# - one to put to ZSK to active and KSK to ready for ods2
# - and finally one to to the same for ods zone
# note that this relies heavily on the internal workings of the
# enforcer.  If it decides to break up the now combined ZSK and
# KSK transitions, or do ods and ods2 at the same time, the test
# is too fragile and will break.
# It would be much better to leap incrementally (i.e. also do
# the intermediate steps) to the expected time from the policy the
# keys are in the right state, regardless of how many times a 
# leap should take place.
# And the sleep commands necessary are awfull of course to guard
# against the asynchronisity of the commands execution.

sleep 5 &&
log_this ods-enforcer-time-leap ods-enforcer time leap &&
sleep 5 &&
log_this ods-enforcer-time-leap ods-enforcer time leap &&
sleep 5 &&
log_this ods-enforcer-time-leap ods-enforcer time leap &&
sleep 5 &&
log_this ods-enforcer-time-leap ods-enforcer time leap &&
sleep 5 &&
log_this ods-enforcer-time-leap ods-enforcer time leap &&
sleep 5 &&

# Check that we have 2 keys per zone
log_this ods-enforcer-key-list2 ods-enforcer key list &&
log_grep ods-enforcer-key-list2 stdout 'ods[[:space:]].*KSK[[:space:]].*ready' &&
log_grep ods-enforcer-key-list2 stdout 'ods[[:space:]].*ZSK[[:space:]].*active' &&
log_grep ods-enforcer-key-list2 stdout 'ods2[[:space:]].*KSK[[:space:]].*ready' &&
log_grep ods-enforcer-key-list2 stdout 'ods2[[:space:]].*ZSK[[:space:]].*active' &&

# Check the presence of signconfs
test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&


ods_stop_enforcer &&
return 0

ods_kill
return 1
