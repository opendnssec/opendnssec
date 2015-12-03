#!/usr/bin/env bash

#TEST: Test deletion of zones with keys.

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

# Run the enforcer so that keys are created
ods_start_enforcer &&

# Add our test zone. We already have the standard one and a "spare" one on a different policy
log_this_timeout ods-enforcer-zone-add 30 ods-enforcer zone add -z test.delete --policy non-default &&
# and wait for all the keys and signconf files to have been generated
ods_waitfor_keys &&
ods_enforcer_idle &&

# Check the presence of all signconfs
test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
test -f "$INSTALL_ROOT/var/opendnssec/signconf/test.keep.xml" &&
test -f "$INSTALL_ROOT/var/opendnssec/signconf/test.delete.xml" &&

# Check the zone is there
log_this ods-enforcer-zone-list1 ods-enforcer zone list &&
log_grep ods-enforcer-zone-list1 stdout 'test.delete[[:space:]]*non-default' &&

# Now get the keys of all zones upgraded to the next stable state
ods_enforcer_leap_to 86400 &&

# Check that we have 2 keys per zone in the state we just forced it into
log_this ods-enforcer-key-list1 ods-enforcer key list &&
log_grep ods-enforcer-key-list1 stdout 'ods[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list1 stdout 'ods[[:space:]]*ZSK[[:space:]]*active' &&
log_grep ods-enforcer-key-list1 stdout 'ods2[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list1 stdout 'ods2[[:space:]]*ZSK[[:space:]]*active' &&
log_grep ods-enforcer-key-list1 stdout 'test.keep[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list1 stdout 'test.keep[[:space:]]*ZSK[[:space:]]*active' &&
log_grep ods-enforcer-key-list1 stdout 'test.delete[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list1 stdout 'test.delete[[:space:]]*ZSK[[:space:]]*active' &&

# Delete our first zone (from non-shared key policy)
ods_enforcer_idle &&
log_this_timeout ods-enforcer-zone-del 30 ods-enforcer zone delete -z test.delete &&
ods_enforcer_idle &&

# Check the zone is _not_ there
log_this ods-enforcer-zone-list2 ods-enforcer zone list &&
! log_grep ods-enforcer-zone-list2 stdout 'test.delete[[:space:]]*non-default' &&

# Check that we still have 2 keys per remaining zone
log_this ods-enforcer-key-list2 ods-enforcer key list &&
log_grep ods-enforcer-key-list2 stdout 'ods[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list2 stdout 'ods[[:space:]]*ZSK[[:space:]]*active' &&
log_grep ods-enforcer-key-list2 stdout 'ods2[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list2 stdout 'ods2[[:space:]]*ZSK[[:space:]]*active' &&
log_grep ods-enforcer-key-list2 stdout 'test.keep[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list2 stdout 'test.keep[[:space:]]*ZSK[[:space:]]*active' &&
! log_grep ods-enforcer-key-list2 stdout 'test.delete[[:space:]]*KSK[[:space:]]*ready' &&
! log_grep ods-enforcer-key-list2 stdout 'test.delete[[:space:]]*ZSK[[:space:]]*active' &&


# Delete our second zone (from shared key policy)
ods_enforcer_idle &&
log_this_timeout ods-enforcer-zone-del 30 ods-enforcer zone delete -z ods2 &&
ods_enforcer_idle &&

# Check the zone is _not_ there
log_this ods-enforcer-zone-list3 ods-enforcer zone list &&
! log_grep ods-enforcer-zone-list3 stdout 'ods2[[:space:]]*default' &&

# Check that we still have 2 keys per remaining zone
log_this ods-enforcer-key-list3 ods-enforcer key list &&
log_grep ods-enforcer-key-list3 stdout 'ods[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list3 stdout 'ods[[:space:]]*ZSK[[:space:]]*active' &&
! log_grep ods-enforcer-key-list3 stdout 'ods2[[:space:]]*KSK[[:space:]]*ready' &&
! log_grep ods-enforcer-key-list3 stdout 'ods2[[:space:]]*ZSK[[:space:]]*active' &&
log_grep ods-enforcer-key-list3 stdout 'test.keep[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list3 stdout 'test.keep[[:space:]]*ZSK[[:space:]]*active' &&
! log_grep ods-enforcer-key-list3 stdout 'test.delete[[:space:]]*KSK[[:space:]]*ready' &&
! log_grep ods-enforcer-key-list3 stdout 'test.delete[[:space:]]*ZSK[[:space:]]*active' &&

# Finally, delete the remaining zones
ods_enforcer_idle &&
log_this ods-enforcer-zone-del ods-enforcer zone delete --all &&
ods_enforcer_idle &&

# Check the zone is _not_ there
log_this ods-enforcer-zone-list4 ods-enforcer zone list &&
log_grep ods-enforcer-zone-list4 stdout 'No zones in database' &&

# Also try to delete a zone immediately after having added it, with
# keys still in the generate state.
log_this_timeout ods-enforcer-zone-add 30 ods-enforcer zone add -z test.delete --policy non-default &&
# sleep required due to issue OPENDNSSEC-687, so this is in fact a bug
#sleep 30 &&
ods_waitfor_keys &&

ods_enforcer_idle &&
log_this_timeout ods-enforcer-zone-del 30 ods-enforcer zone delete -z test.delete &&
ods_enforcer_idle &&

ods_stop_enforcer &&
return 0

echo "################## ERROR: CURRENT STATE ###########################"
echo "DEBUG: " && ods-enforcer zone list
echo "DEBUG: " && ods-enforcer key list -d -p
echo "DEBUG: " && ods-enforcer key list -v
echo "DEBUG: " && ods-enforcer queue

echo
echo "************ERROR******************"
echo

ods_kill
return 1
