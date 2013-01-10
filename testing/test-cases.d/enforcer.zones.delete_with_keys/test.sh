#!/usr/bin/env bash

#TEST: Test deletion of zones with keys.

#CATEGORY: enforcer-zones-delete_zones_with_keys

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

# Add our test zone. We already have the standard one and a "spare" one on a different policy
log_this_timeout ods-ksmutil-zone-add 5 ods-ksmutil zone add -z test.delete --policy non-default &&

# Run the enforcer so that keys are created
log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&

# Check the presence of all signconfs
test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
test -f "$INSTALL_ROOT/var/opendnssec/signconf/test.keep.xml" &&
test -f "$INSTALL_ROOT/var/opendnssec/signconf/test.delete.xml" &&

# Check the zone is there
log_this ods-ksmutil-zone-list1 ods-ksmutil zone list &&
log_grep ods-ksmutil-zone-list1 stdout 'Found Zone: test.delete; on policy non-default' &&

# Check that we have 2 keys per zone
log_this ods-ksmutil-key-list1 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list1 stdout 'ods                             KSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'ods                             ZSK           active' &&
log_grep ods-ksmutil-key-list1 stdout 'ods2                            KSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'ods2                            ZSK           active' &&
log_grep ods-ksmutil-key-list1 stdout 'test.keep                       KSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'test.keep                       ZSK           active' &&
log_grep ods-ksmutil-key-list1 stdout 'test.delete                     KSK           publish' &&
log_grep ods-ksmutil-key-list1 stdout 'test.delete                     ZSK           active' &&

# Delete our first zone (from non-shared key policy)
log_this_timeout ods-ksmutil-zone-del 5 ods-ksmutil zone delete -z test.delete &&

# Check the zone is _not_ there
log_this ods-ksmutil-zone-list2 ods-ksmutil zone list &&
! log_grep ods-ksmutil-zone-list2 stdout 'Found Zone: test.delete; on policy non-default' &&

# Check that we still have 2 keys per remaining zone
log_this ods-ksmutil-key-list2 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list2 stdout 'ods                             KSK           publish' &&
log_grep ods-ksmutil-key-list2 stdout 'ods                             ZSK           active' &&
log_grep ods-ksmutil-key-list2 stdout 'ods2                            KSK           publish' &&
log_grep ods-ksmutil-key-list2 stdout 'ods2                            ZSK           active' &&
log_grep ods-ksmutil-key-list2 stdout 'test.keep                       KSK           publish' &&
log_grep ods-ksmutil-key-list2 stdout 'test.keep                       ZSK           active' &&
! log_grep ods-ksmutil-key-list2 stdout 'test.delete                     KSK           publish' &&
! log_grep ods-ksmutil-key-list2 stdout 'test.delete                     ZSK           active' &&


# Delete our second zone (from shared key policy)
log_this_timeout ods-ksmutil-zone-del 5 ods-ksmutil zone delete -z ods2 &&

# Check the zone is _not_ there
log_this ods-ksmutil-zone-list3 ods-ksmutil zone list &&
! log_grep ods-ksmutil-zone-list3 stdout 'Found Zone: ods2; on policy default' &&

# Check that we still have 2 keys per remaining zone
log_this ods-ksmutil-key-list3 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list3 stdout 'ods                             KSK           publish' &&
log_grep ods-ksmutil-key-list3 stdout 'ods                             ZSK           active' &&
! log_grep ods-ksmutil-key-list3 stdout 'ods2                            KSK           publish' &&
! log_grep ods-ksmutil-key-list3 stdout 'ods2                            ZSK           active' &&
log_grep ods-ksmutil-key-list3 stdout 'test.keep                       KSK           publish' &&
log_grep ods-ksmutil-key-list3 stdout 'test.keep                       ZSK           active' &&
! log_grep ods-ksmutil-key-list3 stdout 'test.delete                     KSK           publish' &&
! log_grep ods-ksmutil-key-list3 stdout 'test.delete                     ZSK           active' &&

# Finally, delete the remaining zones
echo "y" | log_this ods-ksmutil-zone-del ods-ksmutil zone delete --all &&
# Check the zone is _not_ there
log_this ods-ksmutil-zone-list4 ods-ksmutil zone list &&
log_grep ods-ksmutil-zone-list4 stdout 'No zones in DB or zonelist.' &&

log_this_timeout ods-control-enforcer-stop 60 ods-control enforcer stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
return 0

ods_kill
return 1
