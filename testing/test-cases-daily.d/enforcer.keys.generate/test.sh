#!/usr/bin/env bash
#
#TEST: Test to check the operation of the 'ods-ksmutil key generate' command
#TEST: including the new -zonecount parameter

#DISABLED: ON FREEBSD - due to pthread seg fault on freebsd64

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

case "$DISTRIBUTION" in
	freebsd )
		return 0
		;;
esac

ods_reset_env &&

##################  Default behaviour ###########################
# Fail with no zones
log_this ods-ksmutil-no_zones_policy   ods-ksmutil key generate --interval PT40M --policy  Policy1 &&
log_grep ods-ksmutil-no_zones_policy   stdout "Info: 0 zone(s) found on policy \"Policy1\"" &&
log_grep ods-ksmutil-no_zones_policy   stdout "No zones on policy Policy1, skipping..." &&

# Add a zone
log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil zone add --zone ods --input $INSTALL_ROOT/var/opendnssec/unsigned/ods.xml --policy Policy1 --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods.xml &&
log_grep ods-ksmutil-setup_zone_and_keys   stdout "Imported zone: ods" &&
log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil zone list &&
log_grep ods-ksmutil-setup_zone_and_keys   stdout "Found Zone: ods; on policy Policy1" &&

# Generate keys
echo "y" | log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil key generate --interval PT4M --policy  Policy1 &&
log_grep ods-ksmutil-setup_zone_and_keys   stdout "Info: 1 zone(s) found on policy \"Policy1\"" &&
log_grep ods-ksmutil-setup_zone_and_keys   stdout "This will create 2 KSKs (2048 bits) and 5 ZSKs (2048 bits)" &&
log_this ods-ksmutil-keylist1   ods-hsmutil list &&
log_grep ods-ksmutil-keylist1 stdout "7 keys found." && 

####

##################  Using zone count ###########################
# Fail with 0 zone count
! log_this ods-ksmutil-zonecount_fail   ods-ksmutil key generate --interval PT40M --policy  Policy2 --zonecount 0 &&
log_grep ods-ksmutil-zonecount_fail   stdout "Error: zonecount parameter value of 0 is invalid - the value must be greater than 0" &&
# Fail with non-numeric zone count
! log_this ods-ksmutil-zonecount_fail   ods-ksmutil key generate --interval PT40M --policy  Policy2 --zonecount bob &&
log_grep ods-ksmutil-zonecount_fail   stdout "Error: zonecount \"bob\"; should be numeric only" &&

# Generate keys
echo "y" | log_this ods-ksmutil-zonecount   ods-ksmutil key generate --interval PT40M --policy Policy2 --zonecount 3 &&
log_grep ods-ksmutil-zonecount   stdout "Info: 0 zone(s) found on policy \"Policy2\"" &&
log_grep ods-ksmutil-zonecount   stdout "Info: Keys will actually be generated for 3 zone(s) as specified by zone count parameter" &&
log_grep ods-ksmutil-zonecount   stdout "This will create 9 KSKs (2048 bits) and 18 ZSKs (2048 bits)" &&
log_this ods-ksmutil-keylist2   ods-hsmutil list &&
log_grep ods-ksmutil-keylist2 stdout "34 keys found." && 

return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

