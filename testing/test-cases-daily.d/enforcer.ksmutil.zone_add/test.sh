#!/usr/bin/env bash
#
#TEST: Test that the ods-ksmutil zone add works correctly
#TEST: Also test that 'basic' zonelist import/export works (no incrementatl changes tested)

local ignore_blank_lines=" -B "
case "$DISTRIBUTION" in
	sunos | \
	openbsd )
		ignore_blank_lines="-b"
		;;
esac

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
else 
        ods_setup_conf conf.xml conf.xml
fi &&

ods_reset_env &&

# First, fix up the install root in the gold files
eval sed -e 's#install_dir#$INSTALL_ROOT#' zonelist.xml.gold > zonelist.xml.gold_local && 
eval sed -e 's#install_dir#$INSTALL_ROOT#' zonelist.xml.gold_export > zonelist.xml.gold_export_local &&

log_this ods-ksmutil-zone_none   ods-ksmutil zone list &&
log_grep ods-ksmutil-zone_none   stdout "No zones in DB or zonelist." &&


##################  TEST:  Zone add success ###########################
#0. Test all default
log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods0 &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone:.*ods0" &&

#1. Test existing policy
log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods1 --policy Policy1 &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone:.*ods1" &&

# Test default input type and file
log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods2 --policy Policy1 --input $INSTALL_ROOT/var/opendnssec/unsigned/ods2 &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone:.*ods2" &&

#2. Test more parameters
log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods3 --input $INSTALL_ROOT/var/opendnssec/unsigned/ods3 --output $INSTALL_ROOT/var/opendnssec/signed/ods3  &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone:.*ods3" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods4 --input $INSTALL_ROOT/var/opendnssec/unsigned/ods4 --output $INSTALL_ROOT/var/opendnssec/signed/ods4 --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods4_.xml &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone:.*ods4" &&


log_this ods-ksmutil-zone_add_list   ods-ksmutil zone list &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods0; on policy default" &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods1; on policy Policy1" &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods2; on policy Policy1" &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods3; on policy default" &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods4; on policy default" &&

##################  TEST:  Zone add failures/warnings ###########################

# Test re-add of of existing zone
! log_this ods-ksmutil-zone_add_bad   ods-ksmutil zone add --zone ods1 --policy Policy1 &&
log_grep ods-ksmutil-zone_add_bad stdout "Failed to Import zone ods1; it already exists" &&

#3. Test noneexistent policy 
! log_this ods-ksmutil-zone_add_bad   ods-ksmutil zone add --zone ods5 --policy NonexistentPolicy &&
log_grep ods-ksmutil-zone_add_bad   stdout "Error, can't find policy : NonexistentPolicy" &&

#4. Test bad parameter
! log_this ods-ksmutil-zone_add_bad   ods-ksmutil zone &&
log_grep ods-ksmutil-zone_add_bad   stderr "usage: ods-ksmutil \[-c <config> | --config <config>\] zone" &&

#5. Test none exist input file
log_this ods-ksmutil-zone_add_bad   ods-ksmutil zone add --zone ods5 --input $INSTALL_ROOT/var/opendnssec/unsigned/ods5  &&
#log_grep ods-ksmutil-zone_add_bad   stdout "WARNING: The input file $INSTALL_ROOT/var/opendnssec/unsigned/ods11 for zone ods11 does not currently exist. The zone will been added to the database anyway" &&

log_this ods-ksmutil-zone_add_list   ods-ksmutil zone list &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods5; on policy default" &&

##################  TEST:  Zonelist.xml  export ###########################

#cp $INSTALL_ROOT/etc/opendnssec/zonelist.xml zonelist.xml.gold &&

# Check the zonelist.xml
echo "Checking zonelist contents" && 
diff $ignore_blank_lines  $INSTALL_ROOT/etc/opendnssec/zonelist.xml zonelist.xml.gold_local &&
echo "Zonelist contents OK" && 

# Check the export gives the same thing  (note - we use a different gold file here as the order
# in the exported file is not the same as that in the configuration file)
ods-ksmutil zonelist export > zonelist.xml.temp &&
diff $ignore_blank_lines -w  zonelist.xml.temp zonelist.xml.gold_export_local &&
echo "Zonelist export contents OK" && 

# Now add without updating the zonelist. 
log_this ods-ksmutil-zone_add_1   ods-ksmutil zone add --zone ods14 --no-xml &&
log_grep ods-ksmutil-zone_add_1   stdout "Imported zone: ods14 into database only, please run \"ods-ksmutil zonelist export\" to update zonelist.xml" &&
log_this ods-ksmutil-zone_add_list_1   ods-ksmutil zone list &&
log_grep ods-ksmutil-zone_add_list_1   stdout "Found zone ods14 in DB but not zonelist." &&

echo "Checking zonelist contents again after silent add" && 
diff $ignore_blank_lines  $INSTALL_ROOT/etc/opendnssec/zonelist.xml zonelist.xml.gold_local &&
echo "Zonelist contents OK again" &&

# Exported zonelist should be different (not checked in detail)....
ods-ksmutil zonelist export > zonelist.xml.temp1 &&
! diff $ignore_blank_lines -w  zonelist.xml.temp1 zonelist.xml.gold_export_local >/dev/null 2>/dev/null &&
echo "Zonelist export contents OK" &&

##################  TEST:  Zone deletion  ###########################

# Delete zone successfully without updating xml
log_this ods-ksmutil-zone_del_1  ods-ksmutil zone delete -z ods1  --no-xml &&
#log_grep ods-ksmutil-zone_del_1  stdout "zone.*ods1.*deleted successfully"
log_this ods-ksmutil-zone_del_list_1   ods-ksmutil zone list &&
! log_grep ods-ksmutil-zone_del_list_1   stdout "Deleted zone: ods1 from database only, please run \"ods-ksmutil zonelist export\" to update zonelist.xml" &&

echo "Checking zonelist contents again after silent delete" && 
diff $ignore_blank_lines  $INSTALL_ROOT/etc/opendnssec/zonelist.xml zonelist.xml.gold_local &&
echo "Zonelist contents OK again" &&

log_this ods-ksmutil-zone_del_2  ods-ksmutil zone delete --zone ods2  &&
#log_grep ods-ksmutil-zone_del_1  stdout "zone.*ods1.*deleted successfully"
log_this ods-ksmutil-zone_del_list_2   ods-ksmutil zone list &&
! log_grep ods-ksmutil-zone_del_list_2   stdout "Found Zone: ods2; on policy Policy1" &&

# Check it is gone from the zonelist.xml
! $GREP -q -- "ods2" "$INSTALL_ROOT/etc/opendnssec/zonelist.xml" &&

# Test deleting a non-existant zone
! log_this ods-ksmutil-zone_del_2  ods-ksmutil zone delete -z ods1  &&
log_grep ods-ksmutil-zone_del_2 stdout  "Couldn't find zone ods1" && 

# Delete all remaining zones 
echo "y " | log_this ods-ksmutil-zone_del_3  ods-ksmutil zone delete --all  &&

log_this ods-ksmutil-zone_del_list_3  ods-ksmutil zone list  &&
log_grep ods-ksmutil-zone_del_list_3   stdout "No zones in DB or zonelist." &&

echo "Checking no zones in zonelist" && 
! $GREP -q -- "\<\/Zone\>"  "$INSTALL_ROOT/etc/opendnssec/zonelist.xml" &&
echo "Zonelist contents empty" &&

##################  TEST:  Zonelist.xml  import ###########################

cp zonelist.xml.gold_local "$INSTALL_ROOT/etc/opendnssec/zonelist.xml" &&
log_this ods-ksmutil-zonelist-import ods-ksmutil zonelist import && 
log_this ods-ksmutil-zone_add_list_2  ods-ksmutil zone list  &&
log_grep ods-ksmutil-zone_add_list_2   stdout "Found Zone: ods0; on policy default" &&
log_grep ods-ksmutil-zone_add_list_2   stdout "Found Zone: ods1; on policy Policy1" &&
log_grep ods-ksmutil-zone_add_list_2   stdout "Found Zone: ods2; on policy Policy1" &&
log_grep ods-ksmutil-zone_add_list_2   stdout "Found Zone: ods3; on policy default" &&
log_grep ods-ksmutil-zone_add_list_2   stdout "Found Zone: ods4; on policy default" &&
log_grep ods-ksmutil-zone_add_list_2   stdout "Found Zone: ods5; on policy default" &&

# Check the export gives the same thing  (note - we use a different gold file here as the order
# in the exported file is not the same as that in the configuration file)
ods-ksmutil zonelist export > zonelist.xml.temp_2 &&
diff $ignore_blank_lines -w  zonelist.xml.temp_2 zonelist.xml.gold_export_local &&
echo "Zonelist export contents OK" &&

# Clean up
rm zonelist.xml.gold_local  &&
rm zonelist.xml.gold_export_local  &&
rm zonelist.xml.temp  &&
rm zonelist.xml.temp_2  &&

echo && 
echo "************OK******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1



