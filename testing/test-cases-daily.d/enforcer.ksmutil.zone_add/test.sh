#!/usr/bin/env bash
#
#TEST: Test that the ods-ksmutil zone add works correctly
#TEST: Also test that 'basic' zonelist import/export works (no incrementatl changes tested)


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
log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods3 --in-type File --out-type File &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone:.*ods3" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods4 --in-type File --out-type File --input $INSTALL_ROOT/var/opendnssec/unsigned/ods4 --output $INSTALL_ROOT/var/opendnssec/signed/ods4 &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone:.*ods4" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods5 --in-type File --out-type DNS &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone:.*ods5" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods6 --in-type File --out-type DNS --input $INSTALL_ROOT/var/opendnssec/unsigned/ods6 --output $INSTALL_ROOT/etc/opendnssec/addns.xml &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone:.*ods6" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods7 --in-type DNS --out-type DNS &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone:.*ods7" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods8 --in-type DNS --out-type DNS --input $INSTALL_ROOT/etc/opendnssec/addns.xml --output $INSTALL_ROOT/etc/opendnssec/addns.xml &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone:.*ods8" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods9 --in-type DNS --out-type File &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone:.*ods9" &&

log_this ods-ksmutil-zone_add   ods-ksmutil zone add --zone ods10 --in-type DNS --out-type File --input $INSTALL_ROOT/etc/opendnssec/addns.xml --output $INSTALL_ROOT/var/opendnssec/signed/ods10 &&
log_grep ods-ksmutil-zone_add   stdout "Imported zone:.*ods10" &&

log_this ods-ksmutil-zone_add_list   ods-ksmutil zone list &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods0; on policy default" &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods1; on policy Policy1" &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods2; on policy Policy1" &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods3; on policy default" &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods4; on policy default" &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods5; on policy default" &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods6; on policy default" &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods7; on policy default" &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods8; on policy default" &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods9; on policy default" &&
log_grep ods-ksmutil-zone_add_list   stdout "Found Zone: ods10; on policy default" &&

##################  TEST:  Zone add failures/warnings ###########################

# Test re-add of of existing zone
! log_this ods-ksmutil-zone_add_bad   ods-ksmutil zone add --zone ods1 --policy Policy1 &&
log_grep ods-ksmutil-zone_add_bad stdout "Failed to Import zone ods1; it already exists" &&

#3. Test noneexistent policy 
! log_this ods-ksmutil-zone_add_bad   ods-ksmutil zone add --zone ods11 --policy NonexistentPolicy &&
log_grep ods-ksmutil-zone_add_bad   stdout "Error, can't find policy : NonexistentPolicy" &&

#4. Test bad parameter
! log_this ods-ksmutil-zone_add_bad   ods-ksmutil zone &&
log_grep ods-ksmutil-zone_add_bad   stderr "usage: ods-ksmutil \[-c <config> | --config <config>\] zone" &&

#5. Test none exist input file
log_this ods-ksmutil-zone_add_bad   ods-ksmutil zone add --zone ods11 --input $INSTALL_ROOT/var/opendnssec/unsigned/ods11 --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods11.xml &&
log_grep ods-ksmutil-zone_add_bad   stdout "WARNING: The input file $INSTALL_ROOT/var/opendnssec/unsigned/ods11 for zone ods11 does not currently exist. The zone will been added to the database anyway" &&

mv $INSTALL_ROOT/etc/opendnssec/addns.xml $INSTALL_ROOT/etc/opendnssec/addns.xml.backup &&
log_this ods-ksmutil-zone_add_bad   ods-ksmutil zone add --zone ods12 --input $INSTALL_ROOT/etc/opendnssec/addns.xml --in-type DNS --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods12.xml &&
log_grep ods-ksmutil-zone_add_bad   stdout "WARNING: The input file $INSTALL_ROOT/etc/opendnssec/addns.xml for zone ods12 does not currently exist. The zone will been added to the database anyway" &&

#6. Test none exist output file in the case of --out-type DNS
mv $INSTALL_ROOT/etc/opendnssec/addns.xml.backup $INSTALL_ROOT/etc/opendnssec/addns.xml &&
log_this ods-ksmutil-zone_add_bad   ods-ksmutil zone add --zone ods13 --input $INSTALL_ROOT/etc/opendnssec/addns.xml --in-type DNS --out-type DNS --output $INSTALL_ROOT/etc/opendnssec/addns1.xml --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods13.xml &&
log_grep ods-ksmutil-zone_add_bad   stdout "WARNING: The output file $INSTALL_ROOT/etc/opendnssec/addns1.xml for zone ods13 does not currently exist." &&

##################  TEST:  Zonelist.xml  export ###########################

#cp $INSTALL_ROOT/etc/opendnssec/zonelist.xml zonelist.xml.gold &&

# Check the zonelist.xml
echo "Checking zonelist contents" && 
diff -B  $INSTALL_ROOT/etc/opendnssec/zonelist.xml zonelist.xml.gold_local &&
echo "Zonelist contents OK" && 

# Check the export gives the same thing  (note - we use a different gold file here as the order
# in the exported file is not the same as that in the configuration file)
ods-ksmutil zonelist export > zonelist.xml.temp &&
diff -B -w  zonelist.xml.temp zonelist.xml.gold_export_local &&
echo "Zonelist export contents OK" && 

# Now add without updating the zonelist. 
log_this ods-ksmutil-zone_add_1   ods-ksmutil zone add --zone ods14 --no-xml &&
log_grep ods-ksmutil-zone_add_1   stdout "Imported zone: ods14 into database only, please run \"ods-ksmutil zonelist export\" to update zonelist.xml" &&
log_this ods-ksmutil-zone_add_list_1   ods-ksmutil zone list &&
log_grep ods-ksmutil-zone_add_list_1   stdout "Found zone ods14 in DB but not zonelist." &&

echo "Checking zonelist contents again after silent add" && 
diff -B  $INSTALL_ROOT/etc/opendnssec/zonelist.xml zonelist.xml.gold_local &&
echo "Zonelist contents OK again" &&

# Exported zonelist should be different (not checked in detail)....
ods-ksmutil zonelist export > zonelist.xml.temp1 &&
! diff -q -B -w  zonelist.xml.temp1 zonelist.xml.gold_export_local &&
echo "Zonelist export contents OK" &&

##################  TEST:  Zone deletion  ###########################

# Delete zone successfully without updating xml
log_this ods-ksmutil-zone_del_1  ods-ksmutil zone delete -z ods1  --no-xml &&
#log_grep ods-ksmutil-zone_del_1  stdout "zone.*ods1.*deleted successfully"
log_this ods-ksmutil-zone_del_list_1   ods-ksmutil zone list &&
! log_grep ods-ksmutil-zone_del_list_1   stdout "Deleted zone: ods1 from database only, please run \"ods-ksmutil zonelist export\" to update zonelist.xml" &&

echo "Checking zonelist contents again after silent delete" && 
diff -B  $INSTALL_ROOT/etc/opendnssec/zonelist.xml zonelist.xml.gold_local &&
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
log_grep ods-ksmutil-zone_add_list_2   stdout "Found Zone: ods6; on policy default" &&
log_grep ods-ksmutil-zone_add_list_2   stdout "Found Zone: ods7; on policy default" &&
log_grep ods-ksmutil-zone_add_list_2   stdout "Found Zone: ods8; on policy default" &&
log_grep ods-ksmutil-zone_add_list_2   stdout "Found Zone: ods9; on policy default" &&
log_grep ods-ksmutil-zone_add_list_2   stdout "Found Zone: ods10; on policy default" &&
log_grep ods-ksmutil-zone_add_list_2   stdout "Found Zone: ods11; on policy default" &&
log_grep ods-ksmutil-zone_add_list_2   stdout "Found Zone: ods12; on policy default" &&
log_grep ods-ksmutil-zone_add_list_2   stdout "Found Zone: ods13; on policy default" &&

# Check the export gives the same thing  (note - we use a different gold file here as the order
# in the exported file is not the same as that in the configuration file)
ods-ksmutil zonelist export > zonelist.xml.temp_2 &&
diff -B -w  zonelist.xml.temp_2 zonelist.xml.gold_export_local &&
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



