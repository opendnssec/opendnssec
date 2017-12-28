#!/usr/bin/env bash
#
#TEST: Test that the ods-enforcer zone add works correctly
#TEST: Also test that 'basic' zonelist import/export works (no incrementatl changes tested)

# Cater for the fact that solaris and openbsd use different flags in diff

local ignore=" -B -w "
case "$DISTRIBUTION" in
	sunos | \
	openbsd )
		ignore="-b -w "
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

ods_start_enforcer &&
log_this ods-enforcer-zone_none   ods-enforcer zone list &&
log_grep ods-enforcer-zone_none   stdout "No zones in database." &&


##################  TEST:  Zone add success ###########################
#0. Test all default
log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods0 --xml &&
log_grep ods-enforcer-zone_add   stdout "Zone ods0 added successfully" &&

#1. Test existing policy
log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods1 --policy Policy1 --xml &&
log_grep ods-enforcer-zone_add   stdout "Zone ods1 added successfully" &&

# Test default input type and file
log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods2 --policy Policy1 --input $INSTALL_ROOT/var/opendnssec/unsigned/ods2 --xml &&
log_grep ods-enforcer-zone_add   stdout "Zone ods2 added successfully" &&

#2. Test more parameters
log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods3 --in-type File --out-type File --xml &&
log_grep ods-enforcer-zone_add   stdout "Zone ods3 added successfully" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods4 --in-type File --out-type File --input $INSTALL_ROOT/var/opendnssec/unsigned/ods4 --output $INSTALL_ROOT/var/opendnssec/signed/ods4 --xml &&
log_grep ods-enforcer-zone_add   stdout "Zone ods4 added successfully" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods5 --in-type File --out-type DNS --xml &&
log_grep ods-enforcer-zone_add   stdout "Zone ods5 added successfully" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods6 --in-type File --out-type DNS --input $INSTALL_ROOT/var/opendnssec/unsigned/ods6 --output $INSTALL_ROOT/etc/opendnssec/addns.xml --xml &&
log_grep ods-enforcer-zone_add   stdout "Zone ods6 added successfully" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods7 --in-type DNS --out-type DNS --xml &&
log_grep ods-enforcer-zone_add   stdout "Zone ods7 added successfully" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods8 --in-type DNS --out-type DNS --input $INSTALL_ROOT/etc/opendnssec/addns.xml --output $INSTALL_ROOT/etc/opendnssec/addns.xml --xml &&
log_grep ods-enforcer-zone_add   stdout "Zone ods8 added successfully" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods9 --in-type DNS --out-type File --xml &&
log_grep ods-enforcer-zone_add   stdout "Zone ods9 added successfully" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods10 --in-type DNS --out-type File --input $INSTALL_ROOT/etc/opendnssec/addns.xml --output $INSTALL_ROOT/var/opendnssec/signed/ods10 --xml &&
log_grep ods-enforcer-zone_add   stdout "Zone ods10 added successfully" &&

log_this ods-enforcer-zone_add_list   ods-enforcer zone list &&
log_grep ods-enforcer-zone_add_list   stdout "ods0[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list   stdout "ods1[[:space:]]*Policy1" &&
log_grep ods-enforcer-zone_add_list   stdout "ods2[[:space:]]*Policy1" &&
log_grep ods-enforcer-zone_add_list   stdout "ods3[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list   stdout "ods4[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list   stdout "ods5[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list   stdout "ods6[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list   stdout "ods7[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list   stdout "ods8[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list   stdout "ods9[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list   stdout "ods10[[:space:]]*default" &&

##################  TEST:  Zone add failures/warnings ###########################

# Test re-add of of existing zone
! log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods1 --policy Policy1 &&
log_grep ods-enforcer-zone_add_bad stderr "Unable to add zone, zone already exists!" &&

#3. Test noneexistent policy 
! log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods11 --policy NonexistentPolicy &&
log_grep ods-enforcer-zone_add_bad   stderr "Unable to find policy NonexistentPolicy needed for adding the zone!" &&

#4. Test bad parameter
! log_this ods-enforcer-zone_add_bad   ods-enforcer zone &&
log_grep ods-enforcer-zone_add_bad   stderr "Unknown command zone." &&

#5. Test none exist input file
log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods11 --input $INSTALL_ROOT/var/opendnssec/unsigned/ods11 --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods11.xml --xml &&
# in 2.0 it still doesn't show any warning message when there is no unsigned file
#log_grep ods-enforcer-zone_add_bad   stdout "WARNING: The input file $INSTALL_ROOT/var/opendnssec/unsigned/ods11 for zone ods11 does not currently exist. The zone will been added to the database anyway" &&

mv $INSTALL_ROOT/etc/opendnssec/addns.xml $INSTALL_ROOT/etc/opendnssec/addns.xml.backup &&
log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods12 --input $INSTALL_ROOT/etc/opendnssec/addns.xml --in-type DNS --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods12.xml --xml &&
#log_grep ods-enforcer-zone_add_bad   stdout "WARNING: The input file $INSTALL_ROOT/etc/opendnssec/addns.xml for zone ods12 does not currently exist. The zone will been added to the database anyway" &&

#6. Test none exist output file in the case of --out-type DNS
mv $INSTALL_ROOT/etc/opendnssec/addns.xml.backup $INSTALL_ROOT/etc/opendnssec/addns.xml &&
log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods13 --input $INSTALL_ROOT/etc/opendnssec/addns.xml --in-type DNS --out-type DNS --output $INSTALL_ROOT/etc/opendnssec/addns1.xml --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods13.xml --xml &&
#log_grep ods-enforcer-zone_add_bad   stdout "WARNING: The output file $INSTALL_ROOT/etc/opendnssec/addns1.xml for zone ods13 does not currently exist." &&

##################  TEST:  Zonelist.xml  export ###########################

#cp $INSTALL_ROOT/etc/opendnssec/zonelist.xml zonelist.xml.gold &&

# Check the zonelist.xml
echo "Checking zonelist contents" && 
ods_compare_zonelist  $INSTALL_ROOT/etc/opendnssec/zonelist.xml zonelist.xml.gold_local &&
echo "Zonelist contents OK" && 

# Check the export gives the same thing  (note - we use a different gold file here as the the exported file has comments)
log_this ods-enforcer-zonelist-export1 ods-enforcer zonelist export &&
ods_compare_zonelist  $INSTALL_ROOT/etc/opendnssec/zonelist.xml zonelist.xml.gold_export_local &&
echo "Zonelist export contents OK" && 

# Now add without updating the zonelist. 
log_this ods-enforcer-zone_add_1   ods-enforcer zone add --zone ods14 &&
log_grep ods-enforcer-zone_add_1   stdout "Zone ods14 added successfully" &&
log_this ods-enforcer-zone_add_list_1   ods-enforcer zone list &&
log_grep ods-enforcer-zone_add_list_1   stdout "ods14[[:space:]]*default" &&

ods_waitfor_keys &&

echo "Checking zonelist contents again after silent add" && 
ods_compare_zonelist $INSTALL_ROOT/etc/opendnssec/zonelist.xml zonelist.xml.gold_export_local &&
echo "Zonelist contents OK again" &&

# Exported zonelist should be different 
log_this ods-enforcer-zonelist-export2 ods-enforcer zonelist export &&
! ods_compare_zonelist $INSTALL_ROOT/etc/opendnssec/zonelist.xml  zonelist.xml.gold_export_local >/dev/null 2>/dev/null &&
echo "Zonelist export contents OK" &&

##################  TEST:  Zone deletion  ###########################
cp zonelist.xml.gold_export_local "$INSTALL_ROOT/etc/opendnssec/zonelist.xml" &&

# Delete zone successfully without updating xml
sleep 1 && ods_enforcer_idle &&
log_this ods-enforcer-zone_del_1  ods-enforcer zone delete -z ods1 &&
sleep 5 && ods_enforcer_idle &&
log_grep ods-enforcer-zone_del_1  stdout "Deleted zone ods1 successfully" &&
log_this ods-enforcer-zone_del_list_1   ods-enforcer zone list &&
! log_grep ods-enforcer-zone_del_list_1   stdout "ods1[[:space:]]*Policy1" &&

echo "Checking zonelist contents again after silent delete" && 
ods_compare_zonelist  $INSTALL_ROOT/etc/opendnssec/zonelist.xml zonelist.xml.gold_export_local &&
echo "Zonelist contents OK again" &&

sleep 3 && ods_enforcer_idle &&
log_this ods-enforcer-zone_del_2  ods-enforcer zone delete --zone ods2 --xml  &&
sleep 1 && ods_enforcer_idle &&
log_grep ods-enforcer-zone_del_2  stdout "Deleted zone ods2 successfully" &&
log_grep ods-enforcer-zone_del_2 stdout "Exported zonelist to .*/etc/opendnssec/zonelist.xml successfully" &&
log_this ods-enforcer-zone_del_list_2   ods-enforcer zone list &&
! log_grep ods-enforcer-zone_del_list_2   stdout "ods2[[:space:]]*Policy1" &&

# Check it is gone from the zonelist.xml
! $GREP -q -- "ods2" "$INSTALL_ROOT/etc/opendnssec/zonelist.xml" &&

# Test deleting a non-existant zone
! log_this ods-enforcer-zone_del_2  ods-enforcer zone delete -z ods1 &&
log_grep ods-enforcer-zone_del_2 stderr  "Unable to delete zone, zone ods1 not found" &&

# Delete all remaining zones 
sleep 1 && ods_enforcer_idle &&
log_this ods-enforcer-zone_del_3  ods-enforcer zone delete --all --xml &&
sleep 1 && ods_enforcer_idle &&

log_this ods-enforcer-zone_del_list_3  ods-enforcer zone list  &&
log_grep ods-enforcer-zone_del_list_3   stdout "No zones in database." &&

echo "Checking no zones in zonelist" && 
! $GREP -q -- "\<\/Zone\>"  "$INSTALL_ROOT/etc/opendnssec/zonelist.xml" &&
echo "Zonelist contents empty" &&

##################  TEST:  Zonelist.xml  import ###########################

cp zonelist.xml.gold_local "$INSTALL_ROOT/etc/opendnssec/zonelist.xml" &&
log_this ods-enforcer-zonelist-import ods-enforcer zonelist import && 
log_this ods-enforcer-zone_add_list_2  ods-enforcer zone list  &&
log_grep ods-enforcer-zone_add_list_2   stdout "ods0[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_2   stdout "ods1[[:space:]]*Policy1" &&
log_grep ods-enforcer-zone_add_list_2   stdout "ods2[[:space:]]*Policy1" &&
log_grep ods-enforcer-zone_add_list_2   stdout "ods3[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_2   stdout "ods4[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_2   stdout "ods5[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_2   stdout "ods6[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_2   stdout "ods7[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_2   stdout "ods8[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_2   stdout "ods9[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_2   stdout "ods10[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_2   stdout "ods11[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_2   stdout "ods12[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_2   stdout "ods13[[:space:]]*default" &&

# Check the export gives the same thing  
log_this ods-enforcer-zonelist-export3 ods-enforcer zonelist export &&
ods_compare_zonelist  $INSTALL_ROOT/etc/opendnssec/zonelist.xml zonelist.xml.gold_export_local &&
echo "Zonelist export contents OK" &&

ods_stop_enforcer &&

# Clean up
rm zonelist.xml.gold_local  &&
rm zonelist.xml.gold_export_local  &&

echo && 
echo "************OK******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1



