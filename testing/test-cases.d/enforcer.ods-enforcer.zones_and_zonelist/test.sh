#!/usr/bin/env bash
#
#TEST: Test that the ods-enforcer zone add/delete works correctly
#TEST: Also test that 'basic' zonelist import/export works 

#TODO: Need to extend this test to make sure the signer is picking up the correct files when changes are mode!!!!

#TODO: Test that the system starts up with no zonefile and that a message reports this properly

ZONES_FILE=$INSTALL_ROOT/var/opendnssec/enforcer/zones.xml
ZONELIST_FILE=$INSTALL_ROOT/etc/opendnssec/zonelist.xml

# First, fix up the install root in the gold files
eval sed -e 's#@INSTALL_ROOT@#$INSTALL_ROOT#' zonelist.xml.gold > zonelist.xml.gold_local &&
eval sed -e 's#@INSTALL_ROOT@#$INSTALL_ROOT#' zonelist.xml.test > zonelist.xml.test_local && 
eval sed -e 's#@INSTALL_ROOT@#$INSTALL_ROOT#' zonelist.xml.gold_export > zonelist.xml.gold_export_local &&
eval sed -e 's#@INSTALL_ROOT@#$INSTALL_ROOT#' zonelist.xml.gold_export2 > zonelist.xml.gold_export2_local &&

# Cater for the fact that solaris and openbsd use different flags in diff
local ignore_blank_lines=" -B "
case "$DISTRIBUTION" in
	sunos | \
	openbsd )
		ignore_blank_lines="-b"
		;;
esac


if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

#### TO FIX: 
# # Check the system starts without a zonelist.xml file at all
# rm $ZONELIST_FILE
# ods_reset_env &&
# ods_start_enforcer &&
# 
# ! test -f $ZONELIST_FILE &&
# log_this ods-enforcer-zone_none_2   ods-enforcer zone list &&
# log_grep ods-enforcer-zone_none_2   stdout "No zones configured in DB." &&
# 
# ods_stop_enforcer &&

#cp zonelist.xml "$ZONELIST_FILE" &&
ods_reset_env &&
ods_start_enforcer && 

# Now a real but empty zone list
log_this ods-enforcer-zone_none   ods-enforcer zone list &&
log_grep ods-enforcer-zone_none   stdout "No zones configured in DB." &&


##################  TEST:  Zone add success ###########################
#0. Test all default
log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods0 &&
log_grep ods-enforcer-zone_add   stdout "Imported zone:.*ods0 into database only. Use the --xml flag or run \"ods-enforcer zonelist export\" if an update of zonelist.xml is required." &&

#1. Test existing policy
log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods1 --policy Policy1 &&
log_grep ods-enforcer-zone_add   stdout "Imported zone:.*ods1" &&

# Test default input type and file
log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods2 --policy Policy1 --input $INSTALL_ROOT/var/opendnssec/unsigned/ods2 &&
log_grep ods-enforcer-zone_add   stdout "Imported zone:.*ods2" &&

#2. Test more parameters
log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods3 --in-type File --out-type File &&
log_grep ods-enforcer-zone_add   stdout "Imported zone:.*ods3" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods4 --in-type File --out-type File --input $INSTALL_ROOT/var/opendnssec/unsigned/ods4 --output $INSTALL_ROOT/var/opendnssec/signed/ods4 &&
log_grep ods-enforcer-zone_add   stdout "Imported zone:.*ods4" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods5 --in-type File --out-type DNS &&
log_grep ods-enforcer-zone_add   stdout "Imported zone:.*ods5" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods6 --in-type File --out-type DNS --input $INSTALL_ROOT/var/opendnssec/unsigned/ods6 --output $INSTALL_ROOT/etc/opendnssec/addns.xml &&
log_grep ods-enforcer-zone_add   stdout "Imported zone:.*ods6" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods7 --in-type DNS --out-type DNS &&
log_grep ods-enforcer-zone_add   stdout "Imported zone:.*ods7" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods8 --in-type DNS --out-type DNS --input $INSTALL_ROOT/etc/opendnssec/addns.xml --output $INSTALL_ROOT/etc/opendnssec/addns.xml &&
log_grep ods-enforcer-zone_add   stdout "Imported zone:.*ods8" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods9 --in-type DNS --out-type File &&
log_grep ods-enforcer-zone_add   stdout "Imported zone:.*ods9" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods10 --in-type DNS --out-type File --input $INSTALL_ROOT/etc/opendnssec/addns.xml --output $INSTALL_ROOT/var/opendnssec/signed/ods10 &&
log_grep ods-enforcer-zone_add   stdout "Imported zone:.*ods10" &&

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
#####TO FIX: ! This command should fail!
log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods1 --policy Policy1 &&
log_grep ods-enforcer-zone_add_bad stdout "Failed to Import zone ods1; it already exists" &&

#3. Test noneexistent policy 
##### TO FIX ! This command should fail!
log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods11 --policy NonexistentPolicy &&
log_grep ods-enforcer-zone_add_bad   stdout "Error, can't find policy : NonexistentPolicy" &&

#4. Test bad parameter
##### TO FIX !! This command should fail!
log_this ods-enforcer-zone_add_bad   ods-enforcer zone &&
##### TO FIX: 
#log_grep ods-enforcer-zone_add_bad   stderr "usage: ods-enforcer \[-c <config> | --config <config>\] zone" &&
log_grep ods-enforcer-zone_add_bad stdout "Unknown command zone" &&


##### TO FIX: TO be implemented in 2.0
# #5. Test none exist input file
log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods11 --input $INSTALL_ROOT/var/opendnssec/unsigned/ods11 --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods11.xml &&
# log_grep ods-enforcer-zone_add_bad   stdout "WARNING: The input file $INSTALL_ROOT/var/opendnssec/unsigned/ods11 for zone ods11 does not currently exist. The zone will been added to the database anyway" &&
# 
# mv $INSTALL_ROOT/etc/opendnssec/addns.xml $INSTALL_ROOT/etc/opendnssec/addns.xml.backup &&
log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods12 --input $INSTALL_ROOT/etc/opendnssec/addns.xml --in-type DNS --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods12.xml &&
# log_grep ods-enforcer-zone_add_bad   stdout "WARNING: The input file $INSTALL_ROOT/etc/opendnssec/addns.xml for zone ods12 does not currently exist. The zone will been added to the database anyway" &&
# 
# #6. Test none exist output file in the case of --out-type DNS
# mv $INSTALL_ROOT/etc/opendnssec/addns.xml.backup $INSTALL_ROOT/etc/opendnssec/addns.xml &&
log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods13 --input $INSTALL_ROOT/etc/opendnssec/addns.xml --in-type DNS --out-type DNS --output $INSTALL_ROOT/etc/opendnssec/addns1.xml --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods13.xml &&
# log_grep ods-enforcer-zone_add_bad   stdout "WARNING: The output file $INSTALL_ROOT/etc/opendnssec/addns1.xml for zone ods13 does not currently exist." &&

##################  TEST:  Zonelist.xml  export ###########################

#cp $ZONELIST_FILE zonelist.xml.gold &&

# Check the zones.xml internal file is written (2.0 new behaviour)
diff $ignore_blank_lines -w  $ZONES_FILE zonelist.xml.gold_local &&
echo "zones.xml contents OK" &&

# Check the zonelist.xml is still empty (2.0 default behaviour)
echo "Checking zonelist contents" && 
diff $ignore_blank_lines  $ZONELIST_FILE zonelist.xml &&
echo "Zonelist contents OK" && 

# Check the export against a gold
##### TO FIX:  Need a <xml version> comment at the top of the output???
ods-enforcer zonelist export > zonelist.xml.temp &&
diff $ignore_blank_lines -w  zonelist.xml.temp zonelist.xml.gold_export_local &&
echo "Zonelist export contents OK" && 

# Now add _and_ update the zonelist (2.0 new behaviour)
log_this ods-enforcer-zone_add_1   ods-enforcer zone add --zone ods14 --xml &&
log_grep ods-enforcer-zone_add_1   stdout "Imported zone: ods14 into database and zonelist.xml updated" &&
log_this ods-enforcer-zone_add_list_1   ods-enforcer zone list &&
log_grep ods-enforcer-zone_add_list_1   stdout "ods14[[:space:]]*default" &&
#log_grep ods-enforcer-zone_add_list_1   stdout "Found zone ods14 in DB but not zonelist." &&

# Exported zonelist should be different (not checked in detail)....
echo "Checking zonelist contents again after update of zonelist.xml" && 
! diff $ignore_blank_lines  $ZONELIST_FILE zonelist.xml.gold_local >/dev/null 2>/dev/null &&
$GREP -q -- "ods14" "$ZONELIST_FILE" &&
echo "Zonelist contents OK again" &&

# And the zones.xml should be different too
! diff $ignore_blank_lines -w  $ZONES_FILE zonelist.xml.gold_local >/dev/null 2>/dev/null &&
$GREP -q -- "ods14" "$ZONES_FILE" &&
echo "zones.xml contents OK" &&

# Exported zonelist should be different (not checked in detail)....
ods-enforcer zonelist export > zonelist.xml.temp1 &&
! diff $ignore_blank_lines -w  zonelist.xml.temp1 zonelist.xml.gold_export_local >/dev/null 2>/dev/null &&
$GREP -q -- "ods14" "zonelist.xml.temp1" &&
echo "Zonelist export contents OK" &&

##################  TEST:  Zone delete command  ###########################

# Delete zone successfully 
log_this ods-enforcer-zone_del_1  ods-enforcer zone delete -z ods1  &&
log_grep ods-enforcer-zone_del_1   stdout "Deleted zone: ods1 in database only. Use the --xml flag or run \"ods-enforcer zonelist export\" if an update of zonelist.xml is required." &&
#log_grep ods-enforcer-zone_del_1  stdout "zone.*ods1.*deleted successfully"
log_this ods-enforcer-zone_del_list_1   ods-enforcer zone list &&
! log_grep ods-enforcer-zone_del_list_1   stdout "ods1[[:space:]]*Policy1" &&

echo "Checking zonelist contents again after delete" && 
###diff $ignore_blank_lines  $ZONELIST_FILE zonelist.xml.gold_local &&
$GREP -q -- "ods1\"" "$ZONELIST_FILE" &&
$GREP -q -- "ods14" "$ZONELIST_FILE" &&
! $GREP -q -- "ods1\"" "$ZONES_FILE" &&
$GREP -q -- "ods14" "$ZONES_FILE" &&
echo "Zonelist contents OK again" &&

log_this ods-enforcer-zone_del_2  ods-enforcer zone delete --zone ods2 --xml &&
log_grep ods-enforcer-zone_del_2   stdout "Deleted zone: ods2 in database and zonelist.xml updated" &&
#log_grep ods-enforcer-zone_del_1  stdout "zone.*ods1.*deleted successfully"
log_this ods-enforcer-zone_del_list_2   ods-enforcer zone list &&
! log_grep ods-enforcer-zone_del_list_2   stdout "ods2[[:space:]]*Policy1" &&

# Check it is gone from the zonelist.xml
! $GREP -q -- "ods2" "$ZONELIST_FILE" &&
! $GREP -q -- "ods2" "$ZONES_FILE" &&
$GREP -q -- "ods14" "$ZONELIST_FILE" &&
$GREP -q -- "ods14" "$ZONES_FILE" &&

# Test deleting a non-existant zone
#### TO FIX: this should fail
log_this ods-enforcer-zone_del_2  ods-enforcer zone delete -z ods1  &&
log_grep ods-enforcer-zone_del_2 stdout  "Couldn't find zone 'ods1'" && 

# Delete all remaining zones 
echo "y " | log_this ods-enforcer-zone_del_3  ods-enforcer zone delete --all  &&

log_this ods-enforcer-zone_del_list_3  ods-enforcer zone list  &&
log_grep ods-enforcer-zone_del_list_3   stdout "No zones configured in DB." &&

echo "Checking no zones in zonelist" && 
! $GREP -q -- "\<\/Zone\>"  "$ZONELIST_FILE" &&
echo "Zonelist contents empty" &&

##################  TEST:  Zonelist.xml  import ###########################

cp zonelist.xml.gold_local "$ZONELIST_FILE" &&
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

# Check the export gives the same thing  (note - we use a different gold file here as the order
# in the exported file is not the same as that in the configuration file)
ods-enforcer zonelist export > zonelist.xml.temp2 &&
diff $ignore_blank_lines -w  zonelist.xml.temp2 zonelist.xml.gold_export_local &&
echo "Zonelist export contents OK" &&
diff $ignore_blank_lines -w  $ZONES_FILE zonelist.xml.gold_local &&
echo "zones.xml contents OK" &&

# Now do another import with a file that has one extra zone and one zone removed
# and some of the data changed
cp zonelist.xml.test_local "$ZONELIST_FILE" &&
log_this ods-enforcer-zonelist-import ods-enforcer zonelist import && 
log_this ods-enforcer-zone_add_list_3  ods-enforcer zone list  &&
! log_grep ods-enforcer-zone_add_list_3   stdout "ods0[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_3   stdout "ods1[[:space:]]*Policy1" &&
log_grep ods-enforcer-zone_add_list_3   stdout "ods2[[:space:]]*Policy1" &&
log_grep ods-enforcer-zone_add_list_3   stdout "ods3[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_3   stdout "ods4[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_3   stdout "ods5[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_3   stdout "ods6[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_3   stdout "ods7[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_3   stdout "ods8[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_3   stdout "ods9[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_3   stdout "ods10[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_3   stdout "ods11[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_3   stdout "ods12[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_3   stdout "ods13[[:space:]]*default" &&
log_grep ods-enforcer-zone_add_list_3   stdout "ods14[[:space:]]*default" &&

ods-enforcer zonelist export > zonelist.xml.temp3 &&
diff $ignore_blank_lines -w  zonelist.xml.temp3 zonelist.xml.gold_export2_local &&
echo "Zonelist export contents OK" &&
diff $ignore_blank_lines -w  $ZONES_FILE zonelist.xml.test_local &&
echo "zones.xml contents OK" &&


#### TO FIX: this shouldn't be needed
log_this ods-enforcer-enforce ods-enforcer enforce &&

# #Finally run the signer to check all is well
syslog_waitfor 60 "update Zone: ods14" &&
ods_start_signer &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods1' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods2' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods3' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods4' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods5' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods6' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods7' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods8' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods9' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods10' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods12' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods13' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods14' &&
! syslog_grep 'ods-signerd: .*\[STATS\] ods0' &&
! syslog_grep 'ods-signerd: .*\[STATS\] ods11' &&

ods_stop_signer &&

# Now import an emtpy zonelist
cp zonelist.xml "$ZONELIST_FILE" &&
log_this ods-enforcer-zonelist-import-empty ods-enforcer zonelist import && 
log_this ods-enforcer-zonelist-import-empty   ods-enforcer zone list &&
log_grep ods-enforcer-zonelist-import-empty   stdout "No zones configured in DB." &&

diff $ignore_blank_lines -w  $ZONES_FILE zonelist.xml &&
echo "Zonelist export contents OK" &&

ods_stop_enforcer && 

# Clean up
rm zonelist.xml.gold_local  &&
rm zonelist.xml.test_local  &&
rm zonelist.xml.gold_export_local  &&
rm zonelist.xml.gold_export2_local  &&
rm zonelist.xml.temp  &&
rm zonelist.xml.temp1  &&
rm zonelist.xml.temp2  &&
rm zonelist.xml.temp3  &&

echo && 
echo "************OK******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1



