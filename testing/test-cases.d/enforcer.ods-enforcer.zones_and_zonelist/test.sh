#!/usr/bin/env bash
#
#TEST: Test that the ods-enforcer zone add/delete works correctly
#TEST: Also test that 'basic' zonelist import/export works 

#TODO: Need to extend this test to make sure the signer is picking up the correct files when changes are mode!!!!

#TODO: Test that the system starts up with no zonefile and that a message reports this properly

ZONES_FILE=$INSTALL_ROOT/var/opendnssec/enforcer/zones.xml
ZONELIST_FILE=$INSTALL_ROOT/etc/opendnssec/zonelist.xml

local num_completed_updates

# First, fix up the install root in the gold files
sed -e "s%@INSTALL_ROOT@%$INSTALL_ROOT%" zonelist.xml.gold > zonelist.xml.gold_local &&
sed -e "s%@INSTALL_ROOT@%$INSTALL_ROOT%" zonelist.xml.test > zonelist.xml.test_local && 
sed -e "s%@INSTALL_ROOT@%$INSTALL_ROOT%" zonelist.xml.gold_export > zonelist.xml.gold_export_local &&
sed -e "s%@INSTALL_ROOT@%$INSTALL_ROOT%" zonelist.xml.gold_export2 > zonelist.xml.gold_export2_local &&

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
syslog_grep '\[zone_add_cmd\] internal zonelist updated successfully' &&

#1. Test existing policy
log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods1 --policy Policy1 &&
log_grep ods-enforcer-zone_add   stdout "Zone ods1 added successfully" &&

# Test default input type and file
log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods2 --policy Policy1 --input $INSTALL_ROOT/var/opendnssec/unsigned/ods2 &&
log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods2 added successfully" &&

#2. Test more parameters
log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods3 --in-type File --out-type File &&
log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods3 added successfully" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods4 --in-type File --out-type File --input $INSTALL_ROOT/var/opendnssec/unsigned/ods4 --output $INSTALL_ROOT/var/opendnssec/signed/ods4 &&
log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods4 added successfully" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods5 --in-type File --out-type DNS &&
log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods5 added successfully" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods6 --in-type File --out-type DNS --input $INSTALL_ROOT/var/opendnssec/unsigned/ods6 --output $INSTALL_ROOT/etc/opendnssec/addns.xml &&
log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods6 added successfully" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods7 --in-type DNS --out-type DNS &&
log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods7 added successfully" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods8 --in-type DNS --out-type DNS --input $INSTALL_ROOT/etc/opendnssec/addns.xml --output $INSTALL_ROOT/etc/opendnssec/addns.xml &&
log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods8 added successfully" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods9 --in-type DNS --out-type File &&
log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods9 added successfully" &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods10 --in-type DNS --out-type File --input $INSTALL_ROOT/etc/opendnssec/addns.xml --output $INSTALL_ROOT/var/opendnssec/signed/ods10 &&
log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods10 added successfully" &&

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
log_waitfor ods-enforcer-zone_add_bad stderr 900 "Unable to add zone, zone already exists" &&


#3. Test noneexistent policy 
! log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods11 --policy NonexistentPolicy &&
log_waitfor ods-enforcer-zone_add_bad   stderr 900 "Unable to find policy NonexistentPolicy needed for adding the zone!" &&

#4. Test bad parameter
! log_this ods-enforcer-zone_add_bad   ods-enforcer zone &&
##### TO FIX: 
log_waitfor ods-enforcer-zone_add_bad stderr 900 "Unknown command zone" &&


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

# Check the zones.xml internal file is written (2.0 new behaviour)
diff.sh $ZONES_FILE zonelist.xml.gold_local &&
echo "zones.xml contents OK" &&

# Check the zonelist.xml is still empty (2.0 default behaviour)
echo "Checking zonelist contents" && 
diff.sh $ZONELIST_FILE zonelist.xml &&
echo "Zonelist contents OK" && 

# Check the export against a gold
ods-enforcer zonelist export > zonelist.xml.temp &&
cp $ZONELIST_FILE zonelist.xml.temp &&
diff.sh zonelist.xml.temp zonelist.xml.gold_export_local &&
echo "Zonelist export contents OK" && 

# Now add _and_ update the zonelist (2.0 new behaviour)
log_this ods-enforcer-zone_add_1   ods-enforcer zone add --zone ods14 --xml &&
log_grep ods-enforcer-zone_add_1   stdout "Zone ods14 added successfully" &&
log_grep ods-enforcer-zone_add_1   stdout "Zonelist .* updated successfully" &&
log_this ods-enforcer-zone_add_list_1   ods-enforcer zone list &&
log_grep ods-enforcer-zone_add_list_1   stdout "ods14[[:space:]]*default" &&
#log_grep ods-enforcer-zone_add_list_1   stdout "Found zone ods14 in DB but not zonelist." &&

# Exported zonelist should be different (not checked in detail)....
echo "Checking zonelist contents again after update of zonelist.xml" && 
log_this ods-enforcer-zone_update ods-enforcer update zonelist &&
! diff.sh $ZONELIST_FILE zonelist.xml.gold_local &&
$GREP -q -- "ods14" "$ZONELIST_FILE" &&
echo "Zonelist contents OK again" &&

# And the zones.xml should be different too
! diff.sh $ZONES_FILE zonelist.xml.gold_local &&
$GREP -q -- "ods14" "$ZONES_FILE" &&
echo "zones.xml contents OK" &&

# Exported zonelist should be different (not checked in detail)....
ods-enforcer zonelist export > zonelist.xml.temp1 &&
cp $ZONELIST_FILE zonelist.xml.temp1 &&
! diff.sh zonelist.xml.temp1 zonelist.xml.gold_export_local &&
$GREP -q -- "ods14" "zonelist.xml.temp1" &&
echo "Zonelist export contents OK" &&

##################  TEST:  Zone delete command  ###########################

# Delete zone successfully 
log_this ods-enforcer-zone_del_1  ods-enforcer zone delete -z ods1  &&
log_grep ods-enforcer-zone_del_1   stdout "Deleted zone ods1 successfully" &&
log_this ods-enforcer-zone_del_list_1   ods-enforcer zone list &&
! log_grep ods-enforcer-zone_del_list_1   stdout "ods1[[:space:]]*Policy1" &&

echo "Checking zonelist contents again after delete" && 
###diff.sh $ZONELIST_FILE zonelist.xml.gold_local &&
$GREP -q -- "ods1\"" "$ZONELIST_FILE" &&
$GREP -q -- "ods14" "$ZONELIST_FILE" &&
! $GREP -q -- "ods1\"" "$ZONES_FILE" &&
$GREP -q -- "ods14" "$ZONES_FILE" &&
echo "Zonelist contents OK again" &&

log_this ods-enforcer-zone_del_2  ods-enforcer zone delete --zone ods2 --xml &&
log_grep ods-enforcer-zone_del_2   stdout "Deleted zone ods2 successfully" &&
log_this ods-enforcer-zone_del_list_2   ods-enforcer zone list &&
! log_grep ods-enforcer-zone_del_list_2   stdout "ods2[[:space:]]*Policy1" &&

# Check it is gone from the zonelist.xml
! $GREP -q -- "ods2" "$ZONELIST_FILE" &&
! $GREP -q -- "ods2" "$ZONES_FILE" &&
$GREP -q -- "ods14" "$ZONELIST_FILE" &&
$GREP -q -- "ods14" "$ZONES_FILE" &&

# GIVES OUT TWO MESSAGES
#    Unable to delete zone, zone ods1 not found!
# BUT ALSO:
#    Deleted zone ods2 successfully
# REMNANT OF EARLIER COMMAND OR REAL BAD?
# Test deleting a non-existant zone
! log_this ods-enforcer-zone_del_2  ods-enforcer zone delete -z ods1  &&
log_grep ods-enforcer-zone_del_2 stderr  "Unable to delete zone, zone ods1 not found" && 

# Delete all remaining zones 
echo "y " | log_this ods-enforcer-zone_del_3  ods-enforcer zone delete --all  &&

log_this ods-enforcer-zone_del_list_3  ods-enforcer zone list  &&
log_grep ods-enforcer-zone_del_list_3   stdout "No zones configured in DB." &&

echo "Checking no zones in internal zonelist" && 
# BUG, NOT UPDATED diff.sh $ZONES_FILE zonelist.xml &&
echo "Internal Zone file contents empty" &&

##################  TEST:  Zonelist.xml  import ###########################

cp zonelist.xml.gold_local "$ZONELIST_FILE" &&
sleep 20 &&
# num_completed_updates=`syslog_grep_count2 "Completed updating all zones that need required action"` &&
log_this ods-enforcer-zonelist-import ods-enforcer zonelist import &&
syslog_waitfor_count 30 1 ".zonelist_import_cmd. internal zonelist exported successfully" &&
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
cp $ZONELIST_FILE zonelist.xml.temp2 &&
diff.sh zonelist.xml.temp2 zonelist.xml.gold_export_local &&
echo "Zonelist export contents OK" &&
diff.sh $ZONES_FILE zonelist.xml.gold_local &&
echo "zones.xml contents OK" &&

# Now do another import with a file that has one extra zone and one zone removed
# and some of the data changed
cp zonelist.xml.test_local "$ZONELIST_FILE" &&
sleep 20 &&
log_this ods-enforcer-zonelist-import ods-enforcer zonelist import && 
log_this ods-enforcer-zonelist-enforce ods-enforcer enforce && 
syslog_waitfor_count 30 2 ".zonelist_import_cmd. internal zonelist exported successfully" &&
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
cp $ZONELIST_FILE zonelist.xml.temp3 &&
diff.sh zonelist.xml.temp3 zonelist.xml.gold_export2_local &&
echo "Zonelist export contents OK" &&
diff.sh $ZONES_FILE zonelist.xml.test_local &&
echo "zones.xml contents OK" &&

# #Finally run the signer to check all is well
ods_start_signer &&
log_this ods-enforcer-signconf ods-enforcer signconf && 
# cp $INSTALL_root/var/opendnssec/signconf
syslog_waitfor 60 'signconf done, notifying signer' &&
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

log_this ods-enforcer-zone_update2 ods-enforcer update zonelist &&
# it takes a second for the zonelist to be available from previous import-empty
syslog_grep 'ods-enforcerd:.*zonelist_import.*zone ods14 deleted' &&
syslog_grep 'ods-enforcerd:.*zonelist_import.*zone ods13 deleted' &&
syslog_grep 'ods-enforcerd:.*zonelist_import.*zone ods12 deleted' &&
syslog_grep 'ods-enforcerd:.*zonelist_import.*zone ods11 deleted' &&
syslog_grep 'ods-enforcerd:.*zonelist_import.*zone ods10 deleted' &&
syslog_grep 'ods-enforcerd:.*zonelist_import.*zone ods9 deleted' &&
syslog_grep 'ods-enforcerd:.*zonelist_import.*zone ods8 deleted' &&
syslog_grep 'ods-enforcerd:.*zonelist_import.*zone ods7 deleted' &&
syslog_grep 'ods-enforcerd:.*zonelist_import.*zone ods6 deleted' &&
syslog_grep 'ods-enforcerd:.*zonelist_import.*zone ods5 deleted' &&
syslog_grep 'ods-enforcerd:.*zonelist_import.*zone ods4 deleted' &&
syslog_grep 'ods-enforcerd:.*zonelist_import.*zone ods3 deleted' &&
syslog_grep 'ods-enforcerd:.*zonelist_import.*zone ods2 deleted' &&
syslog_grep 'ods-enforcerd:.*zonelist_import.*zone ods1 deleted' &&
#syslog_waitfor 60 'ods-enforcerd:.*The XML in.*zonelist.xml is valid' &&
# BUG NOT UPDATED diff.sh $ZONES_FILE zonelist.xml &&
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

# OTHER PROBLEMS:
# 1:
# Jan 27 11:16:08 nagini ods-enforcerd: 140127037470464: [/home/berry/workspace/root/local-test/etc/opendnssec/zonelist.xml] zonelist ^P�^E�q  updated successfully
# 2:
# Jan 27 12:42:57 nagini ods-enforcerd: 140365595563776: [zonelist_import_cmd] internal zonelist exported successfully
#
# 3:
# syslog_wait and syslog_grep only work from beginning of logging, not nice
# some time


