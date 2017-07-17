#!/usr/bin/env bash
#
#TEST: Test that the ods-enforcer zone add/delete works correctly
#TEST: Also test that 'basic' zonelist import/export works 

#TODO: Need to extend this test to make sure the signer is picking up the correct files when changes are mode!!!!

#TODO: Test that the system starts up with no zonefile and that a message reports this properly

ZONES_FILE=$INSTALL_ROOT/var/opendnssec/enforcer/zones.xml
ZONELIST_FILE=$INSTALL_ROOT/etc/opendnssec/zonelist.xml

local num_completed_updates

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
# log_grep ods-enforcer-zone_none_2   stdout "No zones in database." &&
# 
# ods_stop_enforcer &&

#cp zonelist.xml "$ZONELIST_FILE" &&
ods_reset_env &&
ods_start_enforcer && 

# Now a real but empty zone list
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_none   ods-enforcer zone list &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_none   stdout "No zones in database." &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && ##################  TEST:  Zone add success ###########################
echo "LINE: ${LINENO} " && #0. Test all default
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods0 &&
echo "LINE: ${LINENO} " && syslog_waitfor 60 '\[zone_add_cmd\] internal zonelist updated successfully' &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && #1. Test existing policy
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods1 --policy Policy1 &&
echo "LINE: ${LINENO} " && log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods1 added successfully" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Test default input type and file
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods2 --policy Policy1 --input $INSTALL_ROOT/var/opendnssec/unsigned/ods2 &&
echo "LINE: ${LINENO} " && log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods2 added successfully" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && #2. Test more parameters
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods3 --in-type File --out-type File &&
echo "LINE: ${LINENO} " && log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods3 added successfully" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods4 --in-type File --out-type File --input $INSTALL_ROOT/var/opendnssec/unsigned/ods4 --output $INSTALL_ROOT/var/opendnssec/signed/ods4 &&
echo "LINE: ${LINENO} " && log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods4 added successfully" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods5 --in-type File --out-type DNS &&
echo "LINE: ${LINENO} " && log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods5 added successfully" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods6 --in-type File --out-type DNS --input $INSTALL_ROOT/var/opendnssec/unsigned/ods6 --output $INSTALL_ROOT/etc/opendnssec/addns.xml &&
echo "LINE: ${LINENO} " && log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods6 added successfully" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods7 --in-type DNS --out-type DNS &&
echo "LINE: ${LINENO} " && log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods7 added successfully" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods8 --in-type DNS --out-type DNS --input $INSTALL_ROOT/etc/opendnssec/addns.xml --output $INSTALL_ROOT/etc/opendnssec/addns.xml &&
echo "LINE: ${LINENO} " && log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods8 added successfully" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods9 --in-type DNS --out-type File &&
echo "LINE: ${LINENO} " && log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods9 added successfully" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods10 --in-type DNS --out-type File --input $INSTALL_ROOT/etc/opendnssec/addns.xml --output $INSTALL_ROOT/var/opendnssec/signed/ods10 &&
echo "LINE: ${LINENO} " && log_waitfor ods-enforcer-zone_add   stdout 900 "Zone ods10 added successfully" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add_list   ods-enforcer zone list &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list   stdout "ods0[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list   stdout "ods1[[:space:]]*Policy1" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list   stdout "ods2[[:space:]]*Policy1" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list   stdout "ods3[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list   stdout "ods4[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list   stdout "ods5[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list   stdout "ods6[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list   stdout "ods7[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list   stdout "ods8[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list   stdout "ods9[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list   stdout "ods10[[:space:]]*default" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && ##################  TEST:  Zone add failures/warnings ###########################
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Test re-add of of existing zone
echo "LINE: ${LINENO} " && ! log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods1 --policy Policy1 &&
echo "LINE: ${LINENO} " && log_waitfor ods-enforcer-zone_add_bad stderr 900 "Unable to add zone, zone already exists" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && #3. Test noneexistent policy 
echo "LINE: ${LINENO} " && ! log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods11 --policy NonexistentPolicy &&
echo "LINE: ${LINENO} " && log_waitfor ods-enforcer-zone_add_bad   stderr 900 "Unable to find policy NonexistentPolicy needed for adding the zone!" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && #4. Test bad parameter
echo "LINE: ${LINENO} " && ! log_this ods-enforcer-zone_add_bad   ods-enforcer zone &&
echo "LINE: ${LINENO} " && ##### TO FIX: 
echo "LINE: ${LINENO} " && log_waitfor ods-enforcer-zone_add_bad stderr 900 "Unknown command zone" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && ##### TO FIX: TO be implemented in 2.0
echo "LINE: ${LINENO} " && # #5. Test none exist input file
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods11 --input $INSTALL_ROOT/var/opendnssec/unsigned/ods11 --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods11.xml &&
echo "LINE: ${LINENO} " && # log_grep ods-enforcer-zone_add_bad   stdout "WARNING: The input file $INSTALL_ROOT/var/opendnssec/unsigned/ods11 for zone ods11 does not currently exist. The zone will been added to the database anyway" &&
echo "LINE: ${LINENO} " && # 
echo "LINE: ${LINENO} " && # mv $INSTALL_ROOT/etc/opendnssec/addns.xml $INSTALL_ROOT/etc/opendnssec/addns.xml.backup &&
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods12 --input $INSTALL_ROOT/etc/opendnssec/addns.xml --in-type DNS --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods12.xml &&
echo "LINE: ${LINENO} " && # log_grep ods-enforcer-zone_add_bad   stdout "WARNING: The input file $INSTALL_ROOT/etc/opendnssec/addns.xml for zone ods12 does not currently exist. The zone will been added to the database anyway" &&
echo "LINE: ${LINENO} " && # 
echo "LINE: ${LINENO} " && # #6. Test none exist output file in the case of --out-type DNS
echo "LINE: ${LINENO} " && # mv $INSTALL_ROOT/etc/opendnssec/addns.xml.backup $INSTALL_ROOT/etc/opendnssec/addns.xml &&
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add_bad   ods-enforcer zone add --zone ods13 --input $INSTALL_ROOT/etc/opendnssec/addns.xml --in-type DNS --out-type DNS --output $INSTALL_ROOT/etc/opendnssec/addns1.xml --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods13.xml &&
echo "LINE: ${LINENO} " && # log_grep ods-enforcer-zone_add_bad   stdout "WARNING: The output file $INSTALL_ROOT/etc/opendnssec/addns1.xml for zone ods13 does not currently exist." &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && ##################  TEST:  Zonelist.xml  export ###########################
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Check the zones.xml internal file is written (2.0 new behaviour)
echo "LINE: ${LINENO} " && ods_comparexml --format-zonelist $ZONES_FILE zonelist.xml.gold &&
echo "LINE: ${LINENO} " && cp $ZONES_FILE zonelist.xml.import &&
echo "LINE: ${LINENO} " && echo "zones.xml contents OK" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Check the zonelist.xml is still empty (2.0 default behaviour)
echo "LINE: ${LINENO} " && echo "Checking zonelist contents" && 
echo "LINE: ${LINENO} " && ods_comparexml --format-zonelist $ZONELIST_FILE zonelist.xml &&
echo "LINE: ${LINENO} " && echo "Zonelist contents OK" && 
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Check the export against a gold
echo "LINE: ${LINENO} " && log_this ods-enforcer-zonelist-export ods-enforcer zonelist export &&
echo "LINE: ${LINENO} " && cp $ZONELIST_FILE zonelist.xml.temp &&
echo "LINE: ${LINENO} " && ods_comparexml --format-zonelist zonelist.xml.temp zonelist.xml.gold_export &&
echo "LINE: ${LINENO} " && echo "Zonelist export contents OK" && 
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Now add _and_ update the zonelist (2.0 new behaviour)
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add_1   ods-enforcer zone add --zone ods14 --xml &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_1   stdout "Zone ods14 added successfully" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_1   stdout "Zonelist .* updated successfully" &&
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add_list_1   ods-enforcer zone list &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_1   stdout "ods14[[:space:]]*default" &&
echo "LINE: ${LINENO} " && #log_grep ods-enforcer-zone_add_list_1   stdout "Found zone ods14 in DB but not zonelist." &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Exported zonelist should be different (not checked in detail)....
echo "LINE: ${LINENO} " && echo "Checking zonelist contents again after update of zonelist.xml" && 
echo "LINE: ${LINENO} " && log_this ods-enforcer-zonelist-export ods-enforcer zonelist export &&
echo "LINE: ${LINENO} " && ! ods_comparexml --format-zonelist $ZONELIST_FILE zonelist.xml.gold &&
echo "LINE: ${LINENO} " && $GREP -q -- "ods14" "$ZONELIST_FILE" &&
echo "LINE: ${LINENO} " && echo "Zonelist contents OK again" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # And the zones.xml should be different too
echo "LINE: ${LINENO} " && ! ods_comparexml --format-zonelist $ZONES_FILE zonelist.xml.gold &&
echo "LINE: ${LINENO} " && $GREP -q -- "ods14" "$ZONES_FILE" &&
echo "LINE: ${LINENO} " && echo "zones.xml contents OK" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Exported zonelist should be different (not checked in detail)....
echo "LINE: ${LINENO} " && log_this ods-enforcer-zonelist-export ods-enforcer zonelist export &&
echo "LINE: ${LINENO} " && cp $ZONELIST_FILE zonelist.xml.temp1 &&
echo "LINE: ${LINENO} " && ! ods_comparexml --format-zonelist zonelist.xml.temp1 zonelist.xml.gold_export &&
echo "LINE: ${LINENO} " && $GREP -q -- "ods14" "zonelist.xml.temp1" &&
echo "LINE: ${LINENO} " && echo "Zonelist export contents OK" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && ##################  TEST:  Zone delete command  ###########################
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Delete zone successfully 
echo "LINE: ${LINENO} " && ods_enforcer_idle &&
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_del_1  ods-enforcer zone delete -z ods1  &&
echo "LINE: ${LINENO} " && ods_enforcer_idle &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_del_1   stdout "Deleted zone ods1 successfully" &&
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_del_list_1   ods-enforcer zone list &&
echo "LINE: ${LINENO} " && ! log_grep ods-enforcer-zone_del_list_1   stdout "ods1[[:space:]]*Policy1" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && echo "Checking zonelist contents again after delete" && 
echo "LINE: ${LINENO} " && ### ods_comparexml --format-zonelist $ZONELIST_FILE zonelist.xml.gold &&
echo "LINE: ${LINENO} " && $GREP -q -- "ods1\"" "$ZONELIST_FILE" &&
echo "LINE: ${LINENO} " && $GREP -q -- "ods14" "$ZONELIST_FILE" &&
echo "LINE: ${LINENO} " && ! $GREP -q -- "ods1\"" "$ZONES_FILE" &&
echo "LINE: ${LINENO} " && $GREP -q -- "ods14" "$ZONES_FILE" &&
echo "LINE: ${LINENO} " && echo "Zonelist contents OK again" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # sometimes the connection is closed on slow machines, ignoring for now any return code
echo "LINE: ${LINENO} " && ods_enforcer_idle &&
echo "LINE: ${LINENO} " && ( log_this ods-enforcer-zone_del_2  ods-enforcer zone delete --zone ods2 --xml || true ) &&
echo "LINE: ${LINENO} " && ods_enforcer_idle &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_del_2   stdout "Deleted zone ods2 successfully" &&
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_del_list_2   ods-enforcer zone list &&
echo "LINE: ${LINENO} " && ! log_grep ods-enforcer-zone_del_list_2   stdout "ods2[[:space:]]*Policy1" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Check it is gone from the zonelist.xml
echo "LINE: ${LINENO} " && ! $GREP -q -- "ods2" "$ZONELIST_FILE" &&
echo "LINE: ${LINENO} " && ! $GREP -q -- "ods2" "$ZONES_FILE" &&
echo "LINE: ${LINENO} " && $GREP -q -- "ods14" "$ZONELIST_FILE" &&
echo "LINE: ${LINENO} " && $GREP -q -- "ods14" "$ZONES_FILE" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Test deleting a non-existant zone
echo "LINE: ${LINENO} " && ! log_this ods-enforcer-zone_del_2  ods-enforcer zone delete -z ods1  &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_del_2 stderr  "Unable to delete zone, zone ods1 not found" && 
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # This sleep is necessary to ensure that deleting zone ods1 is completely
echo "LINE: ${LINENO} " && # done, otherwise deleting the other zones will partially fail (silently)
echo "LINE: ${LINENO} " && ods_enforcer_idle &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Delete all remaining zones 
echo "LINE: ${LINENO} " && echo "y " | log_this ods-enforcer-zone_del_3  ods-enforcer zone delete --all  &&
echo "LINE: ${LINENO} " && # Need a sleep to make sure all are gone
echo "LINE: ${LINENO} " && ods_enforcer_idle &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_del_list_3  ods-enforcer zone list  &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_del_list_3   stdout "No zones in database." &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && echo "Checking no zones in internal zonelist" && 
echo "LINE: ${LINENO} " && ods_comparexml --format-zonelist $ZONES_FILE zonelist.xml &&
echo "LINE: ${LINENO} " && echo "Internal Zone file contents empty" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && ##################  TEST:  Zonelist.xml  import ###########################
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && cp zonelist.xml.import "$ZONELIST_FILE" &&
echo "LINE: ${LINENO} " && ods_enforcer_idle &&
echo "LINE: ${LINENO} " && # we no longer have a good way to test this, just sleep for 2 minutes, as it should take only 20 seconds or so for now
echo "LINE: ${LINENO} " && #num_completed_updates=`syslog_grep_count2 "Completed updating all zones that need required action"` &&
echo "LINE: ${LINENO} " && log_this ods-enforcer-zonelist-import ods-enforcer zonelist import &&
echo "LINE: ${LINENO} " && #syslog_waitfor_count 30 $(( num_completed_updates + 1 )) "Completed updating all zones that need required action" &&
echo "LINE: ${LINENO} " && ods_enforcer_idle &&
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add_list_2  ods-enforcer zone list  &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_2   stdout "ods0[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_2   stdout "ods1[[:space:]]*Policy1" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_2   stdout "ods2[[:space:]]*Policy1" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_2   stdout "ods3[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_2   stdout "ods4[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_2   stdout "ods5[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_2   stdout "ods6[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_2   stdout "ods7[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_2   stdout "ods8[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_2   stdout "ods9[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_2   stdout "ods10[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_2   stdout "ods11[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_2   stdout "ods12[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_2   stdout "ods13[[:space:]]*default" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Check the export gives the same thing  (note - we use a different gold file here as the order
echo "LINE: ${LINENO} " && # in the exported file is not the same as that in the configuration file)
echo "LINE: ${LINENO} " && log_this ods-enforcer-zonelist-export ods-enforcer zonelist export &&
echo "LINE: ${LINENO} " && cp $ZONELIST_FILE zonelist.xml.temp2 &&
echo "LINE: ${LINENO} " && ods_comparexml --format-zonelist zonelist.xml.temp2 zonelist.xml.gold_export &&
echo "LINE: ${LINENO} " && echo "Zonelist export contents OK" &&
echo "LINE: ${LINENO} " && ods_comparexml --format-zonelist $ZONES_FILE zonelist.xml.gold &&
echo "LINE: ${LINENO} " && echo "zones.xml contents OK" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Now do another import with a file that has one extra zone and one zone removed
echo "LINE: ${LINENO} " && # and some of the data changed
echo "LINE: ${LINENO} " && sed -e "s%@INSTALL_ROOT@%$INSTALL_ROOT%" < zonelist.xml.test > "$ZONELIST_FILE" &&
echo "LINE: ${LINENO} " && cp "$ZONELIST_FILE" zonelist.xml.test_local &&
echo "LINE: ${LINENO} " && ods_enforcer_idle &&
echo "LINE: ${LINENO} " && log_this ods-enforcer-zonelist-import ods-enforcer zonelist import --remove-missing-zones && 
echo "LINE: ${LINENO} " && log_this ods-enforcer-zonelist-enforce ods-enforcer enforce && 
echo "LINE: ${LINENO} " && syslog_waitfor_count 30 2 ".zonelist_import_cmd. internal zonelist exported successfully" &&
echo "LINE: ${LINENO} " && log_this ods-enforcer-zone_add_list_3  ods-enforcer zone list  &&
echo "LINE: ${LINENO} " && ! log_grep ods-enforcer-zone_add_list_3   stdout "ods0[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_3   stdout "ods1[[:space:]]*Policy1" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_3   stdout "ods2[[:space:]]*Policy1" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_3   stdout "ods3[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_3   stdout "ods4[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_3   stdout "ods5[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_3   stdout "ods6[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_3   stdout "ods7[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_3   stdout "ods8[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_3   stdout "ods9[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_3   stdout "ods10[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_3   stdout "ods11[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_3   stdout "ods12[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_3   stdout "ods13[[:space:]]*default" &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zone_add_list_3   stdout "ods14[[:space:]]*default" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # There is a back-off task sometimes firing up here, which is not caught by
echo "LINE: ${LINENO} " && # the _idle.  This back-off task is generating the right signconf /with/
echo "LINE: ${LINENO} " && # keys once they are available.
echo "LINE: ${LINENO} " && # YBS: keygen will trigger enforce, enforce will trigger signconf.
echo "LINE: ${LINENO} " && # this sleep is no longer relevant.
echo "LINE: ${LINENO} " && #sleep 120 &&
echo "LINE: ${LINENO} " && ods_enforcer_idle &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && log_this ods-enforcer-zonelist-export ods-enforcer zonelist export &&
echo "LINE: ${LINENO} " && cp $ZONELIST_FILE zonelist.xml.temp3 &&
echo "LINE: ${LINENO} " && ods_comparexml --format-zonelist zonelist.xml.temp3 zonelist.xml.gold_export2 &&
echo "LINE: ${LINENO} " && echo "Zonelist export contents OK" &&
echo "LINE: ${LINENO} " && ods_comparexml --format-zonelist $ZONES_FILE zonelist.xml.test_local &&
echo "LINE: ${LINENO} " && echo "zones.xml contents OK" &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # #Finally run the signer to check all is well
echo "LINE: ${LINENO} " && ods_start_signer 10 &&
echo "LINE: ${LINENO} " && # Extra sleep to make sure signer is really started and able to receive
echo "LINE: ${LINENO} " && # signconf command
echo "LINE: ${LINENO} " && sleep 10 &&
echo "LINE: ${LINENO} " && log_this ods-enforcer-signconf ods-enforcer signconf && 
echo "LINE: ${LINENO} " && # The signconf will now be separate per zone, where there will now be a delay
echo "LINE: ${LINENO} " && # where zone ods11 does not get removed because it is still busy
echo "LINE: ${LINENO} " && ods_enforcer_idle &&
echo "LINE: ${LINENO} " && # cp $INSTALL_root/var/opendnssec/signconf
echo "LINE: ${LINENO} " && syslog_waitfor 300 'signconf done for zone ods1, notifying signer' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'signconf done for zone ods2, notifying signer' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'signconf done for zone ods3, notifying signer' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'signconf done for zone ods4, notifying signer' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'signconf done for zone ods5, notifying signer' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'signconf done for zone ods6, notifying signer' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'signconf done for zone ods7, notifying signer' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'signconf done for zone ods8, notifying signer' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'signconf done for zone ods9, notifying signer' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'signconf done for zone ods10, notifying signer' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'signconf done for zone ods11, notifying signer' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'signconf done for zone ods12, notifying signer' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'signconf done for zone ods13, notifying signer' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'signconf done for zone ods14, notifying signer' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] ods1' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] ods2' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] ods3' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] ods4' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] ods5' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] ods6' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] ods7' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] ods8' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] ods9' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] ods10' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] ods12' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] ods13' &&
echo "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] ods14' &&
echo "LINE: ${LINENO} " && ! syslog_grep 'ods-signerd: .*\[STATS\] ods0' &&
echo "LINE: ${LINENO} " && ! syslog_grep 'ods-signerd: .*\[STATS\] ods11' &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && ods_stop_signer &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && # Now import an empty zonelist
echo "LINE: ${LINENO} " && cp zonelist.xml "$ZONELIST_FILE" &&
echo "LINE: ${LINENO} " && log_this ods-enforcer-zonelist-import-empty ods-enforcer zonelist import --remove-missing-zones && 
echo "LINE: ${LINENO} " && ods_enforcer_idle &&
echo "LINE: ${LINENO} " && log_this ods-enforcer-zonelist-import-empty   ods-enforcer zone list &&
echo "LINE: ${LINENO} " && log_grep ods-enforcer-zonelist-import-empty   stdout "No zones in database." &&
echo "LINE: ${LINENO} " && 
echo "LINE: ${LINENO} " && log_this ods-enforcer-zonelist-export ods-enforcer zonelist export &&
echo "LINE: ${LINENO} " && cp $ZONELIST_FILE zonelist.xml.temp4 &&
echo "LINE: ${LINENO} " && ods_comparexml --format-zonelist zonelist.xml.temp4 zonelist.xml.platinum &&
echo "LINE: ${LINENO} " && echo "Zonelist export contents OK" &&
echo "LINE: ${LINENO} " && 

ods_stop_enforcer && 

# Clean up
rm -f zonelist.xml.test_local &&
rm -f zonelist.xml.gold_import &&
rm -f zonelist.xml.temp* &&
rm -f *~ &&

echo &&
echo "************OK******************" &&
echo &&
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

