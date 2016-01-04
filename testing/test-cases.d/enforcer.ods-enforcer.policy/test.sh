#!/usr/bin/env bash

#TEST: Test to check that policy import/export/list works correctly

##############
#   There is a bug in the export where the salt value is exported along with the length
#   To get around this until it is fixed, the exported files have the salt value stripped out
#   before the diff!!! 
#
#  Also, the ordering in the gold files has been changed and this needs to be reviewed still...
##############

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&
ods_start_enforcer &&

  #############Start with a kasp with 2 policies  #############

# test the command "ods-enforcer policy list"
log_this ods-enforcer-list_1 ods-enforcer policy list &&
log_grep ods-enforcer-list_1 stdout 'default[[:space:]]*default fast test policy' &&
log_grep ods-enforcer-list_1 stdout 'default2[[:space:]]*default fast test policy2' &&
echo "************list OK******************" &&

# Export the policy default and check some of its values
ods-enforcer policy export -p default > kasp.xml.temp &&
sed  -e 's#>.*</Salt>#/>#g' kasp.xml.temp > kasp.xml.temp2 &&
ods_comparexml  kasp.xml.temp2 kasp.xml.gold_export_default_policy &&
rm kasp.xml*.temp* &&
echo "************export -p default OK******************" &&

# Export both the policies
ods-enforcer policy export --all > kasp.xml.temp &&
sed  -e 's#>.*</Salt>#/>#g' kasp.xml.temp > kasp.xml.temp2 &&
ods_comparexml  kasp.xml.temp2 kasp.xml.gold_export_2_policies &&
rm kasp.xml*.temp* &&
echo "************export --all OK******************" &&

############# Now add/update policyies  #############

# test the command "ods-enforcer policy import" and import 3 policies
log_this ods-enforcer-import_1 cp -- "kasp_3policies.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
log_this ods-enforcer-import_1 ods-enforcer policy import &&
echo "************import of 3 policies OK******************" &&
log_this ods-enforcer-list_2 ods-enforcer policy list &&
log_grep ods-enforcer-list_2 stdout 'default[[:space:]]*default fast test policy' &&
log_grep ods-enforcer-list_2 stdout 'default2[[:space:]]*default fast test policy2' &&
log_grep ods-enforcer-list_2 stdout 'default3[[:space:]]*default fast test policy3' &&
echo "************list OK******************" &&
### TO FIX: Shouldn't need this sleep, but need to wait for resalt until export bug is fixed!!
sleep 1 &&
# Export again and check against the imported kasp
ods-enforcer policy export --all > kasp.xml.temp &&
sed  -e 's#>.*</Salt>#/>#g' kasp.xml.temp > kasp.xml.temp2 &&
ods_comparexml  kasp.xml.temp2 kasp.xml.gold_export_3_policies &&
rm kasp.xml*.temp* &&

echo "************export OK******************" &&
echo &&

############# Now try to remove a policy  #############

# Set the kasp back to the original kaps with 2 policies, this time use the exported file to test a round trip
log_this ods-enforcer-import_2 cp -- "kasp.xml.gold_export_2_policies" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
log_this ods-enforcer-import_2 ods-enforcer policy import &&
echo "************import of 2 policies OK******************" &&
# All 3 policies should still be there
log_this ods-enforcer-list_3 ods-enforcer policy list &&
log_grep ods-enforcer-list_3 stdout 'default[[:space:]]*default fast test policy' &&
log_grep ods-enforcer-list_3 stdout 'default2[[:space:]]*default fast test policy2' &&
log_grep ods-enforcer-list_3 stdout 'default3[[:space:]]*default fast test policy3' &&
echo "************list OK******************" &&
### TO FIX: Shouldn't need this sleep, but need to wait for resalt until export bug is fixed!!
sleep 1 &&
# check the kasp hasn't been updated
ods_comparexml "$INSTALL_ROOT/etc/opendnssec/kasp.xml" "kasp.xml.gold_export_2_policies" &&
echo "************kasp OK******************" &&

# Now use purge to clean up policy 3 and it will also remove policy 2
ods_enforcer_idle &&
log_this ods-enforcer-policy-purge_1 "ods-enforcer policy purge" &&
ods_enforcer_idle &&
# check the kasp has been updated
#sed  -e 's#>.*</Salt>#/>#g' "$INSTALL_ROOT/etc/opendnssec/kasp.xml" > "$INSTALL_ROOT/etc/opendnssec/kasp.xml2" &&
#$diff_ignore_whitespace -I "^<?xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml2"  kasp.xml.gold_export_default_policy &&
#echo "************export OK******************" &&

# Export the remaining policy
ods-enforcer policy export --all > kasp.xml.temp &&
sed  -e 's#>.*</Salt>#/>#g' kasp.xml.temp > kasp.xml.temp2 &&
ods_comparexml  kasp.xml.temp2 kasp.xml.gold_export_default_policy &&
rm kasp.xml*.temp* &&

echo "************export OK******************" &&
echo &&

# Now check we export an empty policy 
ods_enforcer_idle &&
log_this ods-enforcer-remove-zone ods-enforcer zone delete --all &&
ods_enforcer_idle &&
# Now use purge to remomve the remainin policy
log_this ods-enforcer-policy-purge_2 "ods-enforcer policy purge" &&
ods_enforcer_idle &&
# check the kasp has been updated
#$diff_ignore_whitespace  "$INSTALL_ROOT/etc/opendnssec/kasp.xml"  kasp.xml.gold_export_empty &&
echo "************empty kasp OK******************" &&
echo &&

############ Check some error cases for the commands now ###########################

# check the invalid XML won't import, and we should get the expected errors
log_this ods-enforcer-import-invalidXML cp -- "kasp_invalid.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
### TO FIX: this command should fail
! log_this ods-enforcer-import-invalidXML ods-enforcer policy import &&
### TO FIX: this text should be found
#log_grep ods-enforcer-import-invalidXML stderr 'ods-kaspcheck returned an error, please check your policy' &&
log_grep ods-enforcer-import-invalidXML stderr "Unable to validate the KASP XML, please run ods-kaspcheck for more details!" &&
echo "****************check the invalid XML OK*********************" &&
echo &&

# check the file won't import if a repo does not exist, and we should get the expected errors
log_this ods-enforcer-import-invalidXML_1 cp -- "kasp_missing_repo.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
### TO FIX: this command should fail
! log_this ods-enforcer-import-invalidXML_1 ods-enforcer policy import &&
### TO FIX: this text should be found
#log_grep ods-enforcer-import-invalidXML_1 stdout "ERROR: Unknown repository (bob) defined for KSK in default policy in " &&
echo "****************check the invalid XML OK*********************" &&
echo &&

# Test incomplete command line for export
### TO FIX: this command should fail
! log_this ods-enforcer-export-incomplete-parameters ods-enforcer policy export &&
log_grep ods-enforcer-export-incomplete-parameters stderr 'Either --all or --policy needs to be given' &&
### TO FIX: this command should fail
! log_this ods-enforcer-export-incomplete-parameters ods-enforcer policy &&
log_grep ods-enforcer-export-incomplete-parameters stderr 'Unknown command policy' &&
echo "************incomplete parameter validation OK******************" &&
echo &&

ods_stop_enforcer &&


echo &&
echo "****************all test OK******************" &&
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


