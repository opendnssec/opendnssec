#!/usr/bin/env bash

#TEST: Test to check that policy import/export/list works correctly

# Cater for the fact that solaris needs gdiff and openbsd needs gdiff installed!
# Really need to get gdiff installed and then use a fins_diff function....
local diff_ignore_whitespace="diff -I ^[[:space:]]*$  -w -B " 
case "$DISTRIBUTION" in
	sunos  )
		diff_ignore_whitespace="gdiff -I ^[[:space:]]*$  -w -B"
		;;
	openbsd )
		return 0
		;;
esac


if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

  #############Start with a kasp with 2 policies  #############

# test the command "ods-ksmutil policy list"
log_this ods-ksmutil-list_1 ods-ksmutil policy list &&
log_grep ods-ksmutil-list_1 stdout 'default[[:space:]]*default fast test policy' &&
log_grep ods-ksmutil-list_1 stdout 'default2[[:space:]]*default fast test policy2' &&
echo "************list OK******************" &&

# Export the policy default and check some of its values
ods-ksmutil policy export -p default > kasp.xml.temp &&
$diff_ignore_whitespace  kasp.xml.temp kasp.xml.gold_export_default_policy &&
rm kasp.xml.temp &&

echo "************export -p default OK******************" &&

# Export both the policies
ods-ksmutil policy export --all > kasp.xml.temp &&
$diff_ignore_whitespace  kasp.xml.temp kasp.xml.gold_export_2_policies &&
rm kasp.xml.temp &&

echo "************export --all OK******************" &&

ods_start_enforcer &&
sleep 5 &&
log_this ods-ksmutil-export-after_run ods-ksmutil policy export --all &&
ods_stop_enforcer &&

############# Now add/update policyies  #############

# test the command "ods-ksmutil policy import" and import 3 policies
log_this ods-ksmutil-import_1 cp -- "kasp_3policies.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
log_this ods-ksmutil-import_1 ods-ksmutil policy import &&
echo "************import of 3 policies OK******************" &&
log_this ods-ksmutil-list_2 ods-ksmutil policy list &&
log_grep ods-ksmutil-list_2 stdout 'default[[:space:]]*default fast test policy' &&
log_grep ods-ksmutil-list_2 stdout 'default2[[:space:]]*default fast test policy2' &&
log_grep ods-ksmutil-list_2 stdout 'default3[[:space:]]*default fast test policy3' &&
echo "************list OK******************" &&
# Export again and check against the imported kasp
ods-ksmutil policy export --all > kasp.xml.temp &&
$diff_ignore_whitespace  kasp.xml.temp kasp.xml.gold_export_3_policies &&
rm kasp.xml.temp &&

echo "************export OK******************" &&
echo &&

############# Now try to remove a policy  #############

# Set the kasp back to the original kaps with 2 policies, this time use the exported file to test a round trip
log_this ods-ksmutil-import_2 cp -- "kasp.xml.gold_export_2_policies" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
log_this ods-ksmutil-import_2 ods-ksmutil policy import &&
echo "************import of 2 policies OK******************" &&
# All 3 policies should still be there
log_this ods-ksmutil-list_3 ods-ksmutil policy list &&
log_grep ods-ksmutil-list_3 stdout 'default[[:space:]]*default fast test policy' &&
log_grep ods-ksmutil-list_3 stdout 'default2[[:space:]]*default fast test policy2' &&
log_grep ods-ksmutil-list_3 stdout 'default3[[:space:]]*default fast test policy3' &&
echo "************list OK******************" &&
# check the kasp hasn't been updated
$diff_ignore_whitespace "$INSTALL_ROOT/etc/opendnssec/kasp.xml" "kasp.xml.gold_export_2_policies" &&
echo "************kasp OK******************" &&

# Now use purge to clean up policy 3 and it will also remove policy 2
echo "y" | log_this ods-enforcer-policy-purge_1 "ods-ksmutil policy purge" &&
# check the kasp has been updated
$diff_ignore_whitespace  "$INSTALL_ROOT/etc/opendnssec/kasp.xml"  kasp.xml.gold_export_default_policy &&
echo "************export OK******************" &&

# Export the remaining policy
ods-ksmutil policy export --all > kasp.xml.temp &&
$diff_ignore_whitespace  kasp.xml.temp kasp.xml.gold_export_default_policy &&
rm kasp.xml.temp &&

echo "************export OK******************" &&
echo &&

# Now check we export an empty policy 
echo "y" | log_this ods-ksmutil-remove-zone ods-ksmutil zone delete --all &&
# Now use purge to remomve the remainin policy
echo "y" | log_this ods-enforcer-policy-purge_2 "ods-ksmutil policy purge" &&
# check the kasp has been updated
$diff_ignore_whitespace  "$INSTALL_ROOT/etc/opendnssec/kasp.xml"  kasp.xml.gold_export_empty &&
echo "************empty kasp OK******************" &&
echo &&

############ Check some error cases for the commands now ###########################

# check the invalid XML won't import, and we should get the expected errors
log_this ods-ksmutil-import-invalidXML cp -- "kasp_invalid.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
! log_this ods-ksmutil-import-invalidXML ods-ksmutil policy import &&
log_grep ods-ksmutil-import-invalidXML stdout 'Error: unable to parse file ' &&
log_grep ods-ksmutil-import-invalidXML stdout 'Failed to update policies' &&
echo "****************check the invalid XML OK*********************" &&
echo &&

# check the file won't import if a repo does not exist, and we should get the expected errors
log_this ods-ksmutil-import-invalidXML_1 cp -- "kasp_missing_repo.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
! log_this ods-ksmutil-import-invalidXML_1 ods-ksmutil policy import &&
log_grep ods-ksmutil-import-invalidXML_1 stdout "Error: unable to find repository bob" &&
echo "****************check the invalid XML OK*********************" &&
echo &&

# Test incomplete command line for export
! log_this ods-ksmutil-export-incomplete-parameters ods-ksmutil policy export &&
log_grep ods-ksmutil-export-incomplete-parameters stdout 'please specify either --policy <policy> or --all' &&
! log_this ods-ksmutil-export-incomplete-parameters ods-ksmutil policy &&
log_grep ods-ksmutil-export-incomplete-parameters stdout 'Unknown command: policy NULL' &&
echo "************incomplete parameter validation OK******************" &&
echo &&



echo &&
echo "****************all test OK******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1


