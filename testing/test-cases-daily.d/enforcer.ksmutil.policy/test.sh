#!/usr/bin/env bash

#TEST: Test to check that policy import/export/list works correctly
#TODO: we need to check the command ods-ksmutil policy purge later

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

# Set the policy to the initial value
log_this ods-ksmutil-update cp -- "kasp.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
log_this ods-ksmutil-update ods-ksmutil update kasp &&
log_grep ods-ksmutil-update stdout 'Notifying enforcer of new database...' &&

#TODO: - incomplete parameter validation
! log_this ods-ksmutil-export-incomplete-parameters ods-ksmutil policy export &&
log_grep ods-ksmutil-export-incomplete-parameters stdout 'please specify either --policy <policy> or --all' &&
! log_this ods-ksmutil-export-incomplete-parameters ods-ksmutil policy &&
log_grep ods-ksmutil-export-incomplete-parameters stdout 'Unknown command: policy NULL' &&
echo "************incomplete parameter validation OK******************" &&
echo &&

# test the command "ods-ksmutil policy list"
log_this ods-ksmutil-list ods-ksmutil policy list &&
log_grep ods-ksmutil-list stdout 'default2                         default fast test policy' &&
echo "************list OK******************" &&
echo &&

# Export the policy default and check some of its values
log_this ods-ksmutil-export-p ods-ksmutil policy export -p default &&
log_grep ods-ksmutil-export-p stdout '<Policy name="default">' &&
log_grep ods-ksmutil-export-p stdout '<KSK>' &&
log_grep ods-ksmutil-export-p stdout '<Algorithm length="2048">7</Algorithm>' &&
log_grep ods-ksmutil-export-p stdout '<Lifetime>PT345600S</Lifetime>' &&
log_grep ods-ksmutil-export-p stdout '<Repository>SoftHSM</Repository>' &&
log_grep ods-ksmutil-export-p stdout '<Standby>0</Standby>' &&
log_grep ods-ksmutil-export-p stdout '</KSK>' &&
log_grep_count ods-ksmutil-export-p stdout '<Algorithm length="1024">7</Algorithm>' 1 &&
echo "************export -p default OK******************" &&
echo &&

# Export the policy default2 and check some of its values
log_this ods-ksmutil-export-p ods-ksmutil policy export -p default2 &&
log_grep ods-ksmutil-export-p stdout '<Policy name="default2">' &&
log_grep_count ods-ksmutil-export-p stdout '<Algorithm length="1024">7</Algorithm>' 2 &&
echo "************export -p default2 OK******************" &&
echo &&

# Export the policy by command "ods-ksmutil policy export -all" and check some of its value
log_this ods-ksmutil-export-p ods-ksmutil policy export --all &&
log_grep_count ods-ksmutil-export-p stdout '<Policy name="default">' 2 &&
log_grep_count ods-ksmutil-export-p stdout '<Policy name="default2">' 2 &&
log_grep_count ods-ksmutil-export-p stdout '<Algorithm length="1024">7</Algorithm>' 4 &&
echo "****************export -all OK*********************" &&
echo &&

# test the command "ods-ksmutil policy import"
log_this ods-ksmutil-import cp -- "kasp_3policies.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
# kasp_3policies.xml: add default3 in the kasp.xml
log_this ods-ksmutil-import ods-ksmutil policy import &&
# 'diff' between the imported and exported they should be the same
log_this ods-ksmutil-export-3policies ods-ksmutil policy export --all &&
log_grep ods-ksmutil-export-3policies stdout '<Policy name="default3">' &&
echo "****************import -all OK*********************" &&
echo &&


# test the command "ods-ksmutil policy list" again
log_this ods-ksmutil-list ods-ksmutil policy list &&
log_grep ods-ksmutil-list stdout 'default3                         default fast test policy' &&
echo "****************list OK*********************" &&
echo &&

#TODO: - check the invalid XML won't import, and we should get the expected errors
log_this ods-ksmutil-export-invalidXML cp -- "kasp_invalid.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
! log_this ods-ksmutil-export-invalidXML ods-ksmutil policy import &&
log_grep ods-ksmutil-export-invalidXML stderr 'ods-kaspcheck returned an error, please check your policy' &&
echo "****************check the invalid XML OK*********************" &&
echo &&

# Set the policy to original value
log_this ods-ksmutil-export-invalidXML cp -- "kasp.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
log_this ods-ksmutil-export-invalidXML ods-ksmutil policy import &&
# log_this ods-ksmutil-export1 ods-ksmutil update kasp &&
log_this ods-ksmutil-export-2policies ods-ksmutil policy export --all &&
log_grep ods-ksmutil-export-2policies stdout '<Policy name="default3">' &&
# to prove that The commands (ods-ksmutil policy import and ods-ksmutil update kasp) can only add policies, but cannot delete policies from database.
echo "****************test more about export OK*********************" &&
echo &&

#TODO: we should test more about command "ods-ksmutil policy purge"
echo "y" | log_this ods-ksmutil-purge ods-ksmutil policy purge &&
log_grep ods-ksmutil-purge stdout 'No zones on policy default2; purging...' &&
log_grep ods-ksmutil-purge stdout 'No zones on policy default3; purging...' &&
echo "****************test policy purge OK*********************" &&
echo &&

# Set the policy to original value and end our test
log_this ods-ksmutil-update cp -- "kasp.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
log_this ods-ksmutil-update ods-ksmutil update kasp &&

echo &&
echo "****************all test OK******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1


