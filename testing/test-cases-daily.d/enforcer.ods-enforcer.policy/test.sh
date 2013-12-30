#!/usr/bin/env bash

KASP_FILE=$INSTALL_ROOT/etc/opendnssec/kasp.xml
ZONELIST_FILE=$INSTALL_ROOT/etc/opendnssec/zonelist.xml

#TEST: Test to check that policy import/export/list/purge works correctly

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

# start the engine
ods_start_enforcer &&

# backup the kasp.xml and zonelist.xml
log_this ods-kasp-backup cp -- $KASP_FILE "kasp_backup.xml" &&
log_this ods-zonelist-backup cp -- $ZONELIST_FILE "zonelist_backup.xml" &&

# copy the kasp.xml model to $KASP_FILE
log_this ods-enforcer-update-kasp cp -- "kasp.xml" $KASP_FILE &&
log_this ods-enforcer-update-kasp ods-enforcer update kasp &&
log_grep ods-enforcer-update-kasp stdout 'flushing[[:space:]]all[[:space:]]tasks...' &&
echo "*****************update kasp OK*********************" &&
echo &&

# test the command "ods-enforcer policy list"
log_this ods-enforcer-list ods-enforcer policy list &&
log_grep ods-enforcer-list stdout 'default[[:space:]]*A[[:space:]]default[[:space:]]policy' &&
log_grep ods-enforcer-list stdout 'default_1[[:space:]]*A[[:space:]]default[[:space:]]policy[[:space:]]with[[:space:]]ShareKeys[[:space:]]enable' &&
log_grep ods-enforcer-list stdout 'default_2[[:space:]]*A[[:space:]]default[[:space:]]policy[[:space:]]with[[:space:]]ManualRollover[[:space:]]enable' &&
log_grep ods-enforcer-list stdout 'default_3[[:space:]]*A[[:space:]]default[[:space:]]policy[[:space:]]with[[:space:]]ShareKeys[[:space:]]and[[:space:]]ManualRollover[[:space:]]enable' &&
echo "****************policy list OK***********************" &&
echo &&

#TODO: - incomplete parameter validation
#! log_this ods-ksmutil-export-incomplete-parameters ods-ksmutil policy export &&
log_this ods-ksmutil-export-incomplete-parameters ods-enforcer policy &&
log_grep ods-ksmutil-export-incomplete-parameters stdout 'Unknown[[:space:]]command[[:space:]]policy.' &&
echo "************incomplete parameter validation OK******************" &&
echo &&

# Now export and check the values 
echo "Exporting policy" &&
ods-enforcer policy export > kasp.xml.temp && 
sed '/<Salt>.*/d' kasp.xml.temp  > kasp_no_salt.xml.temp && diff  -w  kasp_no_salt.xml.temp kasp.xml.gold_export && 
rm -f kasp_no_salt.xml.temp &&
echo "ods-enforcer policy export OK!!!" &&
# "export -p default" and check the values
ods-enforcer policy export -p default > kasp.xml.temp && 
sed '/<Salt>.*/d' kasp.xml.temp  > kasp_p_default.xml.temp && diff  -w  kasp_p_default.xml.temp kasp.xml.gold_export_p_default && 
rm -f kasp.xml.temp && 
rm -f kasp_p_default.xml.temp &&
echo "ods-enforcer policy export -p default OK!!!" &&
# TODO: add ods-enforcer policy export --all ?
echo "**********************Exported policy OK************************" &&
echo &&

# Now start to check out the command policy_purge
# clean all zones and copy the zonelist.xml model to $ZONELIST_FILE
echo "y" | log_this ods-enforcer-update-zonelist "ods-enforcer zone delete -a" &&
log_this ods-enforcer-update-zonelist cp -- "zonelist.xml" $ZONELIST_FILE &&
log_this ods-enforcer-update-zonelist "ods-enforcer update zonelist" &&
log_grep ods-enforcer-update-zonelist stdout 'update[[:space:]]zonelist[[:space:]]completed' &&
echo "*****************update zonelist OK*********************" &&
echo &&

#list zone
log_this ods-enforcer-zone-list_1 "ods-enforcer zone list" &&
log_grep ods-enforcer-zone-list_1 stdout 'example.com[[:space:]]*default' &&
log_grep ods-enforcer-zone-list_1 stdout 'example.net[[:space:]]*default_1' &&

#policy purge
echo "y" | log_this ods-enforcer-policy-purge_1 "ods-enforcer policy purge" &&
log_grep ods-enforcer-policy-purge_1 stdout "purge[[:space:]]policy[[:space:]]with[[:space:]]name[[:space:]]=[[:space:]]'default_2'[[:space:]]succeed!" &&
log_grep ods-enforcer-policy-purge_1 stdout "purge[[:space:]]policy[[:space:]]with[[:space:]]name[[:space:]]=[[:space:]]'default_3'[[:space:]]succeed!" &&

# Check that the policy is removed from the database
ods-enforcer policy list > policy_list_temp &&
`$GREP -q -- "default" policy_list_temp` &&
`$GREP -q -- "default_1" policy_list_temp` &&
! `$GREP -q -- "default_2" policy_list_temp` &&
! `$GREP -q -- "default_3" policy_list_temp` &&

# delete zone example.net and execute policy purge
echo "y" | log_this ods-enforcer-policy-purge_2 "ods-enforcer zone delete -z example.net" &&
echo "y" | log_this ods-enforcer-policy-purge_2 "ods-enforcer policy purge" &&
log_grep ods-enforcer-policy-purge_2 stdout "purge[[:space:]]policy[[:space:]]with[[:space:]]name[[:space:]]=[[:space:]]'default_1'[[:space:]]succeed!" &&
ods-enforcer policy list > policy_list_temp &&
`$GREP -q -- "default" policy_list_temp` &&
! `$GREP -q -- "default_1" policy_list_temp` &&
! `$GREP -q -- "default_2" policy_list_temp` &&
! `$GREP -q -- "default_3" policy_list_temp` &&
# Now the policy in database only left default so "policy export" is equal to "kasp.xml.gold_export_p_default" 
ods-enforcer policy export > policy_export_temp &&
sed '/<Salt>.*/d' policy_export_temp  > kasp.xml.export_p_default && diff  -w  kasp.xml.export_p_default kasp.xml.gold_export_p_default && 
rm -f policy_export_temp &&
rm -f kasp.xml.export_p_default &&
echo "*****************policy purge OK*********************" &&
echo &&

# policy import
log_this ods-enforcer-policy-import "ods-enforcer policy import" &&
log_grep ods-enforcer-policy-import stdout 'policy[[:space:]]import[[:space:]]completed' &&
# policy list
ods-enforcer policy list > policy_list_temp &&
`$GREP -q -- "default" policy_list_temp` &&
`$GREP -q -- "default_1" policy_list_temp` &&
`$GREP -q -- "default_2" policy_list_temp` &&
`$GREP -q -- "default_3" policy_list_temp` &&
rm -f policy_list_temp &&
echo "*****************policy import OK*********************" &&
echo &&

# copy the kasp.xml and zonelist.xml back to $KASP_FILE & $ZONELIST_FILE
log_this ods-kasp-backup cp -- "kasp_backup.xml" $KASP_FILE &&
rm -f kasp_backup.xml &&
log_this ods-zonelist-backup cp -- "zonelist_backup.xml" $ZONELIST_FILE &&
rm -f zonelist_backup.xml &&

#close the engine
ods_stop_enforcer &&

echo &&
echo "****************all test OK******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1


