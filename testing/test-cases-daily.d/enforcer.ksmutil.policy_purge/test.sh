#!/usr/bin/env bash

KASP_FILE=$INSTALL_ROOT/etc/opendnssec/kasp.xml

#TEST: Test to check that policy import/export/list works correctly
#TODO: we need to check the command ods-ksmutil policy purge later
if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

# kasp_3policies.xml: It contains three policy, their names were default, default2, default3.
log_this ods-control-start cp -- "kasp_3policies.xml" $KASP_FILE &&

# start the engine
#ods_start_enforcer &&

#update kasp
log_this ods-ksmutil-update-kasp "ods-ksmutil update kasp" &&
#log_grep ods-ksmutil-update-kasp stdout 'flushing all tasks...' &&

#list policy
log_this ods-ksmutil-policy-list_1 "ods-ksmutil policy list" &&
log_grep ods-ksmutil-policy-list_1 stdout 'default[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
log_grep ods-ksmutil-policy-list_1 stdout 'default2[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
log_grep ods-ksmutil-policy-list_1 stdout 'default3[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&

#list zone
log_this ods-ksmutil-zone-list_1 "ods-ksmutil zone list" &&
log_grep ods-ksmutil-zone-list_1 stdout 'Found Zone: ods; on policy default' &&

#policy purge
echo "y" | log_this ods-ksmutil-policy-purge_1 "ods-ksmutil policy purge" &&
log_grep ods-ksmutil-policy-purge_1 stdout "No zones on policy default2; purging..." &&
log_grep ods-ksmutil-policy-purge_1 stdout "No zones on policy default3; purging..." &&
# Check that the policy is removed from the kasp file
! `$GREP -q -- "default2" $KASP_FILE` &&
! `$GREP -q -- "default3" $KASP_FILE` &&

#list policy
log_this ods-ksmutil-policy-list_2 "ods-ksmutil policy list" &&
log_grep ods-ksmutil-policy-list_2 stdout 'default[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
! log_grep ods-ksmutil-policy-list_2 stdout 'default2[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
! log_grep ods-ksmutil-policy-list_2 stdout 'default3[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&

# Now re-instate the 3 policy kasp
log_this ods-control-start cp -- "kasp_3policies.xml" $KASP_FILE &&
#update kasp
log_this ods-ksmutil-update-kasp "ods-ksmutil update kasp" &&

#list policy
log_this ods-ksmutil-policy-list_3 "ods-ksmutil policy list" &&
log_grep ods-ksmutil-policy-list_3 stdout 'default[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
log_grep ods-ksmutil-policy-list_3 stdout 'default2[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
log_grep ods-ksmutil-policy-list_3 stdout 'default3[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&

#add zone
log_this ods-ksmutil-add-zone "ods-ksmutil zone add -z ods1 -p default2" &&
log_grep ods-ksmutil-add-zone stdout 'Imported zone: ods1' &&

#list zone
log_this ods-ksmutil-zone-list_2 "ods-ksmutil zone list" &&
log_grep ods-ksmutil-zone-list_2 stdout 'Found Zone: ods; on policy default' &&
log_grep ods-ksmutil-zone-list_2 stdout 'Found Zone: ods1; on policy default2' &&

#policy purge
echo "y" | log_this ods-ksmutil-policy-purge_2 "ods-ksmutil policy purge" &&
log_grep ods-ksmutil-policy-purge_2 stdout "No zones on policy default3; purging..." &&

#list policy
log_this ods-ksmutil-policy-list_4 "ods-ksmutil policy list" &&
log_grep ods-ksmutil-policy-list_4 stdout 'default[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
log_grep ods-ksmutil-policy-list_4 stdout 'default2[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
! log_grep ods-ksmutil-policy-list_4 stdout 'default3[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&

#delete zone ods1
echo "y" | log_this ods-ksmutil-zone-delete "ods-ksmutil zone delete -z ods1" &&
#log_grep ods-ksmutil-zone-delete stdout "zone 'ods1' deleted successfully" &&

#policy purge
echo "y " | log_this ods-ksmutil-policy-purge_3 "ods-ksmutil policy purge" &&
log_grep ods-ksmutil-policy-purge_3 stdout "No zones on policy default2; purging..." &&
! `$GREP -q -- "default2" $KASP_FILE` &&

#list policy
log_this ods-ksmutil-policy-list_5 "ods-ksmutil policy list" &&
log_grep ods-ksmutil-policy-list_5 stdout 'default[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
! log_grep ods-ksmutil-policy-list_5 stdout 'default2[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
! log_grep ods-ksmutil-policy-list_5 stdout 'default3[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&

#set the kasp to default
log_this ods-set-kasp-default cp -- "kasp.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
log_this ods-set-kasp-default "ods-ksmutil update kasp" &&
log_this ods-set-kasp-default "ods-ksmutil policy list" &&
log_grep ods-set-kasp-default stdout 'default[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
log_grep ods-set-kasp-default stdout 'default2[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
! log_grep ods-set-kasp-default stdout 'default3[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&

#close the engine
# TODO: The enforcer is failing with a foreign key constraint on mysql - this needs investigating!
#ods_stop_enforcer &&

echo &&
echo "****************all test OK******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1


