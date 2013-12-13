#!/usr/bin/env bash

KASP_FILE=$INSTALL_ROOT/etc/opendnssec/kasp.xml

#TEST: A test to check that policy purge works correctly


if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

# kasp_3policies.xml: It contains three policy, their names were default, default2, default3.
log_this ods-control-start cp -- "kasp_3policies.xml" $KASP_FILE &&

# start the engine
ods_start_enforcer &&

#update kasp
log_this ods-enforcer-update-kasp "ods-enforcer update kasp" &&
log_grep ods-enforcer-update-kasp stdout 'flushing all tasks...' &&

#list policy
log_this ods-enforcer-policy-list_1 "ods-enforcer policy list" &&
log_grep ods-enforcer-policy-list_1 stdout 'default[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
log_grep ods-enforcer-policy-list_1 stdout 'default2[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
log_grep ods-enforcer-policy-list_1 stdout 'default3[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&

#list zone
log_this ods-enforcer-zone-list_1 "ods-enforcer zone list" &&
log_grep ods-enforcer-zone-list_1 stdout 'ods[[:space:]].*default' &&

#policy purge
echo "y" | log_this ods-enforcer-policy-purge_1 "ods-enforcer policy purge" &&
log_grep ods-enforcer-policy-purge_1 stdout "No zones on policy default2; purging..." &&
log_grep ods-enforcer-policy-purge_1 stdout "No zones on policy default3; purging..." &&
# Check that the policy is removed from the kasp file
! `$GREP -q -- "default2" $KASP_FILE` &&
! `$GREP -q -- "default3" $KASP_FILE` &&

#list policy
log_this ods-enforcer-policy-list_2 "ods-enforcer policy list" &&
log_grep ods-enforcer-policy-list_2 stdout 'default[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
! log_grep ods-enforcer-policy-list_2 stdout 'default2[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
! log_grep ods-enforcer-policy-list_2 stdout 'default3[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&

# Now re-instate the 3 policy kasp
log_this ods-control-start cp -- "kasp_3policies.xml" $KASP_FILE &&
#update kasp
log_this ods-enforcer-update-kasp "ods-enforcer update kasp" &&

#list policy
log_this ods-enforcer-policy-list_3 "ods-enforcer policy list" &&
log_grep ods-enforcer-policy-list_3 stdout 'default[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
log_grep ods-enforcer-policy-list_3 stdout 'default2[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
log_grep ods-enforcer-policy-list_3 stdout 'default3[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&

#add zone
log_this ods-enforcer-add-zone "ods-enforcer zone add -z ods1 -p default2" &&
log_grep ods-enforcer-add-zone stdout 'Imported zone: ods1' &&

#list zone
log_this ods-enforcer-zone-list_2 "ods-enforcer zone list" &&
log_grep ods-enforcer-zone-list_2 stdout 'ods[[:space:]].*default' &&
log_grep ods-enforcer-zone-list_2 stdout 'ods1[[:space:]].*default2' &&

#policy purge
echo "y" | log_this ods-enforcer-policy-purge_2 "ods-enforcer policy purge" &&
log_grep ods-enforcer-policy-purge_2 stdout "No zones on policy default3; purging..." &&

#list policy
log_this ods-enforcer-policy-list_4 "ods-enforcer policy list" &&
log_grep ods-enforcer-policy-list_4 stdout 'default[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
log_grep ods-enforcer-policy-list_4 stdout 'default2[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
! log_grep ods-enforcer-policy-list_4 stdout 'default3[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&

#delete zone ods1
echo "y" | log_this ods-enforcer-zone-delete "ods-enforcer zone delete -z ods1" &&
log_grep ods-enforcer-zone-delete stdout "zone 'ods1' deleted successfully" &&

#policy purge
echo "y " | log_this ods-enforcer-policy-purge_3 "ods-enforcer policy purge" &&
# FIX THIS ON 2.0 # log_grep ods-enforcer-policy-purge_3 stdout "No zones on policy default2; purging..." &&
! `$GREP -q -- "default2" $KASP_FILE` &&

#list policy
log_this ods-enforcer-policy-list_5 "ods-enforcer policy list" &&
log_grep ods-enforcer-policy-list_5 stdout 'default[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
! log_grep ods-enforcer-policy-list_2 stdout 'default2[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
! log_grep ods-enforcer-policy-list_2 stdout 'default3[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&

#set the kasp to default
log_this ods-set-kasp-default cp -- "kasp.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
log_this ods-set-kasp-default "ods-enforcer update kasp" &&
log_this ods-set-kasp-default "ods-enforcer policy list" &&
log_grep ods-set-kasp-default stdout 'default[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
log_grep ods-set-kasp-default stdout 'default2[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&
! log_grep ods-set-kasp-default stdout 'default3[[:space:]]*default[[:space:]]fast[[:space:]]test[[:space:]]policy' &&

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


