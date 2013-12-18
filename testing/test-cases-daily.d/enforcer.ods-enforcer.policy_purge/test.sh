#!/usr/bin/env bash

#TEST: Test to check that policy import/export/list works correctly
#TODO: we need to check the command ods-ksmutil policy purge later
if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

# kasp_3policies.xml: It contains three policy, their names were default, default2, default3.
log_this ods-control-start cp -- "kasp_3policies.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&

# start the engine
log_this ods-control-start "ods-control start" &&
#log_grep ods-control-start stdout 'Starting enforcer...' &&
#log_grep ods-control-start stdout 'OpenDNSSEC key and signing policy enforcer version 2.0.0a4' &&
#log_grep ods-control-start stdout 'OpenDNSSEC signer engine version 2.0.0a4' &&
#log_grep ods-control-start stdout 'Engine running.' &&

#update kasp
log_this ods-enforcer-update-kasp "ods-enforcer update kasp" &&
log_grep ods-enforcer-update-kasp stdout 'flushing all tasks...' &&

#list policy
log_this ods-enforcer-policy-list_1 "ods-enforcer policy list" &&
log_grep ods-enforcer-policy-list_1 stdout 'default                         default fast test policy' &&
log_grep ods-enforcer-policy-list_1 stdout 'default2                        default fast test policy' &&
log_grep ods-enforcer-policy-list_1 stdout 'default3                        default fast test policy' &&

#list zone
log_this ods-enforcer-zone-list_1 "ods-enforcer zone list" &&
log_grep ods-enforcer-zone-list_1 stdout 'ods                             default' &&

#policy purge
log_this ods-enforcer-policy-purge_1 "ods-enforcer policy purge" &&
log_grep ods-enforcer-policy-purge_1 stdout "purge policy with name = 'default2' succeed!" &&
log_grep ods-enforcer-policy-purge_1 stdout "purge policy with name = 'default3' succeed!" &&

#list policy
log_this ods-enforcer-policy-list_2 "ods-enforcer policy list" &&
log_grep ods-enforcer-policy-list_2 stdout 'default                         default fast test policy' &&
! log_grep ods-enforcer-policy-list_2 stdout 'default2                        default fast test policy' &&
! log_grep ods-enforcer-policy-list_2 stdout 'default3                        default fast test policy' &&
#update kasp
log_this ods-enforcer-update-kasp "ods-enforcer update kasp" &&

#list policy
log_this ods-enforcer-policy-list_3 "ods-enforcer policy list" &&
log_grep ods-enforcer-policy-list_3 stdout 'default                         default fast test policy' &&
log_grep ods-enforcer-policy-list_3 stdout 'default2                        default fast test policy' &&
log_grep ods-enforcer-policy-list_3 stdout 'default3                        default fast test policy' &&

#add zone
log_this ods-enforcer-add-zone "ods-enforcer zone add -z ods1 -p default2" &&
log_grep ods-enforcer-add-zone stdout 'Imported zone: ods1' &&

#list zone
log_this ods-enforcer-zone-list_2 "ods-enforcer zone list" &&
log_grep ods-enforcer-zone-list_2 stdout 'ods                             default' &&
log_grep ods-enforcer-zone-list_2 stdout 'ods1                            default2' &&

#policy purge
log_this ods-enforcer-policy-purge_2 "ods-enforcer policy purge" &&
log_grep ods-enforcer-policy-purge_2 stdout "purge policy with name = 'default3' succeed!" &&

#list policy
log_this ods-enforcer-policy-list_4 "ods-enforcer policy list" &&
log_grep ods-enforcer-policy-list_4 stdout 'default                         default fast test policy' &&
log_grep ods-enforcer-policy-list_4 stdout 'default2                        default fast test policy' &&
! log_grep ods-enforcer-policy-list_4 stdout 'default3                        default fast test policy' &&

#delete zone ods1
echo "y" | log_this ods-enforcer-zone-delete "ods-enforcer zone delete -z ods1" &&
log_grep ods-enforcer-zone-delete stdout "zone 'ods1' deleted successfully" &&

#policy purge
log_this ods-enforcer-policy-purge_3 "ods-enforcer policy purge" &&
log_grep ods-enforcer-policy-purge_3 stdout "purge policy with name = 'default2' succeed!" &&

#list policy
log_this ods-enforcer-policy-list_5 "ods-enforcer policy list" &&
log_grep ods-enforcer-policy-list_5 stdout 'default                         default fast test policy' &&

#set the kasp to default
log_this ods-set-kasp-default cp -- "kasp.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
log_this ods-set-kasp-default "ods-enforcer update kasp" &&
log_this ods-set-kasp-default "ods-enforcer policy list" &&
log_grep ods-set-kasp-default stdout 'default                         default fast test policy' &&
log_grep ods-set-kasp-default stdout 'default2                        default fast test policy' &&

#close the engine
log_this ods-control-stop "ods-control stop" &&
log_grep ods-control-stop stdout 'Stopping enforcer..' &&
log_grep ods-control-stop stdout 'Stopping signer engine...' &&
log_grep ods-control-stop stdout 'Engine shut down.' &&

echo &&
echo "****************all test OK******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
return 1


