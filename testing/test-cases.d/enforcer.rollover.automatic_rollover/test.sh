#!/usr/bin/env bash
#
#TEST: Test to make sure an automatic zsk and ksk rollover can be done
#TEST: Roll the ZSK and then the KSK 
#TEST: We use timeleap to hurry things along




if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

##################  SETUP ###########################
# Start enforcer (Zone already exists and we let it generate keys itself)
ods_start_enforcer &&

log_this ods-enforcer-zone-add ods-enforcer zone add -z ods
ods_enforcer_leap_to 14400 &&

# Check that we have 2 keys for zone
log_this ods-enforcer-key-list1 ods-enforcer key list -v &&
log_grep ods-enforcer-key-list1 stdout "ods[[:space:]]*KSK[[:space:]]*ready" &&
log_grep ods-enforcer-key-list1 stdout "ods[[:space:]]*ZSK[[:space:]]*active" &&

ZSK_KEYTAG1=`log_grep -o ods-enforcer-key-list1 stdout "ods[[:space:]]*ZSK[[:space:]]*active" | awk '{print $10}'` &&
KSK_KEYTAG1=`log_grep -o ods-enforcer-key-list1 stdout "ods[[:space:]]*KSK[[:space:]]*ready" | awk '{print $11}'` &&


# ******************* jump to the time that ZSK should be rolled automatically ************************ 
ods_timeleap_search_key "ods" "ZSK" "publish" &&

# jump to the time that zsk becomes active
ods_enforcer_leap_to 9000 &&

# Check keys, we should see a new ZSK
log_this ods-enforcer-key-list2 ods-enforcer key list -v &&

log_grep ods-enforcer-key-list2 stdout "ods[[:space:]]*KSK[[:space:]]*ready" &&
log_grep ods-enforcer-key-list2 stdout "ods[[:space:]]*ZSK[[:space:]]*retire.*$ZSK_KEYTAG1" &&
log_grep ods-enforcer-key-list2 stdout "ods[[:space:]]*ZSK[[:space:]]*active" &&

ZSK_KEYTAG2=`log_grep -o ods-enforcer-key-list2 stdout "ods[[:space:]]*ZSK[[:space:]]*active" | awk '{print $10}'` &&

# ***************************** run ds-seen command to have active KSK  ********************************** 
ods_enforcer_idle &&
log_this ods-enforcer-ds-seen ods-enforcer key ds-submit -z ods --keytag $KSK_KEYTAG1 &&
log_this ods-enforcer-ds-seen ods-enforcer key ds-seen -z ods --keytag $KSK_KEYTAG1 &&
sleep 1 && ods_enforcer_idle &&

log_this ods-enforcer-key-list3 ods-enforcer key list -v &&

log_grep ods-enforcer-key-list3 stdout "ods[[:space:]]*KSK[[:space:]]*active.*$KSK_KEYTAG1" &&
log_grep ods-enforcer-key-list3 stdout "ods[[:space:]]*ZSK[[:space:]]*retire.*$ZSK_KEYTAG1" &&
log_grep ods-enforcer-key-list3 stdout "ods[[:space:]]*ZSK[[:space:]]*active" &&


# ********************************* Now jump to a time a new KSK introduced    ***************************************
ods_timeleap_search_key "ods" "KSK" "publish" &&


# Check for a published KSK for zone
log_this ods-enforcer-key-list4 ods-enforcer key list -v  &&
log_grep ods-enforcer-key-list4 stdout "ods[[:space:]]*KSK[[:space:]]*publish" &&




ods_stop_enforcer &&
return 0

echo
echo "************ERROR******************"
echo
ods-enforcer key list -dp
ods-enforcer key list -v
ods_kill
return 1

