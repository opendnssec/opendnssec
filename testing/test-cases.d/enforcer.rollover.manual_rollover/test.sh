#!/usr/bin/env bash
#
#TEST: Test to make sure a manual key rollover can be done
#TEST: Roll the ZSK and then the KSK and use the zone option

#TODO: Test the no-retire on the ds-seen command
#TODO: Test error cases/more complicated scenarios e.g.
#TODO: do a manual rollover when a scheduled one is due

#OPENDNSSEC-91: Make the keytype flag required when rolling keys

ODS_ENFORCER_WAIT_STOP_LOG=180

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

##################  SETUP ###########################
# Start enforcer (Zone already exists and we let it generate keys itself)
ods_start_ods-control &&

# note that the first enforce is not scheduled immediately, for almost a minut from now
#sleep 60 && ods_enforcer_idle &&

# Time Leap to time that  that we have ready/active ksk/zsk keys
sleep 1 && ods_enforcer_idle &&
log_this ods-enforcer-time-leap-1 ods_enforcer_leap_to 14400 &&
sleep 1 && ods_enforcer_idle &&

# Check that we have 2 keys per zone
log_this ods-enforcer-key-list1 ods-enforcer key list &&
log_grep ods-enforcer-key-list1 stdout 'ods[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list1 stdout 'ods[[:space:]]*ZSK[[:space:]]*active' &&
log_grep ods-enforcer-key-list1 stdout 'ods2[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list1 stdout 'ods2[[:space:]]*ZSK[[:space:]]*active' &&
log_grep ods-enforcer-key-list1 stdout 'ods3[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list1 stdout 'ods3[[:space:]]*ZSK[[:space:]]*active' &&

#Make sure a zone name is required
! log_this ods-enforcer-key-rollover_bad1 ods-enforcer key rollover --keytype ZSK &&
log_grep ods-enforcer-key-rollover_bad1 stdout 'expected either --zone <zone> or --policy <policy> option' &&

# Make sure nothing happens for a non-existent zone
! log_this ods-enforcer-key-rollover_bad2 ods-enforcer key rollover --zone bob --keytype ZSK &&
log_grep ods-enforcer-key-rollover_bad2 stderr "zone bob not found" &&

# ******************* Roll the ZSK first ************************ 
sleep 1 && ods_enforcer_idle &&
log_this ods-enforcer-key-rollover1 ods-enforcer key rollover --zone ods --keytype ZSK &&
sleep 1 && ods_enforcer_idle &&
syslog_waitfor 5 "ods-enforcerd: .*Manual rollover initiated for ZSK on Zone: ods" &&
# *************************************************************** 

# Check for a published ZSK for our zone
# and check nothing happens to the other zone

log_this ods-enforcer-key-list2 ods-enforcer key list --verbose  &&
log_grep ods-enforcer-key-list2 stdout 'ods[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list2 stdout 'ods[[:space:]]*ZSK[[:space:]]*active' &&
log_grep ods-enforcer-key-list2 stdout 'ods[[:space:]]*ZSK[[:space:]]*publish' &&
log_grep ods-enforcer-key-list2 stdout 'ods2[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list2 stdout 'ods2[[:space:]]*ZSK[[:space:]]*active' &&
! log_grep ods-enforcer-key-list2 stdout 'ods2[[:space:]]*ZSK[[:space:]]*publish' &&
log_grep ods-enforcer-key-list2 stdout 'ods3[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list2 stdout 'ods3[[:space:]]*ZSK[[:space:]]*active' &&
! log_grep ods-enforcer-key-list2 stdout 'ods3[[:space:]]*ZSK[[:space:]]*publish' &&

KSK_CKA_ID1=`log_grep -o ods-enforcer-key-list2 stdout "ods[[:space:]]*KSK[[:space:]]*ready" | awk '{print $9}'` &&
ZSK_CKA_ID1=`log_grep -o ods-enforcer-key-list2 stdout "ods[[:space:]]*ZSK[[:space:]]*active" | awk '{print $8}'` &&
ZSK_CKA_ID2=`log_grep -o ods-enforcer-key-list2 stdout "ods[[:space:]]*ZSK[[:space:]]*publish" | awk '{print $8}'` &&


##################  STEP 1: Time Leap to having new active ZSK ###########################
log_this ods-enforcer-time-leap-2 ods_timeleap_search_key "ods" "ZSK" "active" "$ZSK_CKA_ID2"&&

# Check the published key is now active and the old key is retired
log_this ods-enforcer-key-list3 ods-enforcer key list --verbose &&
log_grep ods-enforcer-key-list3 stdout "ods[[:space:]]*KSK[[:space:]]*ready.*$KSK_CKA_ID1" &&
log_grep ods-enforcer-key-list3 stdout "ods[[:space:]]*ZSK[[:space:]]*retire.*$ZSK_CKA_ID1" &&
log_grep ods-enforcer-key-list3 stdout "ods[[:space:]]*ZSK[[:space:]]*active.*$ZSK_CKA_ID2" &&

# Run the ds-seen on the KSK and check the output (enforcer won't HUP as it isn't running)
ods_enforcer_idle &&
log_this ods-enforcer-dsseen_ods1   ods-enforcer key ds-seen --zone ods --cka_id $KSK_CKA_ID1 &&
sleep 1 && ods_enforcer_idle &&
log_grep ods-enforcer-dsseen_ods1 stdout "1 KSK matches found" &&
log_grep ods-enforcer-dsseen_ods1 stdout "1 KSKs changed." &&

##################  STEP 2: Time Leap to getting rid of old zsk ###########################
log_this ods-enforcer-time-leap-3 ods_timeleap_search_nokey "ods" "ZSK" "retire" "$ZSK_CKA_ID1" &&

# Make sure the old key is now removed
log_this ods-enforcer-key-list4 ods-enforcer key list --verbose &&
log_grep ods-enforcer-key-list4 stdout "ods[[:space:]]*KSK[[:space:]]*active.*$KSK_CKA_ID1" &&
log_grep ods-enforcer-key-list4 stdout "ods[[:space:]]*ZSK[[:space:]]*active.*$ZSK_CKA_ID2" &&
! log_grep ods-enforcer-key-list4 stdout "ods[[:space:]]*ZSK[[:space:]]*retire.*$ZSK_CKA_ID1" &&

##################  STEP 3: Time Leap to next new zsk for ods ###########################
log_this ods-enforcer-time-leap-4 ods_timeleap_search_key "ods" "ZSK" "publish" ".*" 100 &&


# Check the next scheduled rollover starts for the ZSK
log_this ods-enforcer-key-list5 ods-enforcer key list --verbose &&
log_grep ods-enforcer-key-list5 stdout "ods[[:space:]]*KSK[[:space:]]*active.*$KSK_CKA_ID1" &&
log_grep ods-enforcer-key-list5 stdout "ods[[:space:]]*ZSK[[:space:]]*active.*$ZSK_CKA_ID2" &&
log_grep ods-enforcer-key-list5 stdout "ods[[:space:]]*ZSK[[:space:]]*publish" &&

ZSK_CKA_ID3=`log_grep -o ods-enforcer-key-list5 stdout "ods[[:space:]]*ZSK[[:space:]]*publish" | awk '{print $8}'` &&


# ******************* Roll the KSK now ************************ 
ods_enforcer_idle &&
log_this ods-enforcer-key-rollover2 ods-enforcer key rollover --zone ods --keytype KSK &&
sleep 1 && ods_enforcer_idle &&
syslog_waitfor 5 "ods-enforcerd: .*Manual rollover initiated for KSK on Zone: ods" &&
# *************************************************************

# Look for a published KSK
log_this ods-enforcer-key-list6 ods-enforcer key list --verbose &&
log_grep ods-enforcer-key-list6 stdout "ods[[:space:]]*KSK[[:space:]]*active.*$KSK_CKA_ID1" &&
log_grep ods-enforcer-key-list6 stdout 'ods[[:space:]]*KSK[[:space:]]*publish' &&
log_grep ods-enforcer-key-list6 stdout "ods[[:space:]]*ZSK[[:space:]]*active.*$ZSK_CKA_ID2" &&
log_grep ods-enforcer-key-list6 stdout 'ods[[:space:]]*ZSK[[:space:]]*publish' &&

KSK_CKA_ID2=`log_grep -o ods-enforcer-key-list6 stdout "ods[[:space:]]*KSK[[:space:]]*publish" | awk '{print $8}'` &&
KSK_KEYTAG2=`log_grep -o ods-enforcer-key-list6 stdout "ods[[:space:]]*KSK[[:space:]]*publish" | awk '{print $10}'` &&

# ##################  STEP 4: Time Leap to ready KSK ###########################
log_this ods-enforcer-time-leap-5 ods_timeleap_search_key "ods" "KSK" "ready" "$KSK_CKA_ID2" ".*" 100 &&


# Look for a ready KSK 
log_this ods-enforcer-key-list7 ods-enforcer key list --verbose &&
log_grep ods-enforcer-key-list7 stdout "ods[[:space:]]*KSK[[:space:]]*retire.*$KSK_CKA_ID1" &&
log_grep ods-enforcer-key-list7 stdout "ods[[:space:]]*KSK[[:space:]]*ready[[:space:]]*waiting for ds-seen.*$KSK_CKA_ID2" &&
log_grep ods-enforcer-key-list7 stdout "ods[[:space:]]*ZSK[[:space:]]*retire.*$ZSK_CKA_ID2" &&
log_grep ods-enforcer-key-list7 stdout "ods[[:space:]]*ZSK[[:space:]]*ready.*$ZSK_CKA_ID3" &&

syslog_grep "ods-enforcerd: .*please submit DS with keytag $KSK_KEYTAG2 for zone ods" &&

# Run a ds-seen on this new key and check the output
ods_enforcer_idle &&
log_this ods-enforcer-dsseen_ods2   ods-enforcer key ds-seen --zone ods --cka_id $KSK_CKA_ID2 &&
sleep 1 && ods_enforcer_idle &&
log_grep ods-enforcer-dsseen_ods2 stdout "1 KSK matches found." &&
log_grep ods-enforcer-dsseen_ods2 stdout "1 KSKs changed." &&

log_this ods-enforcer-key-list7.5 ods-enforcer key list --verbose &&
log_grep ods-enforcer-key-list7.5 stdout "ods[[:space:]]*KSK[[:space:]]*retire.*$KSK_CKA_ID1" &&
log_grep ods-enforcer-key-list7.5 stdout "ods[[:space:]]*KSK[[:space:]]*active.*$KSK_CKA_ID2" &&
log_grep ods-enforcer-key-list7.5 stdout "ods[[:space:]]*ZSK[[:space:]]*retire.*$ZSK_CKA_ID2" &&
log_grep ods-enforcer-key-list7.5 stdout "ods[[:space:]]*ZSK[[:space:]]*ready.*$ZSK_CKA_ID3" &&

# Time Leap to new active ZSK
log_this ods-enforcer-time-leap-6 ods_timeleap_search_key "ods" "ZSK" "active" "$ZSK_CKA_ID3" &&
# Key list should reflect this
log_this ods-enforcer-key-list8 ods-enforcer key list --verbose &&
log_grep ods-enforcer-key-list8 stdout "ods[[:space:]]*KSK[[:space:]]*retire.*$KSK_CKA_ID1" &&
log_grep ods-enforcer-key-list8 stdout "ods[[:space:]]*KSK[[:space:]]*active.*$KSK_CKA_ID2" &&
log_grep ods-enforcer-key-list8 stdout "ods[[:space:]]*ZSK[[:space:]]*retire.*$ZSK_CKA_ID2" &&
log_grep ods-enforcer-key-list8 stdout "ods[[:space:]]*ZSK[[:space:]]*active.*$ZSK_CKA_ID3" &&

# ##################  STEP 5: Time Leap: one and only one ksk which is active for ods ###########################
ods_enforcer_idle &&
log_this ods-enforcer-ds-gone_ods1 ods-enforcer key ds-gone --zone ods --cka_id $KSK_CKA_ID1 &&
sleep 1 && ods_enforcer_idle &&

log_this ods-enforcer-time-leap-7 ods_timeleap_search_nokey "ods" "KSK" "retire" "$KSK_CKA_ID1" &&

# Look for only an active KSK
log_this ods-enforcer-key-list9 ods-enforcer key list --verbose &&
log_grep ods-enforcer-key-list9 stdout "ods[[:space:]]*KSK[[:space:]]*active.*$KSK_CKA_ID2" &&
! log_grep ods-enforcer-key-list9 stdout "ods[[:space:]]*KSK[[:space:]]*retire.*$KSK_CKA_ID1" &&
! log_grep ods-enforcer-key-list9 stdout "ods[[:space:]]*KSK[[:space:]]*publish" &&
log_grep ods-enforcer-key-list9 stdout "ods[[:space:]]*ZSK[[:space:]]*active.*$ZSK_CKA_ID3" &&
#! log_grep ods-enforcer-key-list9 stdout "ods[[:space:]]*ZSK[[:space:]]*retire.*$ZSK_CKA_ID2" &&
! log_grep ods-enforcer-key-list9 stdout "ods[[:space:]]*ZSK[[:space:]]*publish" &&

# ********Lets roll for all key types now ************** 
ods_enforcer_idle &&
log_this ods-enforcer-key-rollover_all ods-enforcer key rollover --zone ods &&
sleep 1 && ods_enforcer_idle &&
#echo "y" | log_this ods-enforcer-key-rollover_all ods-enforcer key rollover --policy default --all &&
syslog_waitfor 5 "ods-enforcerd: .*Manual rollover initiated for all keys on Zone: ods" &&
# ******************************************************************* 

# Check both keys have started rolling
log_this ods-enforcer-key-list10 ods-enforcer key list --verbose &&
log_grep ods-enforcer-key-list10 stdout "ods[[:space:]]*KSK[[:space:]]*active.*$KSK_CKA_ID2" &&
log_grep ods-enforcer-key-list10 stdout "ods[[:space:]]*KSK[[:space:]]*publish" &&
log_grep ods-enforcer-key-list10 stdout "ods[[:space:]]*ZSK[[:space:]]*active.*$ZSK_CKA_ID3" &&
log_grep ods-enforcer-key-list10 stdout "ods[[:space:]]*ZSK[[:space:]]*publish" &&
log_grep ods-enforcer-key-list10 stdout 'ods2[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list10 stdout 'ods2[[:space:]]*ZSK[[:space:]]*active' &&
log_grep ods-enforcer-key-list10 stdout 'ods3[[:space:]]*KSK[[:space:]]*ready' &&
log_grep ods-enforcer-key-list10 stdout 'ods3[[:space:]]*ZSK[[:space:]]*active' &&

# ******************* Now roll a zone which shares keys ************************ 
#echo "y" | log_this ods-enforcer-key-rollover3 ods-enforcer key rollover --zone ods2 --keytype ZSK &&
#log_grep ods-enforcer-key-rollover3 stdout "This zone shares keys with others, all instances of the active key on this zone will be retired; are you sure?" &&
#syslog_waitfor 5 "ods-enforcer: .*Manual key rollover for key type zsk on zone ods2 initiated" &&
# ***************************************************************

# Check both keys have started rolling on ods2
#log_this ods-enforcer-key-list11 ods-enforcer key list --verbose &&
#log_grep ods-enforcer-key-list11 stdout "ods[[:space:]]*KSK[[:space:]]*active.*$KSK_CKA_ID2" &&
#log_grep ods-enforcer-key-list11 stdout "ods[[:space:]]*KSK[[:space:]]*publish" &&
#log_grep ods-enforcer-key-list11 stdout "ods[[:space:]]*ZSK[[:space:]]*retire.*$ZSK_CKA_ID2" &&
#log_grep ods-enforcer-key-list11 stdout "ods[[:space:]]*ZSK[[:space:]]*active.*$ZSK_CKA_ID3" &&
#log_grep ods-enforcer-key-list11 stdout "ods[[:space:]]*ZSK[[:space:]]*publish" &&
#log_grep ods-enforcer-key-list11 stdout 'ods2[[:space:]]*[[:space:]]*      KSK[[:space:]]*ready' &&
#log_grep ods-enforcer-key-list11 stdout 'ods2[[:space:]]*[[:space:]]*      ZSK[[:space:]]*active' &&
#log_grep ods-enforcer-key-list11 stdout 'ods2[[:space:]]*[[:space:]]*      ZSK[[:space:]]*publish' &&
#log_grep ods-enforcer-key-list11 stdout 'ods3[[:space:]]*[[:space:]]*      KSK[[:space:]]*ready' &&
#log_grep ods-enforcer-key-list11 stdout 'ods3[[:space:]]*[[:space:]]*      ZSK[[:space:]]*active' &&
#log_grep ods-enforcer-key-list11 stdout 'ods3[[:space:]]*[[:space:]]*      ZSK[[:space:]]*publish' &&

ods_stop_ods-control &&

return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1
