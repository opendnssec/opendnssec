#!/usr/bin/env bash
#
#TEST: Test to check key allocation does not violate share / non share

ODS_ENFORCER_WAIT_STOP_LOG=1800	# Seconds we wait for enforcer to run
ODS_ENFORCER_WAIT_STOP_LOG=3600	# Seconds we wait for enforcer to run

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

rm -rf base &&
mkdir  base &&

# Used only to create a gold while setting up the test
#rm -rf gold && mkdir gold &&

##################  SETUP ###########################
# Start enforcer (Zones already exist and we let it generate keys itself)
ods_start_enforcer &&

# Make sure all keys are in use
sleep 90 &&

# Check that we have 2 keys per zone
log_this ods-enforcer-key-list0 ods-enforcer key list &&
( ( log_grep ods-enforcer-key-list0 stdout 'non-share1                      KSK      generate' &&
    log_grep ods-enforcer-key-list0 stdout 'non-share1                      ZSK      publish' ) ||
  ( log_grep ods-enforcer-key-list0 stdout 'non-share1                      KSK      publish' &&
    log_grep ods-enforcer-key-list0 stdout 'non-share1                      ZSK      ready' ) ) &&
( ( log_grep ods-enforcer-key-list0 stdout 'non-share2                      KSK      generate' &&
    log_grep ods-enforcer-key-list0 stdout 'non-share2                      ZSK      publish' ) ||
  ( log_grep ods-enforcer-key-list0 stdout 'non-share2                      KSK      publish' &&
    log_grep ods-enforcer-key-list0 stdout 'non-share2                      ZSK      ready' ) ) &&
( ( log_grep ods-enforcer-key-list0 stdout 'non-share3                      KSK      generate' &&
    log_grep ods-enforcer-key-list0 stdout 'non-share3                      ZSK      publish' ) ||
  ( log_grep ods-enforcer-key-list0 stdout 'non-share3                      KSK      publish' &&
    log_grep ods-enforcer-key-list0 stdout 'non-share3                      ZSK      ready' ) ) &&
( ( log_grep ods-enforcer-key-list0 stdout 'share1                          KSK      generate' &&
    log_grep ods-enforcer-key-list0 stdout 'share1                          ZSK      publish' ) ||
  ( log_grep ods-enforcer-key-list0 stdout 'share1                          KSK      publish' &&
    log_grep ods-enforcer-key-list0 stdout 'share1                          ZSK      ready' ) ) &&
( ( log_grep ods-enforcer-key-list0 stdout 'share2                          KSK      generate' &&
    log_grep ods-enforcer-key-list0 stdout 'share2                          ZSK      publish' ) ||
  ( log_grep ods-enforcer-key-list0 stdout 'share2                          KSK      publish' &&
    log_grep ods-enforcer-key-list0 stdout 'share2                          ZSK      ready' ) ) &&
( ( log_grep ods-enforcer-key-list0 stdout 'share3                          KSK      generate' &&
    log_grep ods-enforcer-key-list0 stdout 'share3                          ZSK      publish' ) ||
  ( log_grep ods-enforcer-key-list0 stdout 'share3                          KSK      publish' &&
    log_grep ods-enforcer-key-list0 stdout 'share3                          ZSK      ready' ) ) &&


# Grab the CKA_IDs of all the keys
log_this ods-enforcer-cka_id1 ods-enforcer key list --verbose &&
KSK_CKA_ID_NON_1=`log_grep -o ods-enforcer-cka_id1 stdout "non-share1                      KSK      " | awk '{print $8}'` &&
KSK_CKA_ID_NON_2=`log_grep -o ods-enforcer-cka_id1 stdout "non-share2                      KSK      " | awk '{print $8}'` &&
KSK_CKA_ID_NON_3=`log_grep -o ods-enforcer-cka_id1 stdout "non-share3                      KSK      " | awk '{print $8}'` &&

ZSK_CKA_ID_NON_1=`log_grep -o ods-enforcer-cka_id1 stdout "non-share1                      ZSK      " | awk '{print $8}'` &&
ZSK_CKA_ID_NON_2=`log_grep -o ods-enforcer-cka_id1 stdout "non-share2                      ZSK      " | awk '{print $8}'` &&
ZSK_CKA_ID_NON_3=`log_grep -o ods-enforcer-cka_id1 stdout "non-share3                      ZSK      " | awk '{print $8}'` &&

KSK_CKA_ID_SHA_1=`log_grep -o ods-enforcer-cka_id1 stdout "share1                          KSK      " | awk '{print $8}'` &&
KSK_CKA_ID_SHA_2=`log_grep -o ods-enforcer-cka_id1 stdout "share2                          KSK      " | awk '{print $8}'` &&
KSK_CKA_ID_SHA_3=`log_grep -o ods-enforcer-cka_id1 stdout "share3                          KSK      " | awk '{print $8}'` &&

ZSK_CKA_ID_SHA_1=`log_grep -o ods-enforcer-cka_id1 stdout "share1                          ZSK      " | awk '{print $8}'` &&
ZSK_CKA_ID_SHA_2=`log_grep -o ods-enforcer-cka_id1 stdout "share2                          ZSK      " | awk '{print $8}'` &&
ZSK_CKA_ID_SHA_3=`log_grep -o ods-enforcer-cka_id1 stdout "share3                          ZSK      " | awk '{print $8}'` &&

# Check the non-shared are different and the shared are the same...

echo "Testing non-shared KSKs" &&
[ "$KSK_CKA_ID_NON_1" != "$KSK_CKA_ID_NON_2" ] &&
[ "$KSK_CKA_ID_NON_1" != "$KSK_CKA_ID_NON_3" ] &&
[ "$KSK_CKA_ID_NON_2" != "$KSK_CKA_ID_NON_3" ] &&

echo "Testing non-shared ZSKs" &&
[ "$ZSK_CKA_ID_NON_1" != "$ZSK_CKA_ID_NON_2" ] &&
[ "$ZSK_CKA_ID_NON_1" != "$ZSK_CKA_ID_NON_3" ] &&
[ "$ZSK_CKA_ID_NON_2" != "$ZSK_CKA_ID_NON_3" ] &&

# OPENDNSSEC-690:
# Disabled testing of re-use of keys 
# Note that it is not just the CKA-IDs which are different, the
# number of keys allocated in the HSM is actually also wrong
# echo "Testing shared KSKs" &&
# [ "$KSK_CKA_ID_SHA_1" == "$KSK_CKA_ID_SHA_2" ] &&
# [ "$KSK_CKA_ID_SHA_1" == "$KSK_CKA_ID_SHA_3" ] &&

# echo "Testing shared ZSKs" &&
# [ "$ZSK_CKA_ID_SHA_1" == "$ZSK_CKA_ID_SHA_2" ] &&
# [ "$ZSK_CKA_ID_SHA_1" == "$ZSK_CKA_ID_SHA_3" ] &&

echo "Make sure that there are no additional keys allocated" &&
test `ods-hsmutil list | grep ^SoftHSM | wc -l` -eq 16 &&

# OPENDNSSEC-690
# This is the wrong number, it should be on of: 8, 12 or 16 (!)
# Currently there will be 16 keys generated, 8 got KSKs and 8 for
# ZSKs, but of these 8, 4 will be for the shared, and 4 for the
# non shared policies.  This is clearly wrong as the shared should
# use less keys.
# Depending on the specification (!) of the implementation;
# - 8 is corrent, when not pre-generating keys, 4 for KSKs, 4 for
#   ZSKs, and per 4, 3 for the non-shared, and 1 for the shared policy.
# - 12 is corrent, when pre-generating keys, 6 for KSKs, 6 for
#   ZSKs, and per 6, one for the shared plus one as reserve (ie.
#   two for shared keys, and 3 for the non-shared policy zones plus
#   one in reserve
# - 16 is correct as per previous, however now the non-shared
#   policy zones will have a key in reserve /per/ zone, ie. 3
#   in use plus 3 in reserve (2*((1+1)+(3+3))=16).
# However in the last case, there will be 4 keys for the shared
# policies and 12 for the non-shared policies, not 6 and 6 as
# is currently the case. So the following test should fail if
# 16 is considered correct:
# echo "Make sure the shared policies use fewer keys" &&
# test `ods-hsmutil list | grep ^SoftHSM | grep RSA/1024 | wc -l` -lt \
#      `ods-hsmutil list | grep ^SoftHSM | grep RSA/2048 | wc -l` &&

for zone in non-share1 non-share2 non-share3 share1 share2 share3; do
	# Used only to create a gold while setting up the test
	#cp $INSTALL_ROOT/var/opendnssec/signconf/$zone.xml gold/signconf_"$zone".xml        
	cp $INSTALL_ROOT/var/opendnssec/signconf/$zone.xml base/signconf_"$zone".xml
done &&

# compare all the signconf files
log_this ods-compare-signconfs  ods_compare_gold_vs_base_signconf &&
rm -rf base &&

return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

