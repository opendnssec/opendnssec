#!/usr/bin/env bash
#
#TEST: Test to check key allocation does not violate share / non share

ENFORCER_WAIT=90	# Seconds we wait for enforcer to run

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
log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-enforcerd -1 &&
syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*all done' &&

# Check that we have 2 keys per zone
log_this ods-ksmutil-key-list0 ods-ksmutil key list &&
log_grep ods-ksmutil-key-list0 stdout 'non-share1                      KSK           publish' &&
log_grep ods-ksmutil-key-list0 stdout 'non-share1                      ZSK           active' &&
log_grep ods-ksmutil-key-list0 stdout 'non-share2                      KSK           publish' &&
log_grep ods-ksmutil-key-list0 stdout 'non-share2                      ZSK           active' &&
log_grep ods-ksmutil-key-list0 stdout 'non-share3                      KSK           publish' &&
log_grep ods-ksmutil-key-list0 stdout 'non-share3                      ZSK           active' &&
log_grep ods-ksmutil-key-list0 stdout 'share1                          KSK           publish' &&
log_grep ods-ksmutil-key-list0 stdout 'share1                          ZSK           active' &&
log_grep ods-ksmutil-key-list0 stdout 'share2                          KSK           publish' &&
log_grep ods-ksmutil-key-list0 stdout 'share2                          ZSK           active' &&
log_grep ods-ksmutil-key-list0 stdout 'share3                          KSK           publish' &&
log_grep ods-ksmutil-key-list0 stdout 'share3                          ZSK           active' &&

#TODO Check that no other keys were allocated
# HOW???

# Grab the CKA_IDs of all the keys
log_this ods-ksmutil-cka_id1 ods-ksmutil key list --all --verbose &&
KSK_CKA_ID_NON_1=`log_grep -o ods-ksmutil-cka_id1 stdout "non-share1                      KSK           publish" | awk '{print $9}'` &&
KSK_CKA_ID_NON_2=`log_grep -o ods-ksmutil-cka_id1 stdout "non-share2                      KSK           publish" | awk '{print $9}'` &&
KSK_CKA_ID_NON_3=`log_grep -o ods-ksmutil-cka_id1 stdout "non-share3                      KSK           publish" | awk '{print $9}'` &&

ZSK_CKA_ID_NON_1=`log_grep -o ods-ksmutil-cka_id1 stdout "non-share1                      ZSK           active" | awk '{print $9}'` &&
ZSK_CKA_ID_NON_2=`log_grep -o ods-ksmutil-cka_id1 stdout "non-share2                      ZSK           active" | awk '{print $9}'` &&
ZSK_CKA_ID_NON_3=`log_grep -o ods-ksmutil-cka_id1 stdout "non-share3                      ZSK           active" | awk '{print $9}'` &&

KSK_CKA_ID_SHA_1=`log_grep -o ods-ksmutil-cka_id1 stdout "share1                          KSK           publish" | awk '{print $9}'` &&
KSK_CKA_ID_SHA_2=`log_grep -o ods-ksmutil-cka_id1 stdout "share2                          KSK           publish" | awk '{print $9}'` &&
KSK_CKA_ID_SHA_3=`log_grep -o ods-ksmutil-cka_id1 stdout "share3                          KSK           publish" | awk '{print $9}'` &&

ZSK_CKA_ID_SHA_1=`log_grep -o ods-ksmutil-cka_id1 stdout "share1                          ZSK           active" | awk '{print $9}'` &&
ZSK_CKA_ID_SHA_2=`log_grep -o ods-ksmutil-cka_id1 stdout "share2                          ZSK           active" | awk '{print $9}'` &&
ZSK_CKA_ID_SHA_3=`log_grep -o ods-ksmutil-cka_id1 stdout "share3                          ZSK           active" | awk '{print $9}'` &&

# Check the non-shared are different and the shared are the same...

echo "Testing non-shared KSKs" &&
[ "$KSK_CKA_ID_NON_1" != "$KSK_CKA_ID_NON_2" ] &&
[ "$KSK_CKA_ID_NON_1" != "$KSK_CKA_ID_NON_3" ] &&
[ "$KSK_CKA_ID_NON_2" != "$KSK_CKA_ID_NON_3" ] &&

echo "Testing non-shared ZSKs" &&
[ "$ZSK_CKA_ID_NON_1" != "$ZSK_CKA_ID_NON_2" ] &&
[ "$ZSK_CKA_ID_NON_1" != "$ZSK_CKA_ID_NON_3" ] &&
[ "$ZSK_CKA_ID_NON_2" != "$ZSK_CKA_ID_NON_3" ] &&

echo "Testing shared KSKs" &&
[ "$KSK_CKA_ID_SHA_1" == "$KSK_CKA_ID_SHA_2" ] &&
[ "$KSK_CKA_ID_SHA_1" == "$KSK_CKA_ID_SHA_3" ] &&

echo "Testing shared ZSKs" &&
[ "$ZSK_CKA_ID_SHA_1" == "$ZSK_CKA_ID_SHA_2" ] &&
[ "$ZSK_CKA_ID_SHA_1" == "$ZSK_CKA_ID_SHA_3" ] &&

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

