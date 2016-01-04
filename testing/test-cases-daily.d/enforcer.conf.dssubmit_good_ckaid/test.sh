#!/usr/bin/env bash
#
#TEST: Test to see that the DSSUB command with --cka_id is dealt with as expected

ENFORCER_WAIT=90	# Seconds we wait for enforcer to run
ENFORCER_COUNT=2	# How many log lines we expect to see

cp dssub.pl "$INSTALL_ROOT/var/opendnssec/enforcer/" &&
chmod 744 "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.pl" &&

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

##################  SETUP ###########################
# Start enforcer (Zone already exists and we let it generate keys itself)
ods_start_enforcer &&

# Check that we are trying to use the correct command:
#syslog_grep " ods-enforcerd: .*Using command: $INSTALL_ROOT/var/opendnssec/enforcer/dssub.pl to submit DS records" &&

# Check that we have 2 keys
log_this ods-enforcer-key-list1 ods-enforcer key list -a &&
log_grep ods-enforcer-key-list1 stdout 'ods[[:space:]]*KSK[[:space:]]*generate' &&
log_grep ods-enforcer-key-list1 stdout 'ods[[:space:]]*ZSK[[:space:]]*publish' &&

# Grab the CKA_ID and KEYTAG of the KSK
log_this ods-enforcer-cka_keytag ods-enforcer key list --verbose --all &&
KSK_CKA_ID=`log_grep -o ods-enforcer-cka_keytag stdout "ods[[:space:]]*KSK[[:space:]]*generate" | awk '{print $8}'` &&
KSK_KEYTAG=`log_grep -o ods-enforcer-cka_keytag stdout "ods[[:space:]]*KSK[[:space:]]*genera" | awk '{print $10}'` &&

## Jump forward a couple of hours so the KSK will be ready
##################  STEP 1: Time = 4hrs ###########################
ods_enforcer_leap_to 14400 &&

# We should be ready for a ds-seen on ods
syslog_grep "ods-enforcerd: .*\[enforce_task\] please submit DS with keytag $KSK_KEYTAG for zone ods" &&

# Check that no dssub.out file exists
echo "Testing dssub command ran" &&
test -f "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" &&

echo "Testing contents of dssub.out" &&
grep "ods. 600 IN DNSKEY 257 3 7 AwEAA.*" "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" &&
grep "; {cka_id = $KSK_CKA_ID}" "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" &&

# Clean up
echo "Cleaning up files" &&
rm "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.pl" &&
rm "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" &&

ods_stop_enforcer &&
return 0

# Something went wrong, make sure clean up tmp if nothing else
rm "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.pl" &&
mv "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" "." &&

echo
echo "************ERROR******************"
echo
ods_kill
return 1

