#!/usr/bin/env bash
#
#TEST: Test to see that the DSSUB command is dealt with as expected

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
sleep 60 &&

# Check that we have 2 keys
log_this ods-enforcer-key-list1 ods-enforcer key list &&
log_grep ods-enforcer-key-list1 stdout 'ods[[:space:]]*KSK[[:space:]]*generate' &&
log_grep ods-enforcer-key-list1 stdout 'ods[[:space:]]*ZSK[[:space:]]*publish' &&

# Grab the KEYTAG of the KSK
log_this ods-enforcer-keytag ods-enforcer key list --verbose &&
KSK_KEYTAG=`log_grep -o ods-enforcer-keytag stdout "ods[[:space:]]*KSK[[:space:]]*generate" | awk '{print $10}'` &&

## Jump forward one hour so the KSK will be ready, obviosuly depends on Propagation Time and TTL 
##################  STEP 1: Time = 1 hr ###########################

log_this ods-enforcer-time-leap ods_enforcer_leap_to 3600 &&


# We should be ready for a ds-seen on ods
syslog_grep "\[enforce_task\] please submit DS with keytag $KSK_KEYTAG for zone ods" &&


# Check that dssub.out file exists
echo "Testing dssub command ran" &&
test -f "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" &&

echo "Testing contents of dssub.out" &&
grep "ods. 600 IN DNSKEY 257 3 7 AwEAA.*" "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" &&
! grep "; {cka_id = .*}" "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" &&

# Also export the key to double check the TTL 
log_this ods-enforcer-key-export 'ods-enforcer key export -z ods' &&
log_grep ods-enforcer-key-export stdout 'ods.	600	IN	DNSKEY	257 3 7 AwEAA' &&

log_this ods-enforcer-key-export-ds 'ods-enforcer key export -z ods --ds ' &&
log_grep ods-enforcer-key-export-ds stdout 'ods.	300	IN	DS	' &&

# Clean up
echo "Cleaning up files" &&
rm -f "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.pl" &&
rm -f "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" &&

ods_stop_enforcer &&
return 0

# Something went wrong, make sure clean up tmp if nothing else
rm -f "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.pl"
mv "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" "."

echo
echo "************ERROR******************"
echo
ods_kill
return 1



