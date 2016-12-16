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

echo -n "LINE: ${LINENO} " && ods_start_enforcer &&

# Check that we have 2 keys
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-key-list1 ods-enforcer key list --all &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-key-list1 stdout 'ods[[:space:]]*KSK[[:space:]]*publish' &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-key-list1 stdout 'ods[[:space:]]*ZSK[[:space:]]*ready' &&

# Grab the KEYTAG of the KSK
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-keytag ods-enforcer key list --verbose --all &&
echo -n "LINE: ${LINENO} " && KSK_KEYTAG=`log_grep -o ods-enforcer-keytag stdout "ods[[:space:]]*KSK[[:space:]]*publish" | awk '{print $10}'` &&

## Jump forward one hour so the KSK will be ready, obviosuly depends on Propagation Time and TTL 
##################  STEP 1: Time = 4 hr ###########################

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-time-leap ods_enforcer_leap_to 14400 &&



# We should be ready for a ds-seen on ods
echo -n "LINE: ${LINENO} " && syslog_grep "\[enforce_task\] please submit DS with keytag $KSK_KEYTAG for zone ods" &&


# Check that dssub.out file exists
echo -n "LINE: ${LINENO} " && echo "Testing dssub command ran" &&
echo -n "LINE: ${LINENO} " && test -f "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" &&

echo -n "LINE: ${LINENO} " && echo "Testing contents of dssub.out" &&
echo -n "LINE: ${LINENO} " && grep "ods. 600 IN DNSKEY 257 3 7 AwEAA.*" "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" &&
echo -n "LINE: ${LINENO} " && ! grep "; {cka_id = .*}" "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" &&

# Also export the key to double check the TTL 
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-key-export 'ods-enforcer key export -z ods' &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-key-export stdout 'ods.	600	IN	DNSKEY	257 3 7 AwEAA' &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-key-export-ds 'ods-enforcer key export -z ods --ds ' &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-key-export-ds stdout 'ods.	300	IN	DS	' &&

# Clean up
echo -n "LINE: ${LINENO} " && echo "Cleaning up files" &&
echo -n "LINE: ${LINENO} " && rm -f "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.pl" &&
echo -n "LINE: ${LINENO} " && rm -f "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" &&

echo -n "LINE: ${LINENO} " && ods_stop_enforcer &&
echo -n "LINE: ${LINENO} " && return 0

# Something went wrong, make sure clean up tmp if nothing else
rm -f "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.pl"
mv "$INSTALL_ROOT/var/opendnssec/enforcer/dssub.out" "."

echo
echo "************ERROR******************"
echo
ods_kill
return 1



