#!/usr/bin/env bash

#TEST: Basic test to use the signer --serial <nr> option
#TEST: Uses the 'counter' serial number option

#TODO: Test with other serial options

SIGNED_ZONE=$INSTALL_ROOT/var/opendnssec/signed/ods	# The zone path which already signed by OpenDNSSSEC

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&


ods_reset_env &&

##################  SETUP ###########################
# Start enforcer and signer
ods_start_ods-control &&

## Wait for signed zone file
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
test -f "$SIGNED_ZONE" &&
`$GREP -q -- "IN[[:space:]]SOA[[:space:]]ns1.ods.[[:space:]]postmaster.ods.[[:space:]]1001[[:space:]]" $SIGNED_ZONE` &&
echo "Zone originally signed with serial 1001" &&

##################  Sign with higher serial ###########################
log_this signer-sign-serial	ods-signer sign ods --serial 2000 &&
log_this signer-sign-serial	ods-signer flush &&
syslog_waitfor_count 60 2 'ods-signerd: .*\[STATS\] ods' &&
test -f "$SIGNED_ZONE" &&
`$GREP -q -- "IN[[:space:]]SOA[[:space:]]ns1.ods.[[:space:]]postmaster.ods.[[:space:]]2000[[:space:]]" $SIGNED_ZONE` &&
echo "Zone now signed with serial 2000" &&

##################  Sign with lower serial ###########################
log_this signer-sign-serial_fail	ods-signer sign ods --serial 500 &&
log_this signer-sign-serial_fail	ods-signer flush &&
log_grep signer-sign-serial_fail	stdout "Error: Unable to enforce serial 500 for zone ods." && 


ods_stop_ods-control &&
echo "** OK **" &&
return 0

ods_kill
return 1
