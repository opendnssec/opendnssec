#!/usr/bin/env bash

#TEST: Basic test to use the signer --serial <nr> option
#TEST: Uses the 'counter' serial number option

#TODO: Test with other serial options

SIGNED_ZONE=$INSTALL_ROOT/var/opendnssec/signed/ods	# The zone path which already signed by OpenDNSsec	

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&


ods_reset_env &&

echo "##################  SETUP ###########################"
# Start enforcer and signer
echo -n "LINE: ${LINENO} " && ods_start_ods-control &&

## Wait for signed zone file

echo -n "LINE: ${LINENO} " && syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
echo -n "LINE: ${LINENO} " && test -f "$SIGNED_ZONE" &&
echo -n "LINE: ${LINENO} " && `$GREP -q -- "IN[[:space:]]SOA[[:space:]]ns1.ods.[[:space:]]postmaster.ods.[[:space:]]1001[[:space:]]" $SIGNED_ZONE` &&
echo -n "LINE: ${LINENO} " && echo "Zone originally signed with serial 1001" &&

echo "##################  Sign with higher serial ###########################"
echo -n "LINE: ${LINENO} " && log_this signer-sign-serial	ods-signer sign ods --serial 2000 &&
echo -n "LINE: ${LINENO} " && log_this signer-sign-serial	ods-signer flush &&
echo -n "LINE: ${LINENO} " && syslog_waitfor_count 60 2 'ods-signerd: .*\[STATS\] ods' &&
echo -n "LINE: ${LINENO} " && test -f "$SIGNED_ZONE" &&
echo -n "LINE: ${LINENO} " && `$GREP -q -- "IN[[:space:]]SOA[[:space:]]ns1.ods.[[:space:]]postmaster.ods.[[:space:]]2000[[:space:]]" $SIGNED_ZONE` &&
echo -n "LINE: ${LINENO} " && echo "Zone now signed with serial 2000" &&

echo "##################  Sign with lower serial ###########################"
echo -n "LINE: ${LINENO} " && log_this signer-sign-serial_fail	ods-signer sign ods --serial 500 &&
echo -n "LINE: ${LINENO} " && log_this signer-sign-serial_fail	ods-signer flush &&
echo -n "LINE: ${LINENO} " && log_grep signer-sign-serial_fail    stdout "Error: Unable to enforce serial 500 for zone ods." &&


ods_stop_ods-control &&
echo "** OK **" &&
return 0

ods_kill
return 1
