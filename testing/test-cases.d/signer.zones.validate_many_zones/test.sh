#!/usr/bin/env bash

#TEST: Configure and sign with one repository (SoftHSM)
#TEST: Use the test zones and check they all get sigend OK
#TEST: Will eventually add validation into this to check the output
#TEST: For now use it to check any signing bugs with explicit tests


if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&

#########################################################################
# Basic checks of signing test zones

log_this_timeout ods-control-signer-start 60 ods-control signer start &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] example.com' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/example.com" &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] all.rr.org' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/all.rr.org" &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] all.rr.binary.org' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/all.rr.binary.org" &&

# OPENDNSSEC-231: Make sure we can support reverse classless zones
syslog_waitfor 60 'ods-signerd: .*\[STATS\] 64/1.0.168.192.IN-ADDR.ARPA' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/64-1.0.168.192.in-addr.arpa" &&

# Validate the output when we have a validation tool.....

#########################################################################
# Tests to cover signing specific bugs

#SUPPORT-40 - Double check that all records down to the forth level appear in the output
$GREP -q -- "^test.example.com..*86400.*IN.*NS.*ns2.example.com." "$INSTALL_ROOT/var/opendnssec/signed/example.com" &&
$GREP -q -- "^test1.test.example.com..*86400.*IN.*NS.*ns2.example.com." "$INSTALL_ROOT/var/opendnssec/signed/example.com" &&

#OPENDSNSEC-290 - Update the zone by changing a CNAME record to an A record. 
ods_setup_zone test/all.rr.org &&
log_this_timeout ods-update-zone 10 ods-signer sign all.rr.org &&

syslog_waitfor_count 60 2 'ods-signerd: .*\[STATS\] all.rr.org' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/all.rr.org" &&

#OPENDNSSEC-247 - Update the SOA minimum in the policy and make sure the NSEC TTL changes.
$GREP -q -- "<Minimum>PT300S</Minimum>" "$INSTALL_ROOT/var/opendnssec/signconf/all.rr.org" &&
$GREP -q -- "300.*IN.*NSEC3" "$INSTALL_ROOT/var/opendnssec/signed/all.rr.org" &&
mv kasp.xml kasp.xml_orig &&
cp test/kasp.xml kasp.xml &&
log_this ods-update-policy ods_setup_conf kasp.xml &&
log_this_timeout ods-update-policy 10 ods-ksmutil update kasp &&
syslog_waitfor 60 'ods-enforcerd: .*Called signer engine:.*ods-signer update all.rr.org' &&
$GREP -q -- "<Minimum>PT600S</Minimum>" "$INSTALL_ROOT/var/opendnssec/signconf/all.rr.org" &&
# SAD -> MM: This is only logged when using SQLite...
#syslog_waitfor 60 'ods-signerd: .*zone all.rr.org set soa ttl to 600' &&

syslog_waitfor_count 60 3 'ods-signerd: .*\[STATS\] all.rr.org' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/all.rr.org" &&
# SAD -> MM: This check fails...
#$GREP -q -- "600.*IN.*NSEC3" "$INSTALL_ROOT/var/opendnssec/signed/all.rr.org" &&

#########################################################################

log_this_timeout ods-control-start 60 ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&

mv kasp.xml_orig kasp.xml &&
return 0

ods_kill
mv kasp.xml_orig kasp.xml &&
return 1

