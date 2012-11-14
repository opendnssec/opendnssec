#!/usr/bin/env bash
#
# Configure and sign with one repository (SoftHSM)
# Use the test zones and check they all get sigend OK
# Will eventually add validation into this to check the output
# For now use it to check any signing bugs with explicit tests

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&

log_this_timeout ods-control-signer-start 60 ods-control signer start &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] example.com' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/example.com" &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] all.rr.org' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/all.rr.org" &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] all.rr.binary.org' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/all.rr.binary.org" &&

# Validate the output when we have a validation tool.....
# In the mean time:

# SUPPORT-40. Double check that all records down to the forth level appear in the output
$GREP -q -- "^test.example.com..*86400.*IN.*NS.*ns2.example.com." "$INSTALL_ROOT/var/opendnssec/signed/example.com" &&
$GREP -q -- "^test1.test.example.com..*86400.*IN.*NS.*ns2.example.com." "$INSTALL_ROOT/var/opendnssec/signed/example.com" &&

log_this_timeout ods-control-start 60 ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
return 0

ods_kill
return 1

