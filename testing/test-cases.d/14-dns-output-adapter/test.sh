#!/usr/bin/env bash

## Test basic Output DNS Adapter
## Start OpenDNSsEC, see if the zone gets signed and see if NOTIFY
## messages are send.

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

## Start master name server
ods_ldns_testns 15353 ods.datafile &&

## Start OpenDNSSEC
log_this_timeout ods-control-start 60 ods-control start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

## Wait for signed zone file
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
## Retry NOTIFY
syslog_waitfor 120 'ods-signerd: .*\[notify\] notify max retry for zone ods, 127\.0\.0\.1 unreachable' &&

ods-signer verbosity 6 &&

## See if we can transfer the signed zone
log_this_timeout axfr 10 drill -p 15354 @127.0.0.1 axfr ods &&
log_waitfor axfr stdout 5 'ods\..*3600.*IN.*SOA.*ns1\.ods\..*postmaster\.ods\..*1001.*9000.*4500.*1209600.*3600' &&
log_waitfor axfr stdout 5 'ods\..*600.*IN.*MX.*10.*mail\.ods\.' &&
## See if we send overflow UDP if does not fit.
log_this_timeout ixfr 10 drill -p 15354 @127.0.0.1 ixfr ods &&
syslog_waitfor 10 'ods-signerd: .*\[axfr\] axfr fallback zone ods' &&
syslog_waitfor 10 'ods-signerd: .*\[axfr\] axfr udp overflow zone ods' &&
log_waitfor ixfr stdout 5 'ods\..*IN.*IXFR' &&
log_waitfor ixfr stdout 5 'ods\..*3600.*IN.*SOA.*ns1\.ods\..*postmaster\.ods\..*1001.*9000.*4500.*1209600.*3600' &&
! (log_waitfor ixfr stdout 5 'ods\..*600.*IN.*MX.*10.*mail\.ods\.') &&

## See if we fallback to AXFR if IXFR not available.

log_this_timeout ixfr-tcp 10 drill -t -p 15354 @127.0.0.1 ixfr ods &&
log_waitfor ixfr-tcp stdout 5 'ods\..*IN.*IXFR' &&
log_waitfor ixfr-tcp stdout 5 'ods\..*3600.*IN.*SOA.*ns1\.ods\..*postmaster\.ods\..*1001.*9000.*4500.*1209600.*3600' &&
log_waitfor ixfr-tcp stdout 5 'ods\..*600.*IN.*MX.*10.*mail\.ods\.' &&

## Stop
log_this_timeout ods-control-stop 60 ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
ods_ldns_testns_kill &&
return 0

## Test failed. Kill stuff
ods_ldns_testns_kill
ods_kill
return 1
