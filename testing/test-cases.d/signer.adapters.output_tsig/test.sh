#!/usr/bin/env bash

#TEST: Test basic Output DNS Adapter
#TEST: Start OpenDNSSEC and see if zone gets transferred and signed
#TEST: and see if NOTIFY messages are sent.

# So we can use validns 0.7 it is installed from source so need to
# specify this path
case "$DISTRIBUTION" in
        redhat )
                append_path /usr/sbin
                ;;
esac

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

## Start secondary name server
ods_ldns_testns 15353 ods.datafile &&

## Start OpenDNSSEC
ods_start_ods-control && 

## Wait for signed zone file
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&

## SOA query (DO bit set)
log_this_timeout soa 10 drill -D -p 15354 -y secret.example.com:sw0nMPCswVbes1tmQTm1pcMmpNRK+oGMYN+qKNR/BwQ=:hmac-sha256 @127.0.0.1 soa ods &&
log_grep soa stdout 'ods\..*3600.*IN.*SOA.*ns1\.ods\..*postmaster\.ods\..*1001.*9000.*4500.*1209600.*3600' &&

## See if we can transfer the signed zone
log_this_timeout axfr 10 drill -p 15354 -y secret.example.com:sw0nMPCswVbes1tmQTm1pcMmpNRK+oGMYN+qKNR/BwQ=:hmac-sha256 @127.0.0.1 axfr ods &&
log_grep axfr stdout 'ods\..*3600.*IN.*SOA.*ns1\.ods\..*postmaster\.ods\..*1001.*9000.*4500.*1209600.*3600' &&
log_grep axfr stdout 'ods\..*600.*IN.*MX.*10.*mail\.ods\.' &&

## See if we send overflow UDP if does not fit.
log_this_timeout ixfr 10 drill -p 15354 -y secret.example.com:sw0nMPCswVbes1tmQTm1pcMmpNRK+oGMYN+qKNR/BwQ=:hmac-sha256 @127.0.0.1 ixfr ods &&
syslog_waitfor 10 'ods-signerd: .*\[axfr\] axfr fallback zone ods' &&
syslog_waitfor 10 'ods-signerd: .*\[axfr\] axfr udp overflow zone ods' &&
{log_grep ixfr stdout 'ods\..*IN.*TYPE251' || log_grep ixfr stdout 'ods\..*IN.*IXFR'} &&
log_grep ixfr stdout 'ods\..*3600.*IN.*SOA.*ns1\.ods\..*postmaster\.ods\..*1001.*9000.*4500.*1209600.*3600' &&
!log_grep ixfr stdout 'ods\..*600.*IN.*MX.*10.*mail\.ods\.' &&

## See if we fallback to AXFR if IXFR not available. [OPENDNSSEC-466]
log_this_timeout ixfr-tcp 10 drill -t -p 15354 -y secret.example.com:sw0nMPCswVbes1tmQTm1pcMmpNRK+oGMYN+qKNR/BwQ=:hmac-sha256 @127.0.0.1 ixfr ods &&
log_grep ixfr-tcp stdout 'ods\..*3600.*IN.*SOA.*ns1\.ods\..*postmaster\.ods\..*1001.*9000.*4500.*1209600.*3600' &&
log_grep ixfr-tcp stdout 'ods\..*600.*IN.*MX.*10.*mail\.ods\.' &&

## Stop
ods_stop_ods-control && 
ods_ldns_testns_kill &&
return 0

## Test failed. Kill stuff
ods_ldns_testns_kill
ods_kill
return 1
