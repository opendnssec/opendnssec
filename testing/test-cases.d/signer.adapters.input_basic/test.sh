#!/usr/bin/env bash

#TEST: Test basic Input DNS Adapter
#TEST: Start OpenDNSSEC and see if zone gets transferred and signed.

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

## Start master name server
ods_ldns_testns 15353 ods.datafile &&

## Start OpenDNSSEC
ods_start_ods-control &&

## Wait for signed zone file
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] \.' &&

## Check signed zone file [when we decide on auditor tool]
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/root" &&
## Validate the output
log_this validate-zone-ods validns -s -p all "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
log_grep validate-zone-ods stdout 'validation errors:   0' &&

## Bump verbosity (for grepping important syslog lines)
ods-signer verbosity 5 &&

## Fake notify
ldns-notify -p 15354 -s 1001 -r 2 -z ods 127.0.0.1 &&

## Request IXFR/UDP
syslog_waitfor 10 'ods-signerd: .*\[xfrd\] zone ods request udp/ixfr=1000 to 127\.0\.0\.1' &&
syslog_waitfor 10 'ods-signerd: .*\[xfrd\] zone ods received too short udp reply from 127\.0\.0\.1, retry tcp' &&

## Request IXFR/TCP
syslog_waitfor 10 'ods-signerd: .*\[xfrd\] zone ods request tcp/ixfr=1000 to 127\.0\.0\.1' &&
syslog_waitfor 10 'ods-signerd: .*\[xfrd\] reschedule task for zone ods: disk serial=1001 acquired=.*, memory serial=1000 acquired=.*' &&
syslog_waitfor_count 60 2 'ods-signerd: .*\[STATS\] ods' &&

## Retransfer
log_this ods-signer-retransfer ods-signer retransfer ods &&
syslog_waitfor_count 60 3 'ods-signerd: .*\[STATS\] ods' &&

## We should now have label34 back again and no more label35 to label40
grep 'label34' "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
! grep 'label35' "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

## Stop
ods_stop_ods-control &&
ods_ldns_testns_kill &&
return 0

## Test failed. Kill stuff
ods_ldns_testns_kill
ods_kill
return 1
