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

ods-signer verbosity 5 &&

## Wait for signed zone file
syslog_waitfor 300 'ods-signerd: .*\[STATS\] ods' &&

## Check signed zone file [when we decide on auditor tool]
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
# Validate the output on redhat
# case "$DISTRIBUTION" in
#         redhat )
#                 log_this validate-zone-ods validns -s -p all "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
#                 log_grep validate-zone-ods stdout 'validation errors:   0'
#                 ;;
# esac &&

## Fake notify
ldns-notify -p 15354 -s 1001 -r 2 -z ods 127.0.0.1 &&

## Request IXFR/UDP
syslog_waitfor 60 'ods-signerd: .*\[xfrd\] zone ods sending udp query id=.* qtype=IXFR to 127\.0\.0\.1' &&
syslog_waitfor 60 'ods-signerd: .*\[xfrd\] zone ods received too short udp reply from 127\.0\.0\.1, retry tcp'

## Request IXFR/TCP
syslog_waitfor 60 'ods-signerd: .*\[xfrd\] zone ods request ixfr to 127\.0\.0\.1' &&
syslog_waitfor 60 'ods-signerd: .*\[xfrd\] reschedule task for zone ods: disk serial=1001 acquired=.*, memory serial=1000 acquired=.*' &&

## Stop
ods_stop_ods-control && 
ods_ldns_testns_kill &&
return 0

## Test failed. Kill stuff
ods_ldns_testns_kill
ods_kill
return 1
