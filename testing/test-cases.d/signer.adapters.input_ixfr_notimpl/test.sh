#!/usr/bin/env bash

#TEST: Test basic Input DNS Adapter
#TEST: Start OpenDNSSEC and see if zone gets transferred and signed.
#TEST: Check we can support NOTIMPL from nameserver
#OPENDNSSEC-366: After key rollover, signer is failing task read and blocks signing

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

## Fake notify
log_this ldns-notify ldns-notify -p 15354 -s 1001 -r 2 -z ods 127.0.0.1 &&

## Request IXFR/UDP
syslog_waitfor 300 'ods-signerd: .*\[xfrd\] zone ods request udp/ixfr=.* to 127\.0\.0\.1' &&
syslog_waitfor 300 'ods-signerd: .*\[xfrd\] bad packet: zone ods received error code NOTIMPL from 127\.0\.0\.1' &&

## Request AXFR/TCP
syslog_waitfor 60 'ods-signerd: .*\[xfrd\] zone ods request axfr to 127\.0\.0\.1' &&

## Do a ods-signer sign ("key rollover"), and don't fail reading because of missing xfr.
ods-signer sign ods &&
syslog_waitfor 60 'ods-signerd: .*zone ods unsigned data not changed, continue' &&

## Stop
ods_stop_ods-control && 
ods_ldns_testns_kill &&
return 0

## Test failed. Kill stuff
ods_ldns_testns_kill
ods_kill
return 1
