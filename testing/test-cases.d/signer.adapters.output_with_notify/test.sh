#!/usr/bin/env bash

## Test basic Output DNS Adapter
## Start OpenDNSsEC, see if NOTIFY messages are send and accepted.

#TEST: Test basic Output DNS Adapter
#TEST: Start OpenDNSSEC and see if zone gets transferred and signed
#TEST: and see if NOTIFY messages are sent and accepted.


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
## Check if NOTIFY is send and accepted
log_waitfor ldns-testns stdout 5 'comparepkt: match!' &&

## Check signed zone file [when we decide on auditor tool]

## Stop
ods_stop_ods-control && 
ods_ldns_testns_kill &&
return 0

## Test failed. Kill stuff
ods_ldns_testns_kill
ods_kill
return 1
