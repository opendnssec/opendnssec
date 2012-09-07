#!/usr/bin/env bash

## Test basic Output DNS Adapter
## Start OpenDNSsEC, see if the zone gets signed and see if NOTIFY
## messages are send and accepted.

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
## Check if NOTIFY is send and accepted
log_waitfor ldns-testns stdout 5 'comparepkt: match!' &&

## Check signed zone file [when we decide on auditor tool]

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
