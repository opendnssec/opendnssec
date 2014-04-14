#!/usr/bin/env bash

#TEST: Test basic Input DNS Adapter
#TEST: Start OpenDNSSEC and see if zone gets transferred and signed
#TEST: and then see what happens with retries fail and the expire time passes.

## It requires setting up a zone in OpenDNSSEC with Input DNS Adapter,
## non-default zonelist.xml, non-default conf.xml, additional addns.xml.
## It requires setting up a primary name server (ldns-testns).
## It requires a checker tool like wdiff or ldns-verify-zone to review
## the result (possibly with an known good file).

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

## Check signed zone file [when we decide on auditor tool]

## Stop master name server
ods-signer verbosity 5 &&
ods_ldns_testns_kill &&

## See if we can transfer the signed zone
log_this_timeout drill 10 drill -p 15354 @127.0.0.1 axfr ods &&
log_grep drill stdout 'ods\..*3600.*IN.*SOA.*ns1\.ods\..*postmaster\.ods\..*1001.*30.*5.*31.*3600' &&

## See if SOA RETRY is being done
syslog_waitfor 35 'ods-signerd: .*\[xfrd\] zone ods make request round 0 master' &&
syslog_waitfor 35 'ods-signerd: .*\[xfrd\] zone ods make request round 1 master' &&
syslog_waitfor 35 'ods-signerd: .*\[xfrd\] zone ods make request round 2 master' &&
syslog_waitfor 5 'ods-signerd: .*\[xfrd\] zone ods sets timer timeout retry 5' &&

## See if it stops serving zone transfer after the SOA EXPIRE interval
sleep 35 &&
log_this_timeout drill 10 drill -p 15354 @127.0.0.1 axfr ods &&
(log_grep drill stderr 'Error in AXFR: SERVFAIL' || log_grep drill stderr 'AXFR failed.') &&

## Stop
ods_stop_ods-control && 
return 0

## Test failed. Kill stuff
ods_ldns_testns_kill
ods_kill
return 1
