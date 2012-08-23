#!/usr/bin/env bash

## Test basic Output DNS Adapter
## It requires setting up a zone in OpenDNSSEC with Output DNS Adapter,
## non-default zonelist.xml, non-default conf.xml, additional addns.xml.
## It requires setting up a secondary name server (ldns-testns) to accept the notifies.
## It requires drill or dig to fetch the axfr.
## It requires a checker tool like wdiff or ldns-verify-zone to review
## the result (possibly with an known good file).

## Configuration set up
ods_get_random_port 2 &&
LISTENER_PORT=$RND_PORT &&
SLAVE_PORT=$(($LISTENER_PORT + 1)) &&
cp conf.xml.in conf.xml &&
cp addns.xml.in addns.xml &&
apply_parameter "LISTENER_PORT" "$LISTENER_PORT" conf.xml &&
apply_parameter "SLAVE_PORT" "$SLAVE_PORT" addns.xml &&

# Have to reset up the conf, because we apply special parameters
ods_setup_conf &&
ods_reset_env &&

## Start master name server
ods_ldns_testns $SLAVE_PORT ods.datafile &&

## Start OpenDNSSEC
log_this_timeout ods-control-start 30 ods-control start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

## Wait for signed zone file
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&

## Check signed zone file [when we decide on auditor tool]

## Stop
log_this_timeout ods-control-stop 30 ods-control stop
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
ods_ldns_testns_kill &&
return 0

## Test failed. Kill stuff
ods_ldns_testns_kill
ods_kill
return 1
