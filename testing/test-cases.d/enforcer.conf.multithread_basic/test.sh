#!/usr/bin/env bash

#TEST: Configure and sign 4 zones with one repository using multi-threaded Enforcer
#TEST: and 3 different policies, 1 with shared keys and 2 without.

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&
if [ -n "$HAVE_MYSQL" ]; then
	syslog_waitfor 60 'ods-enforcerd: .*\[worker\[4\]\]: started'
fi &&

log_this_timeout ods-control-signer-start 60 ods-control signer start &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods2' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods3' &&
syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods4' &&

test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods2" &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods3" &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods4" &&

log_this_timeout ods-control-start 60 ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
return 0

ods_kill
return 1
