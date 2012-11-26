#!/usr/bin/env bash

#TEST: Test 2 zones on separate policies, check the signconfs look reasonable

#CATEGORY: enforcer-policies-dual_policy_check_signconf

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&

test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Resign>PT180S</Resign>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Refresh>PT900S</Refresh>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Default>PT3600S</Default>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Denial>PT3600S</Denial>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Jitter>PT60S</Jitter>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<InceptionOffset>PT60S</InceptionOffset>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<OptOut />" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<TTL>PT600S</TTL>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Minimum>PT300S</Minimum>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Serial>unixtime</Serial>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&

test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Resign>PT300S</Resign>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Refresh>PT1500S</Refresh>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Default>PT7200S</Default>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Denial>PT7200S</Denial>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Jitter>PT120S</Jitter>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<InceptionOffset>PT120S</InceptionOffset>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
! $GREP -q -- "<OptOut />" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<TTL>PT1200S</TTL>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Minimum>PT600S</Minimum>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Serial>counter</Serial>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&

log_this_timeout ods-control-enforcer-stop 60 ods-control enforcer stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
return 0

ods_kill
return 1
