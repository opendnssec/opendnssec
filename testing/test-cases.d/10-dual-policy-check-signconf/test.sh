#!/usr/bin/env bash
#
# Test 2 zones on separate policies, check the signconfs look reasonable

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

log_this_timeout ods-control-enforcer-start 30 ods-control enforcer start &&
syslog_waitfor 60 'ods-enforcerd: .*\[engine\] enforcer started' &&

ods_setup_env &&
syslog_waitfor 15 'ods-enforcerd: .*\[enforcer\] update Zone: ods' &&
syslog_waitfor 15 'ods-enforcerd: .*\[enforcer\] update Zone: ods2' &&

test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Resign>PT7200S</Resign>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Refresh>PT259200S</Refresh>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Default>PT1209600S</Default>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Denial>PT1296000S</Denial>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Jitter>PT43200S</Jitter>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<InceptionOffset>PT3600S</InceptionOffset>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<OptOut/>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<TTL>PT3600S</TTL>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Minimum>PT3600S</Minimum>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Serial>unixtime</Serial>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&

test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Resign>PT3600S</Resign>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Refresh>PT172800S</Refresh>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Default>PT1814400S</Default>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Denial>PT1728000S</Denial>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Jitter>PT36000S</Jitter>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<InceptionOffset>PT3000S</InceptionOffset>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
! $GREP -q -- "<OptOut/>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<TTL>PT3400S</TTL>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Minimum>PT6000S</Minimum>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Serial>counter</Serial>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&

log_this_timeout ods-control-enforcer-stop 30 ods-control enforcer stop &&
syslog_waitfor 60 'ods-enforcerd: .*\[engine\] enforcer shutdown' &&
return 0

ods_kill
return 1
