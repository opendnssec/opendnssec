#!/usr/bin/env bash

#TEST: Test 2 zones on separate policies, check the signconfs look reasonable


if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

ods_start_enforcer &&

test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Resign>PT2H</Resign>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Refresh>P3D</Refresh>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Default>P14D</Default>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Denial>P15D</Denial>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Jitter>PT12H</Jitter>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<InceptionOffset>PT1H</InceptionOffset>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<OptOut/>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<TTL>PT1H</TTL>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Minimum>PT1H</Minimum>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&
$GREP -q -- "<Serial>unixtime</Serial>" "$INSTALL_ROOT/var/opendnssec/signconf/ods.xml" &&

test -f "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Resign>PT1H</Resign>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Refresh>P2D</Refresh>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Default>P21D</Default>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Denial>P20D</Denial>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Jitter>PT10H</Jitter>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<InceptionOffset>PT50M</InceptionOffset>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
! $GREP -q -- "<OptOut/>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<TTL>PT1H</TTL>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Minimum>PT1H40M</Minimum>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&
$GREP -q -- "<Serial>counter</Serial>" "$INSTALL_ROOT/var/opendnssec/signconf/ods2.xml" &&

ods_stop_enforcer &&
return 0

ods_kill
return 1
