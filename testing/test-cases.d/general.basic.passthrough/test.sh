#!/usr/bin/env bash
#
#TEST: Make sure no signatures are added to a zone in a passthrough
#policy. Also see that the SOA serial is bumped.

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&
ods_start_ods-control &&

## add zone in passthrough policy
log_this 01-zone_add ods-enforcer zone add -z example.com &&

## wait for signed file to appear
syslog_waitfor 10 'ods-signerd: .*\[STATS\] example.com' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/example.com" &&

## test absence of signatures
grep -vq RRSIG "$INSTALL_ROOT/var/opendnssec/signed/example.com" &&

## test serial bump
SOA1=`grep SOA "$INSTALL_ROOT/var/opendnssec/unsigned/example.com" | cut -f5 | cut -f3 -d" "` &&
SOA2=`grep SOA "$INSTALL_ROOT/var/opendnssec/signed/example.com" | cut -f5 | cut -f3 -d" "` &&
test $SOA1 -lt $SOA2 &&

## ask for a resign
touch "$INSTALL_ROOT/var/opendnssec/signed/example.com" &&
log_this 02-resign ods-signer sign example.com &&
syslog_waitfor_count 10 2 'ods-signerd: .*\[STATS\] example.com' &&

## serial bumped again?
SOA3=`grep SOA "$INSTALL_ROOT/var/opendnssec/signed/example.com" | cut -f5 | cut -f3 -d" "` &&
test $SOA2 -lt $SOA3 &&

ods_stop_ods-control &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

