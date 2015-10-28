#!/usr/bin/env bash

#TEST:Test basic Output DNS Adapter
#TEST: Start OpenDNSsEC, see if the zone gets signed and see if NOTIFY
#TEST: messages are send. 

#OPENDNSSEC-353: OpenDNSSEC does not add NSEC3s for empty non-terminals when DS below is added
## ldns-nsec3-hash -a 1 -t 5 on.ods: pg2pe0nhf68boi8ja5saif5aeckddlbv.
## ldns-nsec3-hash -a 1 -t 5 ottawa.on.ods: j48lenn1anop230egquckffan2n0qbkn.
## ldns-nsec3-hash -a 1 -t 5 problementry.ottawa.on.ods: nhro7p35mrhe2s9cqcdnggi2pbvpsse2.
## ldns-nsec3-hash -a 1 -t 5 aaa.ottawa.on.ods: ct6k2dk97n0g6ahn69gj460v3klmg39e.
## ldns-nsec3-hash -a 1 -t 5 zzz.ottawa.on.ods: m10bkro8ogntoae82vmdv6bkr086jejv.

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

## Start OpenDNSSEC
ods_start_ods-control && 

## Add zone and wait for signed zone file
sleep 2 &&
sed < ./zonefile-a > "$INSTALL_ROOT/var/opendnssec/unsigned/ods" -e 's/SERIAL/1001/g' &&
ods-enforcer zone add -z ods -p optout &&
syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods serial 1001*' &&

( grep 'IN[[:space:]]*NSEC3[^P]' $INSTALL_ROOT/var/opendnssec/signed/ods || true ) &&

echo "Update zonefile, add DS and wait for signed zone" &&
sleep 2 &&
sed < ./zonefile-b > "$INSTALL_ROOT/var/opendnssec/unsigned/ods" -e 's/SERIAL/1002/g' &&
ods-signer sign ods &&
syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods serial 1002*' &&
sleep 10 &&

echo "Check if empty non-terminal NSEC3s are added" &&
grep -q "ods.	3600	IN	SOA	ns1.ods. postmaster.ods. 1002 9000 4500 1209600 3600" "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "pg2pe0nhf68boi8ja5saif5aeckddlbv.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "j48lenn1anop230egquckffan2n0qbkn.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "nhro7p35mrhe2s9cqcdnggi2pbvpsse2.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
! grep -q "ct6k2dk97n0g6ahn69gj460v3klmg39e.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
! grep -q "m10bkro8ogntoae82vmdv6bkr086jejv.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

( grep 'IN[[:space:]]*NSEC3[^P]' $INSTALL_ROOT/var/opendnssec/signed/ods || true ) &&

echo "Update zonefile, remove DS again and wait for signed zone" &&
sleep 2 &&
sed < ./zonefile-c > "$INSTALL_ROOT/var/opendnssec/unsigned/ods" -e 's/SERIAL/1003/g' &&
ods-signer sign ods &&
syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods serial 1003*' &&
sleep 10 &&

( grep 'IN[[:space:]]*NSEC3[^P]' $INSTALL_ROOT/var/opendnssec/signed/ods || true ) &&

## Reintroduce zone with different policy and wait for signed zone file
ods_enforcer_idle &&
ods-enforcer zone delete -z ods &&
# Cautious sleep to make sure zone is gone
ods_enforcer_idle &&
sed < ./zonefile-c > "$INSTALL_ROOT/var/opendnssec/unsigned/ods" -e 's/SERIAL/2001/g' &&

ods-enforcer zone add -z ods -p optin &&
ods_waitfor_keys &&

## Wait for signed zone file
syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods serial 2001*' &&
( grep 'IN[[:space:]]*NSEC3[^P]' $INSTALL_ROOT/var/opendnssec/signed/ods || true ) &&
echo "Verify NSEC3s are not present" &&
(
grep -q "ods.	3600	IN	SOA	ns1.ods. postmaster.ods. 2001 9000 4500 1209600 3600" "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "pg2pe0nhf68boi8ja5saif5aeckddlbv.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "j48lenn1anop230egquckffan2n0qbkn.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods"
grep -q "nhro7p35mrhe2s9cqcdnggi2pbvpsse2.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "ct6k2dk97n0g6ahn69gj460v3klmg39e.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "m10bkro8ogntoae82vmdv6bkr086jejv.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods"
) &&

echo "Update zonefile, add DS and wait for signed zone" &&
sleep 2 &&
sed < ./zonefile-b > "$INSTALL_ROOT/var/opendnssec/unsigned/ods" -e 's/SERIAL/2002/g' &&
ods-signer sign ods &&
syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods serial 2002*' &&
sleep 10 &&

( grep 'IN[[:space:]]*NSEC3[^P]' $INSTALL_ROOT/var/opendnssec/signed/ods || true ) &&

echo "Check if required empty non-terminal NSEC3s are present" &&
grep -q "ods.	3600	IN	SOA	ns1.ods. postmaster.ods. 2002 9000 4500 1209600 3600" "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "pg2pe0nhf68boi8ja5saif5aeckddlbv.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "j48lenn1anop230egquckffan2n0qbkn.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "nhro7p35mrhe2s9cqcdnggi2pbvpsse2.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "ct6k2dk97n0g6ahn69gj460v3klmg39e.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "m10bkro8ogntoae82vmdv6bkr086jejv.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

echo "Update zonefile, remove DS again and wait for signed zone" &&
sleep 2 &&
sed < ./zonefile-c > "$INSTALL_ROOT/var/opendnssec/unsigned/ods" -e 's/SERIAL/2003/g' &&
ods-signer sign ods &&
syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods serial 2003*' &&
sleep 10 &&

( grep 'IN[[:space:]]*NSEC3[^P]' $INSTALL_ROOT/var/opendnssec/signed/ods || true ) &&

echo "Check if empty non-terminal NSEC3s are removed" &&
grep -q "ods.	3600	IN	SOA	ns1.ods. postmaster.ods. 2003 9000 4500 1209600 3600" "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "pg2pe0nhf68boi8ja5saif5aeckddlbv.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "j48lenn1anop230egquckffan2n0qbkn.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "nhro7p35mrhe2s9cqcdnggi2pbvpsse2.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "ct6k2dk97n0g6ahn69gj460v3klmg39e.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep -q "m10bkro8ogntoae82vmdv6bkr086jejv.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

## Stop
ods_stop_ods-control && 
return 0

## Test failed. Kill stuff
echo "UNSIGNED ZONE"
echo "----------------------------------------"
cat "$INSTALL_ROOT/var/opendnssec/unsigned/ods"
echo "SIGNED ZONE"
echo "----------------------------------------"
cat "$INSTALL_ROOT/var/opendnssec/signed/ods"
ods_kill
return 1
