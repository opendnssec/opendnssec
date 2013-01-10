#!/usr/bin/env bash

#TEST:Test basic Output DNS Adapter
#TEST: Start OpenDNSsEC, see if the zone gets signed and see if NOTIFY
#TEST: messages are send. 

#OPENDNSSEC-353: OpenDNSSEC does not add NSEC3s for empty non-terminals when DS below is added

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

## Start OpenDNSSEC
log_this_timeout ods-control-start 60 ods-control start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

## Wait for signed zone file
syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods serial 1001*' &&
## ldns-nsec3-hash -a 1 -t 5 on.ods: pg2pe0nhf68boi8ja5saif5aeckddlbv.
## ldns-nsec3-hash -a 1 -t 5 ottawa.on.ods: j48lenn1anop230egquckffan2n0qbkn.
grep "ods.	3600	IN	SOA	ns1.ods. postmaster.ods. 1001 9000 4500 1209600 3600" "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
! grep "pg2pe0nhf68boi8ja5saif5aeckddlbv.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
! grep "j48lenn1anop230egquckffan2n0qbkn.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

## Update zonefile, add DS
cp -- ./unsigned/ods.2 "$INSTALL_ROOT/var/opendnssec/unsigned/ods" &&
ods-signer sign ods &&
syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods serial 1002*' &&
sleep 3 &&
ods-signer verbosity 5 &&

## Check if empty non-terminal NSEC3s are added
grep "ods.	3600	IN	SOA	ns1.ods. postmaster.ods. 1002 9000 4500 1209600 3600" "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep "pg2pe0nhf68boi8ja5saif5aeckddlbv.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
grep "j48lenn1anop230egquckffan2n0qbkn.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

## Update zonefile, remove DS again
cp -- ./unsigned/ods.3 "$INSTALL_ROOT/var/opendnssec/unsigned/ods" &&
ods-signer sign ods &&
syslog_waitfor 60 'ods-signerd: .*\[adapter\] write zone ods serial 1003*' &&
sleep 3 &&

## Check if empty non-terminal NSEC3s are removed
grep "ods.	3600	IN	SOA	ns1.ods. postmaster.ods. 1003 9000 4500 1209600 3600" "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
! grep "pg2pe0nhf68boi8ja5saif5aeckddlbv.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
! grep "j48lenn1anop230egquckffan2n0qbkn.ods." "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

## Stop
log_this_timeout ods-control-stop 60 ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
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
