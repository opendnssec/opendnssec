#!/usr/bin/env bash

#TEST: Configure and sign with one repository (SoftHSM)
#TEST: Use the test zones and check they all get sigend OK
#TEST: Will eventually add validation into this to check the output
#TEST: For now use it to check any signing bugs with explicit tests

ODS_ENFORCER_WAIT_STOP_LOG=1800

# So we can use validns 0.7 it is installed from source so need to
# specify this path
case "$DISTRIBUTION" in
        redhat )
                append_path /usr/sbin
                ;;
esac


if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env  &&

ods_start_ods-control &&

#########################################################################
echo -n "LINE: ${LINENO} " && echo "\n############ Basic checks of signing test zones #########\n" &&

echo -n "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] example.com' &&
echo -n "LINE: ${LINENO} " && test -f "$INSTALL_ROOT/var/opendnssec/signed/example.com" &&

echo -n "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] all.rr.org' &&
echo -n "LINE: ${LINENO} " && test -f "$INSTALL_ROOT/var/opendnssec/signed/all.rr.org" &&

echo -n "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] all.rr.binary.org' &&
echo -n "LINE: ${LINENO} " && test -f "$INSTALL_ROOT/var/opendnssec/signed/all.rr.binary.org" &&

# OPENDNSSEC-231: Make sure we can support reverse classless zones
echo -n "LINE: ${LINENO} " && syslog_waitfor 300 'ods-signerd: .*\[STATS\] 64/1.0.168.192.IN-ADDR.ARPA' &&
echo -n "LINE: ${LINENO} " && test -f "$INSTALL_ROOT/var/opendnssec/signed/64-1.0.168.192.in-addr.arpa" &&

# Validate the output on redhat
case "$DISTRIBUTION" in
        redhat )
                # disable check for now, as validns can't seem to find the keys
                # can't use -p all as the zone has only 1 NS per name
                # log_this validate-zone-ods validns -s -p cname-other-data -p dname -p dnskey -p nsec3param-not-apex -p mx-alias -p ns-alias -p rp-txt-exists -p tlsa-host "$INSTALL_ROOT/var/opendnssec/signed/example.com" &&
                # log_grep validate-zone-ods stdout 'validation errors:   0' &&
                # log_this validate-zone-all.rr.org validns -s -p all "$INSTALL_ROOT/var/opendnssec/signed/all.rr.org" &&
                # log_grep validate-zone-all.rr.org stdout 'validation errors:   0'
                # The other two zone types don't seem to be supported by validns
                ;;
esac &&


#########################################################################
# Tests to cover signing specific bugs

#SUPPORT-40 - Double check that all records down to the forth level appear in the output
echo -n "LINE: ${LINENO} " && $GREP -q -- "^test.example.com..*86400.*IN.*NS.*ns2.example.com." "$INSTALL_ROOT/var/opendnssec/signed/example.com" &&
echo -n "LINE: ${LINENO} " && $GREP -q -- "^test1.test.example.com..*86400.*IN.*NS.*ns2.example.com." "$INSTALL_ROOT/var/opendnssec/signed/example.com" &&

#OPENDSNSEC-290 - Update the zone by changing a CNAME record to an A record.
ods_setup_zone test/all.rr.org &&
num_signedzones=`syslog_grep_count2 'ods-signerd: .*\[STATS\] all.rr.org'` &&
log_this_timeout ods-update-zone 20 ods-signer sign all.rr.org &&
syslog_waitfor_count 60 `expr $num_signedzones + 1` 'ods-signerd: .*\[STATS\] all.rr.org' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/all.rr.org" &&

# Note that the test above and below this sleep need to be separated by at least 1 second, otherwise
# the SOA serial will not have been changed (set to unixtime) and thus the signer will not notice
# a change to the zone, and not sign it
sleep 5 &&

#OPENDNSSEC-247 - Update the SOA minimum in the policy and make sure the NSEC TTL changes.
$GREP -q -- "<Minimum>PT5M</Minimum>" "$INSTALL_ROOT/var/opendnssec/signconf/all.rr.org" &&
$GREP -q -- "300.*IN.*NSEC3" "$INSTALL_ROOT/var/opendnssec/signed/all.rr.org" &&
cp kasp.xml kasp.xml_orig &&
cp test/kasp.xml kasp.xml &&
log_this ods-update-policy ods_setup_conf kasp.xml &&
log_this_timeout ods-update-policy 10 ods-enforcer policy import &&
#syslog_waitfor 300 'ods-enforcerd: .*Called signer engine:.*ods-signer update all.rr.org' &&
syslog_waitfor 300 'ods-enforcerd: .*\[enforcer\] updateZone: processing all.rr.org with policyName default' &&
syslog_waitfor 300 'ods-signerd: .*zone all.rr.org scheduled for immediate .*' &&
sleep 5 &&
$GREP -q -- "<Minimum>PT10M</Minimum>" "$INSTALL_ROOT/var/opendnssec/signconf/all.rr.org" &&
syslog_waitfor_count 300 `expr $num_signedzones + 2` 'ods-signerd: .*\[STATS\] all.rr.org' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/all.rr.org" &&
$GREP -q -- "600.*IN.*NSEC3" "$INSTALL_ROOT/var/opendnssec/signed/all.rr.org" &&

#########################################################################

ods_stop_ods-control && 

cp kasp.xml_orig kasp.xml &&
return 0

echo '*********** ERROR **********'
ods_kill
cp kasp.xml_orig kasp.xml
return 1
