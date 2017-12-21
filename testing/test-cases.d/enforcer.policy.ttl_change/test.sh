#!/usr/bin/env bash
#
#TEST: change TTL of key to something shorter and see if the enforcer
# would consider the current published TTL.
# method:
#  - add zone, roll in key
#  - stop, change TTL
#  - start update policy
#  - key rollover -t ZSK
#  - see how long it takes for the new DNSKEY to become omnipresent

## expected behaviour introduction will take about and hour, roll as well.
## runtime 8 seconds
## wrong: roll takes about a minute (the newer TTL)

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env -i -n &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add --zone ods1 &&
echo "################## LEAP TO OMNIPRESENT ZSK DNSKEY" &&
echo "LINE: ${LINENO} " && TSTART=`ods-enforcer queue|grep "It is now"|sed -E "s/^.*\(([0-9]+) .*$/\1/"` &&
echo -n "LINE: ${LINENO} " && echo "Current time:" $TSTART
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&

echo "################## TEST: 1 ZSK with DNSKEY OMNIPRESENT" &&
echo "LINE: ${LINENO} " && COUNT=`ods-enforcer key list -d -p |grep ZSK|cut -f 4 -d ";" |grep -c omnipresent` &&
echo "LINE: ${LINENO} " && [ $COUNT -eq 1 ] &&

echo "################## TEST: roughly an hour should have passed" &&
echo "LINE: ${LINENO} " && TEND=`ods-enforcer queue|grep "It is now"|sed -E "s/^.*\(([0-9]+) .*$/\1/"` &&
DELTA=$((TEND-TSTART)) &&
echo -n "LINE: ${LINENO} " && echo "seconds passed:" $DELTA &&
test $DELTA -gt 3500 && ## roughly an hour must have passed in this one leap

echo "################## LOWER TTL AND RELOAD" &&
echo -n "LINE: ${LINENO} " && cp kasp-short-ttl.xml  "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
echo -n "LINE: ${LINENO} " && ods-enforcer policy import &&
echo -n "LINE: ${LINENO} " && ods-enforcer key rollover -t ZSK -z ods1 &&

echo "################## LEAP TO OMNIPRESENT ZSK DNSKEY" &&
echo "LINE: ${LINENO} " && TSTART=`ods-enforcer queue|grep "It is now"|sed -E "s/^.*\(([0-9]+) .*$/\1/"` &&
echo -n "LINE: ${LINENO} " && echo "Current time:" $TSTART
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&

echo "################## TEST: roughly an hour should have passed" &&
echo "LINE: ${LINENO} " && COUNT=`ods-enforcer key list -d -p |grep ZSK|cut -f 4 -d ";" |grep -c omnipresent` &&
echo "LINE: ${LINENO} " && [ $COUNT -eq 2 ] &&

echo "LINE: ${LINENO} " && TEND=`ods-enforcer queue|grep "It is now"|sed -E "s/^.*\(([0-9]+) .*$/\1/"` &&
DELTA=$((TEND-TSTART)) &&
echo -n "LINE: ${LINENO} " && echo "seconds passed:" $DELTA &&
test $DELTA -gt 3500 && ## roughly an hour must have passed in this one leap

## Now we add 3th key, but since the previous DNSKEY set had a 1 minute TTL
## we expect roughly that time to pass for the DNSKEY to go rum->omn

echo "DEBUG: " && ods-enforcer key list -d -p &&
echo -n "LINE: ${LINENO} " && ods-enforcer key rollover -t ZSK -z ods1 &&
echo "DEBUG: " && ods-enforcer key list -d -p &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo "DEBUG: " && ods-enforcer key list -d -p &&

echo "################## LEAP TO OMNIPRESENT ZSK DNSKEY" &&
echo -n "LINE: ${LINENO} " && echo "Current time:" $TSTART
echo "LINE: ${LINENO} " && TSTART=`ods-enforcer queue|grep "It is now"|sed -E "s/^.*\(([0-9]+) .*$/\1/"` &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo "DEBUG: " && ods-enforcer key list -d -p &&

echo "################## TEST: roughly an minute should have passed" &&
echo "LINE: ${LINENO} " && COUNT=`ods-enforcer key list -d -p |grep ZSK|cut -f 4 -d ";" |grep -c omnipresent` &&
echo "LINE: ${LINENO} " && [ $COUNT -eq 3 ] &&
echo "LINE: ${LINENO} " && TEND=`ods-enforcer queue|grep "It is now"|sed -E "s/^.*\(([0-9]+) .*$/\1/"` &&
DELTA=$((TEND-TSTART)) &&
echo -n "LINE: ${LINENO} " && echo "seconds passed:" $DELTA &&
test $DELTA -lt 70 && ## roughly a minute must have passed in this one leap


echo "################## TEST TEARDOWN" &&
echo -n "LINE: ${LINENO} " && ods_stop_enforcer &&

exit 0

echo "################## ERROR: CURRENT STATE" &&
echo "DEBUG: " && ods-enforcer key list -d -p
echo "DEBUG: " && ods-enforcer key list -v
echo "DEBUG: " && ods-enforcer queue

echo
echo "************error******************"
echo
ods_kill
return 1
