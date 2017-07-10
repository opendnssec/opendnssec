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

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env -i &&
ods_start_enforcer &&

echo "################## ZONE ADD 1" &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add --zone ods1 &&
echo -n "LINE: ${LINENO} " && ods_enforcer_idle &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone list &&

echo "################## LEAP TO OMNIPRESENT ZSK DNSKEY" &&
echo -n "LINE: ${LINENO} " && ods_enforcer_leap_over 3600 &&

echo "################## LOWER TTL AND RESTART" &&
echo -n "LINE: ${LINENO} " && cp kasp-short-ttl.xml  "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
echo -n "LINE: ${LINENO} " && ods-enforcer policy import &&
echo -n "LINE: ${LINENO} " && ods_enforcer_idle &&

echo "################## START ZSK ROLL" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key rollover -t ZSK -z ods1 &&

echo "################## TESTING 2ND ZSK IS NOT ACTIVE FOR ENOUGH TIME" &&
echo -n "LINE: ${LINENO} " && ods_enforcer_leap_to 60 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -d -p | grep ZSK &&
echo -n "LINE: ${LINENO} " && COUNT=`ods-enforcer key list -d -p |grep ZSK|cut -f 4 -d ";" |grep -c omnipresent` &&
echo -n "LINE: ${LINENO} " && [ $COUNT -eq 1 ] &&
TSTART=`ods-enforcer queue|grep "It is now"|sed -E "s/^.*\(([0-9]+) .*$/\1/"` &&

echo "################## BUT A MOMENT LATER IT IS" &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap &&
echo -n "LINE: ${LINENO} " && ods_enforcer_idle &&
echo -n "LINE: ${LINENO} " && COUNT=`ods-enforcer key list -d -p |grep ZSK|cut -f 4 -d ";" |grep -c omnipresent` &&
echo -n "LINE: ${LINENO} " && [ $COUNT -eq 2 ] &&
TEND=`ods-enforcer queue|grep "It is now"|sed -E "s/^.*\(([0-9]+) .*$/\1/"` &&
DELTA=$((TEND-TSTART)) &&
echo -n "LINE: ${LINENO} " && echo $DELTA &&
test $DELTA -gt 3500 && ## roughly an hour must have passed in this one leap

###############################################################################
## NOTICE: we would expect roughly an hour + a minute here. (Old TTL + margins)
## If we would botch it up we expect a minute + a minute. (New TTL + margin)
## However somehow in reality we see an hour + an hour + a minute (2x old TTL
## + margin). Likely this is some sort of side effect of time leap or 
## inconsistent handling of timestamps wrt timezones. This test is written
## so it will still succeed if we once fix that bug. (i.e. anything more than
## an hour is okay)
###############################################################################

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

