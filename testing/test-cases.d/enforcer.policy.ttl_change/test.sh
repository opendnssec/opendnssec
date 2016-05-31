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
#runtime: about 11 seconds 

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env -i &&
ods_start_enforcer &&

echo "################## ZONE ADD 1 ###########################" &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add --zone ods1 &&

echo "################## LEAP TO OMNIPRESENT ZSK DNSKEY ###########################" &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&

echo "################## LOWER TTL AND RESTART ###########################" &&
ods_stop_enforcer &&
echo -n "LINE: ${LINENO} " && cp kasp-short-ttl.xml  "$INSTALL_ROOT/etc/opendnssec/kasp.xml" &&
ods_start_enforcer &&
echo -n "LINE: ${LINENO} " && ods-enforcer policy import &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&

echo "################## START ZSK ROLL ##########################" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key rollover -t ZSK -z ods1 &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&

echo "################## RECORD T_0 #########################" &&
echo -n "LINE: ${LINENO} " && T0=`ods-enforcer queue | grep "It is now" | 
	sed -r "s/^.*\(([0-9]+) .*$/\1/"` &&

echo "################## LEAP TO OMNIPRESENT ########################" &&
echo -n "LINE: ${LINENO} " && ods-enforcer time leap --attach &&

echo "################## MUST HAVE 2 OMNIPRESENT ZSKS ######################" &&
COUNT=`ods-enforcer key list -d -p |grep ZSK|cut -f 4 -d ";" |grep -c omnipresent` &&
[ $COUNT -eq 2 ] &&

echo "################## RECORD T_1 #########################" &&
echo -n "LINE: ${LINENO} " && T1=`ods-enforcer queue | grep "It is now" | 
	sed -r "s/^.*\(([0-9]+) .*$/\1/"` &&

echo "################## DID ENOUGH TIME PASS? ########################" &&
###############################################################################
## NOTICE: we would expect roughly an hour + a minute here. (Old TTL + margins)
## If we would botch it up we expect a minute + a minute. (New TTL + margin)
## However somehow in reality we see an hour + an hour + a minute (2x old TTL
## + margin). Likely this is some sort of side effect of time leap or 
## inconsistent handling of timestamps wrt timezones. This test is written
## so it will still succeed if we once fix that bug. (i.e. anything more than
## an hour is okay)
###############################################################################
echo "T1 - T0 = $T1 - $T0 = $((T1 - T0))" &&
[ $((T1 - T0)) -gt 3600 ] &&

echo "################## TEST TEARDOWN ###########################" &&
echo -n "LINE: ${LINENO} " && ods_stop_enforcer &&

exit 0

echo "################## ERROR: CURRENT STATE ###########################"
echo "DEBUG: " && ods-enforcer key list -d -p
echo "DEBUG: " && ods-enforcer key list -v
echo "DEBUG: " && ods-enforcer queue

echo
echo "************error******************"
echo
ods_kill
return 1

