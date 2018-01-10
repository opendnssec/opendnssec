#!/usr/bin/env bash
#
#TEST: Test if two zones share keys and key material not reused within a zone
#runtime: about 10 seconds 

visual_sleep()
{
	echo -n "sleeping for $1 seconds" &&
	local L=$1 &&
	while [ $L -gt 10 ]; do
		sleep 10 &&
		L=$((L-10)) &&
		echo -n "...$L"
	done &&
	sleep $L &&
	echo
}

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env -n &&

echo "################## ZONE ADD 1 ###########################" &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add --zone ods1 &&
echo -n "LINE: ${LINENO} " && visual_sleep 2 &&
echo "################## ZONE ADD 2 ###########################" &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add --zone ods2 &&

echo "################## ROLL KSK ###########################" &&
echo -n "LINE: ${LINENO} " && ods_enforcer_idle &&
echo -n "LINE: ${LINENO} " && ods-enforcer key rollover -z ods2 -t KSK &&

echo "################## CHECK ###########################" &&
echo -n "LINE: ${LINENO} " && ods_enforcer_idle &&

echo -n "LINE: ${LINENO} " && KSK1=`ods-enforcer key list -d -p | grep ods1 | grep KSK |cut -d ";" -f 9` &&
echo -n "LINE: ${LINENO} " && ZSK1=`ods-enforcer key list -d -p | grep ods1 | grep ZSK |cut -d ";" -f 9` &&
echo -n "LINE: ${LINENO} " && KSK2=`ods-enforcer key list -d -p | grep ods2 | grep KSK | grep ";0;0;" | cut -d ";" -f 9` &&
echo -n "LINE: ${LINENO} " && ZSK2=`ods-enforcer key list -d -p | grep ods2 | grep ZSK |cut -d ";" -f 9` &&
echo -n "LINE: ${LINENO} " && KSK3=`ods-enforcer key list -d -p | grep ods2 | grep KSK | grep ";1;1;" | cut -d ";" -f 9` &&

echo -n "LINE: ${LINENO} KSK1 set?" && test -n "$KSK1" && echo "...OK" &&
echo -n "LINE: ${LINENO} ZSK1 set?" && test -n "$ZSK1" && echo "...OK" &&
echo -n "LINE: ${LINENO} KSK2 set?" && test -n "$KSK2" && echo "...OK" &&
echo -n "LINE: ${LINENO} ZSK2 set?" && test -n "$ZSK2" && echo "...OK" &&
echo -n "LINE: ${LINENO} KSK3 set?" && test -n "$KSK3" && echo "...OK" &&

echo -n "LINE: ${LINENO} Both zones should use same KSK" && test "$KSK1"  = "$KSK2" && echo "...OK" &&
echo -n "LINE: ${LINENO} New KSK should be different" && test "$KSK2" != "$KSK3" && echo "...OK" &&
echo -n "LINE: ${LINENO} Both zones should use same ZSK" && test "$ZSK1"  = "$ZSK2" && echo "...OK" &&
echo -n "LINE: ${LINENO} KSKs and ZSKs may not use same material" && test "$KSK1" != "$ZSK1" && echo "...OK" &&
echo -n "LINE: ${LINENO} New KSK may not use same material as ZSKs" && test "$KSK3" != "$ZSK1" && echo "...OK" &&

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

