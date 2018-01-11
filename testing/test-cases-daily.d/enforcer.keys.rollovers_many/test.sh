#!/usr/bin/env bash
#
#TEST: Tracks, in real time a KSK and a ZSK rollover
#runtime: about 5.5 minutes

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

echo "################## ZONE ADD ###########################" &&
echo -n "LINE: ${LINENO} " && log_this 00_zone_add ods-enforcer zone add --zone \
	ods --input $INSTALL_ROOT/var/opendnssec/unsigned/ods.xml --policy Policy1 --signerconf \
	$INSTALL_ROOT/var/opendnssec/signconf/ods.xml &&

echo "################## PROPAGATE ###########################" &&
echo -n "LINE: ${LINENO} " && ods_enforcer_leap_over 4 &&
echo -n "LINE: ${LINENO} " && KSK1_ID=`ods-enforcer key list -d -p | grep KSK |cut -d ";" -f 9` &&
echo -n "LINE: ${LINENO} " && ZSK1_ID=`ods-enforcer key list -d -p | grep ZSK |cut -d ";" -f 9` &&
echo -n "LINE: ${LINENO} " && test -n "$KSK1_ID" &&
echo -n "LINE: ${LINENO} " && test -n "$ZSK1_ID" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $KSK1_ID | grep publish &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $ZSK1_ID | grep ready &&

echo "################## DS-SUBMIT/DS-SEEN ###########################" &&
echo -n "LINE: ${LINENO} " && ods_enforcer_leap_over 4 &&

echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $KSK1_ID | grep ready &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $KSK1_ID | grep ds-submit &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $ZSK1_ID | grep active &&

echo -n "LINE: ${LINENO} " && ods-enforcer key ds-submit -z ods -k $KSK1_ID && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-seen -z ods -k $KSK1_ID &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $KSK1_ID | grep active &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $ZSK1_ID | grep active &&

echo "################## NEW ZSK ###########################" &&
echo -n "LINE: ${LINENO} " && ods_enforcer_leap_over 80 &&

echo -n "LINE: ${LINENO} " && ZSK2_ID=`ods-enforcer key list -d -p | grep ZSK |grep hidden |cut -d ";" -f 9` &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $ZSK1_ID | grep active &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $ZSK2_ID | grep publish &&

echo "################## ZSK RETIRE ###########################" &&
echo -n "LINE: ${LINENO} " && ods_enforcer_leap_over 35 &&

echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $ZSK1_ID | grep retire &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $ZSK2_ID | grep active &&

echo "################## NEW KSK ###########################" &&
echo -n "LINE: ${LINENO} " && ods_enforcer_leap_over 55 &&

echo -n "LINE: ${LINENO} " && KSK2_ID=`ods-enforcer key list -d -p | grep KSK |grep hidden |cut -d ";" -f 9` &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep "$KSK1_ID" | grep active &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep "$KSK2_ID" | grep publish &&

echo "################## KSK RETIRE ###########################" &&
echo -n "LINE: ${LINENO} " && ods_enforcer_leap_over 22 &&

echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $KSK1_ID | grep retire &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $KSK2_ID | grep ready &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $KSK1_ID | grep ds-retract &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $KSK2_ID | grep ds-submit &&

echo -n "LINE: ${LINENO} " && ods-enforcer key ds-submit -z ods -k $KSK2_ID && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-seen -z ods -k $KSK2_ID &&
## ds-gone fails on busy DB if ds-seen still running
echo -n "LINE: ${LINENO} " && ods_enforcer_leap_over 2 &&

echo -n "LINE: ${LINENO} " && ods-enforcer key ds-retract -z ods -k $KSK1_ID && sleep 3 &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-gone -z ods -k $KSK1_ID &&

echo "################## FINAL CHECK ###########################" &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $ZSK1_ID | grep retire &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $ZSK2_ID | grep active &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $KSK1_ID | grep retire &&
echo -n "LINE: ${LINENO} " && ods-enforcer key list -v | grep $KSK2_ID | grep active &&

echo -n "LINE: ${LINENO} " && ods_stop_enforcer &&

exit 0

echo "################## ERROR: CURRENT STATE ###########################"
echo "DEBUG: " && date
echo "DEBUG: " && ods-enforcer key list -d -p
echo "DEBUG: " && ods-enforcer key list -v
echo "DEBUG: " && ods-enforcer queue

echo
echo "************error******************"
echo
ods_kill
return 1

