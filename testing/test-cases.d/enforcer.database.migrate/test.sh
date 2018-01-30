#!/usr/bin/env bash
#
#TEST: 
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

## This is a hack to get access to the migrate scripts which are in the source
## but not part of the build. I want to avoid copying (and keeping up to date!)
## these files to the test directory.
cd_to_src()
{
	cd ../../.. &&
	cd `pwd | sed "s/test/build/"`/enforcer/utils/
}

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env -n &&

echo "################## ZONE ADD 1 ###########################" &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add --zone ods1 &&
echo -n "LINE: ${LINENO} " && ods_waitfor_keys &&

echo "################## ZONE ADD 2 ###########################" &&
echo -n "LINE: ${LINENO} " && ods-enforcer zone add --zone ods2 &&

echo "################## ROLL KSK ###########################" &&
echo -n "LINE: ${LINENO} " && ods_enforcer_idle &&
echo -n "LINE: ${LINENO} " && ods_waitfor_keys &&
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

echo "################## STOP AND CONVERT ###########################" &&
echo -n "LINE: ${LINENO} " && ods_stop_enforcer &&

if [ -n "$HAVE_MYSQL" ]; then
	echo -n "LINE: ${LINENO} " && (cd_to_src && ./convert_mysql_to_sqlite -o $INSTALL_ROOT/var/opendnssec/kasp.db -i test) &&
	echo -n "LINE: ${LINENO} " && echo "DROP DATABASE test;" | mysql -u test -ptest -h localhost &&
	echo -n "LINE: ${LINENO} " && (cd_to_src && ./convert_sqlite_to_mysql -i $INSTALL_ROOT/var/opendnssec/kasp.db -o test)
else
	echo -n "LINE: ${LINENO} " && (cd_to_src && ./convert_sqlite_to_mysql -p test -u test -i $INSTALL_ROOT/var/opendnssec/kasp.db -o test ) &&
	echo -n "LINE: ${LINENO} " && rm $INSTALL_ROOT/var/opendnssec/kasp.db &&
	echo -n "LINE: ${LINENO} " && (cd_to_src && ./convert_mysql_to_sqlite -p test -u test -o $INSTALL_ROOT/var/opendnssec/kasp.db -i test )
fi &&

echo -n "LINE: ${LINENO} " && ods-migrate &&

echo -n "LINE: ${LINENO} " && ods-enforcerd --set-time "2001-01-01-01:01:01:01" &&
echo -n "LINE: ${LINENO} " && unset KSK1 &&
echo -n "LINE: ${LINENO} " && unset ZSK1 &&
echo -n "LINE: ${LINENO} " && unset KSK2 &&
echo -n "LINE: ${LINENO} " && unset ZSK2 &&
echo -n "LINE: ${LINENO} " && unset KSK3 &&

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

echo "################## STOP ###########################" &&
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

