#!/usr/bin/env bash
#
#TEST: Test the end to end workflow for adding and deleting zones works
#TEST: and that the right zones get signed

#TODO: Re-examine the deletion path and this should not require an enforce??

ZONES_FILE=$INSTALL_ROOT/var/opendnssec/enforcer/zones.xml
ZONELIST_FILE=$INSTALL_ROOT/etc/opendnssec/zonelist.xml

# Cater for the fact that solaris and openbsd use different flags in diff
local ignore_blank_lines=" -B "
case "$DISTRIBUTION" in
	sunos | \
	openbsd )
		ignore_blank_lines="-b"
		;;
esac


if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&


ods_reset_env &&


##################  TEST:  Zone add success ###########################
#0. Test all default
ods-enforcer start &&
log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods0 &&
ods_enforcer_idle &&
log_grep ods-enforcer-zone_add stdout "Zone ods0 added successfully" &&

ods-enforcer stop &&
sleep 5 &&
ods-enforcer start &&
log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods1 &&
ods_enforcer_idle &&
log_grep ods-enforcer-zone_add stdout "Zone ods1 added successfully" &&
sleep 30 &&
ods-enforcer stop &&
sleep 5 &&
ods-enforcer start &&
log_this ods-enforcer-zone_del   ods-enforcer zone delete --zone ods1 &&
sleep 30 && ods_enforcer_idle &&
log_grep ods-enforcer-zone_del   stdout "Deleted zone.*ods1" &&

sleep 3 &&

ods-enforcer stop &&
sleep 5 &&


echo && 
echo "************OK******************" &&
echo &&
return 0


echo "################## ERROR: CURRENT STATE ###########################"
echo "DEBUG: " && ods-enforcer zone list
echo "DEBUG: " && ods-enforcer key list -d -p
echo "DEBUG: " && ods-enforcer key list -v
echo "DEBUG: " && ods-enforcer queue
echo "stderr: "
cat _log.$BUILD_TAG.ods-enforcer-zone_del.stderr
echo "stdout: "
cat _log.$BUILD_TAG.ods-enforcer-zone_del.stdout
echo "************ERROR******************"
echo
ods_kill
return 1



