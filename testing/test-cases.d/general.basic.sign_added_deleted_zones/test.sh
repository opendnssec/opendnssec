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
ods_start_ods-control &&

# Start with an empty zonelist 
log_this ods-enforcer-zone_none   ods-enforcer zone list &&
log_grep ods-enforcer-zone_none   stdout "No zones in database." &&


##################  TEST:  Zone add success ###########################
#0. Test all default
ods_enforcer_idle &&
log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods0 &&
#log_grep ods-enforcer-zone_add   stdout "Imported zone:.*ods0 into database only. Use the --xml flag or run \"ods-enforcer zonelist export\" if an update of zonelist.xml is required." &&
ods_enforcer_idle &&
log_grep ods-enforcer-zone_add stdout "Zone ods0 added successfully" &&

log_this ods-enforcer-zone_add_list   ods-enforcer zone list &&
log_grep ods-enforcer-zone_add_list   stdout "ods0[[:space:]]*default" &&

#syslog_waitfor 5 "update zone: ods0" &&
syslog_waitfor 25 'ods-signerd: .*\[STATS\] ods0' &&

log_this ods-enforcer-zone_add   ods-enforcer zone add --zone ods1 &&
ods_enforcer_idle &&
#log_grep ods-enforcer-zone_add   stdout "Imported zone:.*ods1 into database only. Use the --xml flag or run \"ods-enforcer zonelist export\" if an update of zonelist.xml is required." &&
log_grep ods-enforcer-zone_add stdout "Zone ods1 added successfully" &&

log_this ods-enforcer-zone_add_list   ods-enforcer zone list &&
log_grep ods-enforcer-zone_add_list   stdout "ods1[[:space:]]*default" &&

syslog_waitfor 5 "update zone: ods1" &&
syslog_waitfor 20 'ods-signerd: .*\[STATS\] ods1' &&

ods_enforcer_idle &&
log_this ods-enforcer-zone_add   ods-enforcer zone delete --zone ods1 &&
sleep 5 && ods_enforcer_idle &&
log_grep ods-enforcer-zone_add   stdout "Deleted zone.*ods1" &&

syslog_waitfor 180 "zone ods1 deleted" &&

log_this ods-signer-sign-all ods-signer update --all &&
log_this ods-signer-sign-all ods-signer sign --all &&

#syslog_waitfor_count 5 1 "update zone: ods0" &&
syslog_waitfor_count 60 2 'ods-signerd: .*\[STATS\] ods0' &&
#syslog_grep_count 1 "update zone: ods1" &&
syslog_grep_count 1 'ods-signerd: .*\[STATS\] ods1' &&

ods_stop_ods-control &&

echo && 
echo "************OK******************" &&
echo &&
return 0


echo "################## ERROR: CURRENT STATE ###########################"
echo "DEBUG: " && ods-enforcer zone list
echo "DEBUG: " && ods-enforcer key list -d -p
echo "DEBUG: " && ods-enforcer key list -v
echo "DEBUG: " && ods-enforcer queue

echo "************ERROR******************"
echo
ods_kill
return 1



