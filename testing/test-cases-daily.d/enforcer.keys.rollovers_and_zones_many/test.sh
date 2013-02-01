#!/usr/bin/env bash
#
#TEST: Test to track key rollovers when the enforcer is configured to be multi-threaded
#TEST: in real time from the enforcer side only. 
#TEST: Configured with very short key lifetimes and 1 min enforcer interval.
#TEST: Checks just the signconf.xml contents and a that the zone is signed
#TEST: Takes about 10 mins and follows several KSK and ZKK rollovers.

#TODO: - check more logging in syslog
#TODO: - fix the compare script to directly compare the key ids in the signconf

# Lets use parameters for the timing intervals so they are easy to change
SHORT_TIMEOUT=11    # Timeout when checking log output. DS lock out wait is 10 sec so use 11 for this
LONG_TIMEOUT=20     # Timeout when waiting for enforcer run to have happened
SLEEP_INTERVAL=50   # This should be just shorter than the enforcer run interval in conf.xml

compare_files_ignore_locator () {

        if [ -z "$1" -o -z "$2" ]; then
                echo "usage: compare_files_ignore_locator <file1> <file2> " >&2
                exit 1
        fi

        local file1="$1"
        local file2="$2"
        local file1_tmp="tmp/file1.tmp"
        local file2_tmp="tmp/file2.tmp"

        sed 's#<Locator>.*#<Locator></Locator>#g' $file1 > $file1_tmp
        sed 's#<Locator>.*#<Locator></Locator>#g' $file2 > $file2_tmp
        diff $file1_tmp $file2_tmp
}

check_zone_X_at_timestep_Y () {
	
	 local signing_count=$(( $2 + 1 ))
	
	 #cp $INSTALL_ROOT/var/opendnssec/signconf/ods$1.xml gold/ods_signconf_ods$1_$2.xml &&  	
	 log_this ods-ksmutil-check-$2   compare_files_ignore_locator  $INSTALL_ROOT/var/opendnssec/signconf/ods$1.xml gold/ods_signconf_ods$1_$2.xml &&	
	 syslog_waitfor_count $LONG_TIMEOUT $signing_count "ods-signerd: .*\[STATS\] ods$1" &&
	 test -f "$INSTALL_ROOT/var/opendnssec/signed/ods$1" &&
	 return 0
	
	 return 1
	
}

check_zones_at_timestep_Y () {
	
	# Start signer for a single run
	log_this_timeout ods-control-signer-start $SHORT_TIMEOUT  ods-signerd -1 &&
	syslog_waitfor $SHORT_TIMEOUT  'ods-signerd: .*\[engine\] signer shutdown' &&	
	
	for no in 1 2 3 4; do
		if ! check_zone_X_at_timestep_Y $no $1; then 
			return 1
		fi
	done	
	
	return 0
		
}


if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
else
	return 0
fi &&

ods_reset_env &&

rm -rf tmp &&
mkdir  tmp &&

# Used only to create a gold while setting up the test
#rm -rf gold && mkdir gold &&

##################  SETUP ###########################
# Generate keys
echo "y" | log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil key generate --interval PT10M --policy  default &&
echo "y" | log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil key generate --interval PT10M --policy  default2 &&
echo "y" | log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil key generate --interval PT10M --policy  shared &&

# Start enforcer
log_this_timeout ods-enforcer-start $SHORT_TIMEOUT   ods-control enforcer start &&
syslog_waitfor $SHORT_TIMEOUT 'ods-enforcerd: .*Sleeping for' &&
##################  STEP 0: Time = 0 ###########################
# Check the output
log_this ods-ksmutil-check-0   date && log_this ods-ksmutil-check-0   ods-ksmutil key list --all --verbose &&
KSK_ODS1_1=`log_grep -o ods-ksmutil-check-0 stdout "ods1.*KSK           publish" | awk '{print $6}'` &&
KSK_ODS2_1=`log_grep -o ods-ksmutil-check-0 stdout "ods2.*KSK           publish" | awk '{print $6}'` &&
KSK_ODS3_1=`log_grep -o ods-ksmutil-check-0 stdout "ods3.*KSK           publish" | awk '{print $6}'` &&
KSK_ODS4_1=`log_grep -o ods-ksmutil-check-0 stdout "ods4.*KSK           publish" | awk '{print $6}'` &&
check_zones_at_timestep_Y 0 &&

# Wait for the enforcer to run again
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 2 'ods-enforcerd: .*Sleeping for' &&
##################  STEP 1: Time ~ 1 x enforcer interval ###########################
check_zones_at_timestep_Y 1 &&

# Issue ds_seen for KSK1. This will cause the enforcer to run.
log_this ods-ksmutil-dsseen_1   ods-ksmutil key ds-seen --zone ods1 --cka_id $KSK_ODS1_1 &&
log_this ods-ksmutil-dsseen_1   ods-ksmutil key ds-seen --zone ods2 --cka_id $KSK_ODS2_1 &&
log_this ods-ksmutil-dsseen_1   ods-ksmutil key ds-seen --zone ods3 --cka_id $KSK_ODS3_1 &&
log_this ods-ksmutil-dsseen_1   ods-ksmutil key ds-seen --zone ods4 --cka_id $KSK_ODS4_1 &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS1_1 made active" &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS2_1 made active" &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS3_1 made active" &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS4_1 made active" &&

syslog_waitfor_count $LONG_TIMEOUT 3 'ods-enforcerd: .*Sleeping for' &&

# WAIT for the enforcer to run
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 4 'ods-enforcerd: .*Sleeping for' &&
##################  STEP 2 ###########################
check_zones_at_timestep_Y 2 &&

# Wait for the enforcer to run
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 5 'ods-enforcerd: .*Sleeping for' &&
# ##################  STEP 3 ###########################
check_zones_at_timestep_Y 3 &&

# Wait for the enforcer to run
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 6 'ods-enforcerd: .*Sleeping for' &&
# ##################  STEP 4 ###########################
# Expect a new KSK to be published
log_this ods-ksmutil-check-4   date && log_this ods-ksmutil-check-4   ods-ksmutil key list --all --verbose &&
KSK_ODS1_2=`log_grep -o ods-ksmutil-check-4 stdout "ods1.*KSK           publish" | awk '{print $6}'` &&
KSK_ODS2_2=`log_grep -o ods-ksmutil-check-4 stdout "ods2.*KSK           publish" | awk '{print $6}'` &&
KSK_ODS3_2=`log_grep -o ods-ksmutil-check-4 stdout "ods3.*KSK           publish" | awk '{print $6}'` &&
KSK_ODS4_2=`log_grep -o ods-ksmutil-check-4 stdout "ods4.*KSK           publish" | awk '{print $6}'` &&

check_zones_at_timestep_Y 4 &&

# Wait for the enforcer to run.
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 7 'ods-enforcerd: .*Sleeping for' &&
# ##################  STEP 5 ###########################
check_zones_at_timestep_Y 5 &&

# Issue ds_seen for KSK2
log_this ods-ksmutil-dsseen_2   ods-ksmutil key ds-seen --zone ods1 --cka_id $KSK_ODS1_2 &&
log_this ods-ksmutil-dsseen_2   ods-ksmutil key ds-seen --zone ods2 --cka_id $KSK_ODS2_2 &&
log_this ods-ksmutil-dsseen_2   ods-ksmutil key ds-seen --zone ods3 --cka_id $KSK_ODS3_2 &&
log_this ods-ksmutil-dsseen_2   ods-ksmutil key ds-seen --zone ods4 --cka_id $KSK_ODS4_2 &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS1_2 made active" &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS2_2 made active" &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS3_2 made active" &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS4_2 made active" &&
syslog_waitfor_count $LONG_TIMEOUT 8 'ods-enforcerd: .*Sleeping for' &&

# Wait for the enforcer to run.
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 9 'ods-enforcerd: .*Sleeping for' &&
# ##################  STEP 6 ###########################
check_zones_at_timestep_Y 6 &&
 
# ##################  SHUTDOWN ###########################
log_this_timeout ods-enforcer-stop 60 ods-control enforcer stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&

rm -rf tmp &&

return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1

