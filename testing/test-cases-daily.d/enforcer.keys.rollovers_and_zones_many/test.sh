#!/usr/bin/env bash
#
#TEST: Test to track key rollovers when many zones are configured on many policies
#TEST: in real time. 
#TEST: Configured with very short key lifetimes and 1 min enforcer interval.
#TEST: Checks just the signconf.xml contents and a that the zone is signed
#TEST: Takes about 10 mins and follows several KSK and ZKK rollovers.

#DISABLED: ON SQLITE (database locking causes problems)
#DISABLED: ON OPENBSD (last signing fails....)

#TODO: - check more logging in syslog

# Lets use parameters for the timing intervals so they are easy to change
SHORT_TIMEOUT=11    # Timeout when checking log output. DS lock out wait is 10 sec so use 11 for this
LONG_TIMEOUT=20     # Timeout when waiting for enforcer run to have happened
SLEEP_INTERVAL=50   # This should be just shorter than the enforcer run interval in conf.xml

check_zone_X_at_timestep_Y () {
	
	 local signing_count=$(( $2 + 1 ))
	
         # Used only to create a gold while setting up the test
	 #cp $INSTALL_ROOT/var/opendnssec/signconf/ods$1.xml gold/ods_signconf_ods$1_$2.xml &&  	
         
         cp $INSTALL_ROOT/var/opendnssec/signconf/ods$1.xml base/ods_signconf_ods$1_$2.xml &&
	 syslog_waitfor_count $LONG_TIMEOUT $signing_count "ods-signerd: .*\[STATS\] ods$1" &&
         test -f "$INSTALL_ROOT/var/opendnssec/signed/ods$1" 
	
}


check_zones_at_timestep_Y () {
	
	# Start signer for a single run
	log_this_timeout ods-control-signer-start $SHORT_TIMEOUT  ods-signerd -1 &&
	syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&	
	
	for no in 1 2 3 4; do
		if ! check_zone_X_at_timestep_Y $no $1; then 
			return 1
		fi
	done	
	
}

case "$DISTRIBUTION" in
	openbsd )
		return 0
		;;
esac


if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
else
	return 0
fi &&

ods_reset_env &&

rm -rf base &&
mkdir  base &&

# Used only to create a gold while setting up the test
#rm -rf gold && mkdir gold &&

##################  SETUP ###########################
# Generate keys
echo "y" | log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil key generate --interval PT10M --policy  default &&
echo "y" | log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil key generate --interval PT10M --policy  default2 &&
echo "y" | log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil key generate --interval PT10M --policy  shared &&

# Start enforcer
ods_start_enforcer && 
##################  STEP 0: Time = 0 ###########################
# Check the output
log_this ods-ksmutil-check-0   date && log_this ods-ksmutil-check-0   ods-ksmutil key list --all --verbose &&
KSK_ODS1_1=`log_grep -o ods-ksmutil-check-0 stdout "ods1.*KSK           publish" | awk '{print $9}'` &&
KSK_ODS2_1=`log_grep -o ods-ksmutil-check-0 stdout "ods2.*KSK           publish" | awk '{print $9}'` &&
KSK_ODS3_1=`log_grep -o ods-ksmutil-check-0 stdout "ods3.*KSK           publish" | awk '{print $9}'` &&
KSK_ODS4_1=`log_grep -o ods-ksmutil-check-0 stdout "ods4.*KSK           publish" | awk '{print $9}'` &&
check_zones_at_timestep_Y 0 &&

# Wait for the enforcer to run again
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 2 'ods-enforcerd: .*Sleeping for' &&
##################  STEP 1: Time ~ 1 x enforcer interval ###########################
check_zones_at_timestep_Y 1 &&

# Issue ds_seen for KSK1. This will cause the enforcer to run.
log_this ods-ksmutil-dsseen_1   ods-ksmutil key ds-seen --zone ods1 --cka_id $KSK_ODS1_1 &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS1_1 made active" &&
syslog_waitfor_count $LONG_TIMEOUT 3 'ods-enforcerd: .*Sleeping for' &&
log_this ods-ksmutil-dsseen_1   ods-ksmutil key ds-seen --zone ods2 --cka_id $KSK_ODS2_1 &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS2_1 made active" &&
syslog_waitfor_count $LONG_TIMEOUT 4 'ods-enforcerd: .*Sleeping for' &&
log_this ods-ksmutil-dsseen_1   ods-ksmutil key ds-seen --zone ods3 --cka_id $KSK_ODS3_1 &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS3_1 made active" &&
syslog_waitfor_count $LONG_TIMEOUT 5 'ods-enforcerd: .*Sleeping for' &&
log_this ods-ksmutil-dsseen_1   ods-ksmutil key ds-seen --zone ods4 --cka_id $KSK_ODS4_1 &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS4_1 made active" &&
syslog_waitfor_count $LONG_TIMEOUT 6 'ods-enforcerd: .*Sleeping for' &&

# WAIT for the enforcer to run
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 7 'ods-enforcerd: .*Sleeping for' &&
##################  STEP 2 ###########################
check_zones_at_timestep_Y 2 &&

# Wait for the enforcer to run
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 8 'ods-enforcerd: .*Sleeping for' &&
# ##################  STEP 3 ###########################
check_zones_at_timestep_Y 3 &&

# Wait for the enforcer to run
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 9 'ods-enforcerd: .*Sleeping for' &&
# ##################  STEP 4 ###########################
# Expect a new KSK to be published
log_this ods-ksmutil-check-4   date && log_this ods-ksmutil-check-4   ods-ksmutil key list --all --verbose &&
KSK_ODS1_2=`log_grep -o ods-ksmutil-check-4 stdout "ods1.*KSK           publish" | awk '{print $9}'` &&
KSK_ODS2_2=`log_grep -o ods-ksmutil-check-4 stdout "ods2.*KSK           publish" | awk '{print $9}'` &&
KSK_ODS3_2=`log_grep -o ods-ksmutil-check-4 stdout "ods3.*KSK           publish" | awk '{print $9}'` &&
KSK_ODS4_2=`log_grep -o ods-ksmutil-check-4 stdout "ods4.*KSK           publish" | awk '{print $9}'` &&

check_zones_at_timestep_Y 4 &&

# Wait for the enforcer to run.
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 10 'ods-enforcerd: .*Sleeping for' &&
# ##################  STEP 5 ###########################
check_zones_at_timestep_Y 5 &&

# Issue ds_seen for KSK2
log_this ods-ksmutil-dsseen_2   ods-ksmutil key ds-seen --zone ods1 --cka_id $KSK_ODS1_2 &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS1_2 made active" &&
syslog_waitfor_count $LONG_TIMEOUT 11 'ods-enforcerd: .*Sleeping for' &&
log_this ods-ksmutil-dsseen_2   ods-ksmutil key ds-seen --zone ods2 --cka_id $KSK_ODS2_2 &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS2_2 made active" &&
syslog_waitfor_count $LONG_TIMEOUT 12 'ods-enforcerd: .*Sleeping for' &&
log_this ods-ksmutil-dsseen_2   ods-ksmutil key ds-seen --zone ods3 --cka_id $KSK_ODS3_2 &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS3_2 made active" &&
syslog_waitfor_count $LONG_TIMEOUT 13 'ods-enforcerd: .*Sleeping for' &&
log_this ods-ksmutil-dsseen_2   ods-ksmutil key ds-seen --zone ods4 --cka_id $KSK_ODS4_2 &&
syslog_waitfor $SHORT_TIMEOUT   "ods-ksmutil: .*Key $KSK_ODS4_2 made active" &&
syslog_waitfor_count $LONG_TIMEOUT 14 'ods-enforcerd: .*Sleeping for' &&

# Wait for the enforcer to run.
sleep $SLEEP_INTERVAL && syslog_waitfor_count $LONG_TIMEOUT 15 'ods-enforcerd: .*Sleeping for' &&
# ##################  STEP 6 ###########################
# just check the state of the KSKs here as the ZSK rollover is too hard to predict in real time
log_this ods-ksmutil-check-6   date && log_this ods-ksmutil-check-6   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-check-6   stdout "KSK           retire.*$KSK_ODS1_1" &&
log_grep ods-ksmutil-check-6   stdout "KSK           active.*$KSK_ODS1_2" &&
log_grep ods-ksmutil-check-6   stdout "KSK           retire.*$KSK_ODS2_1" &&
log_grep ods-ksmutil-check-6   stdout "KSK           active.*$KSK_ODS2_2" &&
log_grep ods-ksmutil-check-6   stdout "KSK           retire.*$KSK_ODS3_1" &&
log_grep ods-ksmutil-check-6   stdout "KSK           active.*$KSK_ODS3_2" &&
log_grep ods-ksmutil-check-6   stdout "KSK           retire.*$KSK_ODS4_1" &&
log_grep ods-ksmutil-check-6   stdout "KSK           active.*$KSK_ODS4_2" &&
 
# ##################  SHUTDOWN ###########################
ods_stop_enforcer &&

log_this ods-compare-signconfs  ods_compare_gold_vs_base_signconf &&

rm -rf base &&
echo "************OK******************" &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1


