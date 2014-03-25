#!/usr/bin/env bash
#
#TEST: Test to check to check that the enforcer automatically generates keys correctly
#TEST: This test does mulitple runs of the enforcer with zones
#TEST: on different policies and checks it generates the right number
#TEST: of the right kind of key. Tries to test algorithm and length mixtures
#TEST: shared keys and standby

#DISABLED: ON SOLARIS T2000- as key generation takes too long!

ENFORCER_WAIT=90	# Seconds we wait for enforcer to run

add_zones() {
	for (( ZONE_COUNT=$1; ZONE_COUNT<=$2; ZONE_COUNT++ ))
	do
		sed s/ods./ods_$ZONE_COUNT./g unsigned/ods > unsigned/ods_$ZONE_COUNT &&
		log_this ods-zone-add_$3 ods-ksmutil zone add --zone ods_$ZONE_COUNT --policy Policy$3
	done 	
}

case "$DISTRIBUTION" in
	sunos )	
		if uname -m 2>/dev/null | $GREP -q -i sun4v 2>/dev/null; then
			return 0	
		fi
		;;			
esac

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

##################  Basic behaviour  ###########################
# Fail with no zones
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_waitfor $ENFORCER_WAIT 'ods-enforcerd: .*No zones on policy Policy1, skipping...' &&

# Generate keys with algorithm 7, length 2048
add_zones 1 1 1 && 
ods_start_enforcer_timeshift &&

syslog_grep_count 1  "ods-enforcerd: .*1 zone(s) found on policy \"Policy1\""  &&
syslog_grep_count 1  'ods-enforcerd: .*1 new KSK(s) (2048 bits) need to be created.'  &&
syslog_grep_count 1  'ods-enforcerd: .*5 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist   ods-hsmutil list &&
log_grep enforcer-keylist   stdout "6 keys found." && 

##################  1. Keys not shared, same alg & length ###########################
ods_setup_conf zonelist.xml zonelist.xml &&
ods_reset_env &&

# Generate keys on a policy where the keys have the same algorithm (7) and length (2048)
# Firstly for an empty queue
add_zones 2 4 2 && 
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1  "ods-enforcerd: .*3 zone(s) found on policy \"Policy2\""  &&
syslog_grep_count 1  'ods-enforcerd: .*6 new KSK(s) (2048 bits) need to be created.'  &&
syslog_grep_count 1  'ods-enforcerd: .*9 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_1   ods-hsmutil list &&
log_grep enforcer-keylist_1   stdout "15 keys found." && 

add_zones 5 10 2 && 
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1 "ods-enforcerd: .*9 zone(s) found on policy \"Policy2\""  &&
# 3 ZSKs have been made active so we need more keys than when we run the test from ods-ksmutil
syslog_grep_count 2  'ods-enforcerd: .*6 new KSK(s) (2048 bits) need to be created.'  &&
syslog_grep_count 1  'ods-enforcerd: .*27 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_1a   ods-hsmutil list &&
log_grep enforcer-keylist_1a   stdout "48 keys found." &&

##################
# Then when there are some keys in the queue: more than the number of KSK needed but less than the total
add_zones 11 17 2 && 
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1  "ods-enforcerd: .*16 zone(s) found on policy \"Policy2\""  &&
syslog_grep_count 1  'ods-enforcerd: .*No new KSKs need to be created.'  &&
# 6 more ZSKs have been made active so we need more keys than when we run the test from ods-ksmutil
syslog_grep_count 1  'ods-enforcerd: .*41 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_2   ods-hsmutil list &&
log_grep enforcer-keylist_2   stdout "89 keys found." &&

##################
# Then when there are more than enough keys in the queue
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 2  "ods-enforcerd: .*16 zone(s) found on policy \"Policy2\""  &&
syslog_grep_count 2  'ods-enforcerd: .*No new KSKs need to be created.'  &&
# 7 more ZSKs have been made active so we need more keys than when we run the test from ods-ksmutil
# Note we can't distinguish this from 27 new keys so let it count as 2 instances :-(
syslog_grep_count 2  'ods-enforcerd: .*7 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_2a   ods-hsmutil list &&
log_grep enforcer-keylist_2a   stdout "96 keys found." &&


##################  2. Keys not shared, diff alg & length ###########################
ods_setup_conf zonelist.xml zonelist.xml &&
ods_reset_env &&

# Generate keys where the algorithms/lengths are different - use algorithm 7/2048 and 8/2048 
# Firstly for an empty queue
add_zones 1 3 3 && 
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1  "ods-enforcerd: .*3 zone(s) found on policy \"Policy3\""  &&
syslog_grep_count 3  'ods-enforcerd: .*6 new KSK(s) (2048 bits) need to be created.'  &&
syslog_grep_count 2  'ods-enforcerd: .*9 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_3   ods-hsmutil list &&
log_grep enforcer-keylist_3   stdout "15 keys found." &&

##################
# Then when there are some keys in the queue
add_zones 4 12 3 && 
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1  "ods-enforcerd: .*12 zone(s) found on policy \"Policy3\""  &&
syslog_grep_count 1  'ods-enforcerd: .*18 new KSK(s) (2048 bits) need to be created.'  &&
# 3 more ZSKs have been made active so we need more keys than when we run the test from ods-ksmutil
syslog_grep_count 1  'ods-enforcerd: .*30 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_4   ods-hsmutil list &&
log_grep enforcer-keylist_4   stdout "63 keys found." &&
 

##################  3. Keys not shared, same alg & length. Standby enabled ###########################
ods_setup_conf zonelist.xml zonelist.xml &&
ods_reset_env &&

# Generate keys where standby also is enabled on alg 7, length 2048
add_zones 1 3 4 && 
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1  "ods-enforcerd: .*3 zone(s) found on policy \"Policy4\""  &&
syslog_grep_count 1  'ods-enforcerd: .*9 new KSK(s) (2048 bits) need to be created.'  &&
syslog_grep_count 3  'ods-enforcerd: .*9 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_5   ods-hsmutil list &&
log_grep enforcer-keylist_5   stdout "18 keys found." &&


##################  4. Keys not shared, same alg & length ###########################
ods_setup_conf zonelist.xml zonelist.xml &&
ods_reset_env &&

# Generate keys - now a policy with shared keys both with alg 7, length 2048
add_zones 1 15 5 && 
# Now a policy with shared keys one with alg 7, length 1024 and one with alg 8, length 2048
add_zones 16 30 6 && 
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1 "ods-enforcerd: .*15 zone(s) found on policy \"Policy5\""  &&
syslog_grep_count 1  "ods-enforcerd: .*15 zone(s) found on policy \"Policy6\""  &&
syslog_grep_count 1  'ods-enforcerd: .*2 new KSK(s) (2048 bits) need to be created.' &&
syslog_grep_count 1  'ods-enforcerd: .*2 new KSK(s) (1024 bits) need to be created.' &&
syslog_grep_count 2  'ods-enforcerd: .*2 new ZSK(s) (2048 bits) need to be created.'  &&
log_this enforcer-keylist_8   ods-hsmutil list &&
log_grep enforcer-keylist_8   stdout "8 keys found." &&

##################
# Now shorten the key lifetimes in the kasp
ods_setup_conf kasp.xml kasp_2.xml &&
log_this ods-ksmutil-update-kasp ods-ksmutil update kasp && 

# Again with some keys in the queue
ods_start_enforcer_timeshift 120 &&

syslog_grep_count 2  "ods-enforcerd: .*15 zone(s) found on policy \"Policy5\""  &&
syslog_grep_count 2  'ods-enforcerd: .*9 new KSK(s) (2048 bits) need to be created.'  &&
syslog_grep_count 1  'ods-enforcerd: .*21 new ZSK(s) (2048 bits) need to be created.' &&

syslog_grep_count 2  "ods-enforcerd: .*15 zone(s) found on policy \"Policy6\""  &&
syslog_grep_count 1  'ods-enforcerd: .*10 new KSK(s) (1024 bits) need to be created.'  &&
syslog_grep_count 1  'ods-enforcerd: .*20 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_9   ods-hsmutil list &&
log_grep enforcer-keylist_9   stdout "68 keys found." &&


echo && 
echo "************OK******************" &&
echo &&

return 0 

echo
echo "************ERROR******************"
echo
ods_kill
return 1

