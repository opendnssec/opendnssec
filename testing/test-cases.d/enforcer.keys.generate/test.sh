#!/usr/bin/env bash
#
#TEST: Test to check to check that the enforcer automatically generates keys correctly
#TEST: This test does mulitple runs of the enforcer with zones
#TEST: on different policies and checks it generates the right number
#TEST: of the right kind of key. Tries to test algorithm and length mixtures
#TEST: shared keys and standby

#DISABLED: ON SOLARIS T2000- as key generation takes too long!

ENFORCER_WAIT=90	# Seconds we wait for enforcer to run

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
log_this ods-zone-add-1 ods-ksmutil zone add --zone ods1 --policy Policy1 &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1  "ods-enforcerd: 1 zone(s) found on policy \"Policy1\""  &&
syslog_grep_count 1  'ods-enforcerd: 1 new KSK(s) (2048 bits) need to be created.'  &&
syslog_grep_count 1  'ods-enforcerd: 5 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist   ods-hsmutil list &&
log_grep enforcer-keylist   stdout "6 keys found." && 

##################  1. Keys not shared, same alg & length ###########################
ods_setup_conf zonelist.xml zonelist.xml &&
ods_reset_env &&

# Generate keys on a policy where the keys have the same algorithm (7) and length (2048)
# Firstly for an empty queue
log_this ods-zone-add-2 ods-ksmutil zone add --zone ods2 --policy Policy2 &&
log_this ods-zone-add-3 ods-ksmutil zone add --zone ods3 --policy Policy2 &&
log_this ods-zone-add-4 ods-ksmutil zone add --zone ods4 --policy Policy2 &&
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1  "ods-enforcerd: 3 zone(s) found on policy \"Policy2\""  &&
syslog_grep_count 1  'ods-enforcerd: 6 new KSK(s) (2048 bits) need to be created.'  &&
syslog_grep_count 1  'ods-enforcerd: 9 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_1   ods-hsmutil list &&
log_grep enforcer-keylist_1   stdout "15 keys found." && 

log_this ods-zone-add-5 ods-ksmutil zone add --zone ods5 --policy Policy2 &&
log_this ods-zone-add-6 ods-ksmutil zone add --zone ods6 --policy Policy2 &&
log_this ods-zone-add-7 ods-ksmutil zone add --zone ods7 --policy Policy2 &&
log_this ods-zone-add-8 ods-ksmutil zone add --zone ods8 --policy Policy2 &&
log_this ods-zone-add-9 ods-ksmutil zone add --zone ods9 --policy Policy2 &&
log_this ods-zone-add-10 ods-ksmutil zone add --zone ods10 --policy Policy2 &&
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1 "ods-enforcerd: 9 zone(s) found on policy \"Policy2\""  &&
# 3 ZSKs have been made active so we need more keys than when we run the test from ods-ksmutil
syslog_grep_count 1  'ods-enforcerd: 12 new KSK(s) (2048 bits) need to be created.'  &&
syslog_grep_count 1  'ods-enforcerd: 21 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_1a   ods-hsmutil list &&
log_grep enforcer-keylist_1a   stdout "48 keys found." &&

##################
# Then when there are some keys in the queue: more than the number of KSK needed but less than the total
log_this ods-zone-add-11 ods-ksmutil zone add --zone ods11 --policy Policy2 &&
log_this ods-zone-add-12 ods-ksmutil zone add --zone ods12 --policy Policy2 &&
log_this ods-zone-add-13 ods-ksmutil zone add --zone ods13 --policy Policy2 &&
log_this ods-zone-add-14 ods-ksmutil zone add --zone ods14 --policy Policy2 &&
log_this ods-zone-add-15 ods-ksmutil zone add --zone ods15 --policy Policy2 &&
log_this ods-zone-add-16 ods-ksmutil zone add --zone ods16 --policy Policy2 &&
log_this ods-zone-add-17 ods-ksmutil zone add --zone ods17 --policy Policy2 &&
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1  "ods-enforcerd: 16 zone(s) found on policy \"Policy2\""  &&
syslog_grep_count 1  'ods-enforcerd: 14 new KSK(s) (2048 bits) need to be created.'  &&
# 6 more ZSKs have been made active so we need more keys than when we run the test from ods-ksmutil
syslog_grep_count 1  'ods-enforcerd: 27 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_2   ods-hsmutil list &&
log_grep enforcer-keylist_2   stdout "89 keys found." &&

##################
# Then when there are more than enough keys in the queue
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 2  "ods-enforcerd: 16 zone(s) found on policy \"Policy2\""  &&
syslog_grep_count 1  'ods-enforcerd: No new KSKs need to be created.'  &&
# 7 more ZSKs have been made active so we need more keys than when we run the test from ods-ksmutil
# Note we can't distinguish this from 27 new keys so let it count as 2 instances :-(
syslog_grep_count 1  'ods-enforcerd: 7 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_2a   ods-hsmutil list &&
log_grep enforcer-keylist_2a   stdout "96 keys found." &&


##################  2. Keys not shared, diff alg & length ###########################
ods_setup_conf zonelist.xml zonelist.xml &&
ods_reset_env &&

# Generate keys where the algorithms/lengths are different - use algorithm 7/2048 and 8/2048 
# Firstly for an empty queue
log_this ods-zone-add-1 ods-ksmutil zone add --zone ods1 --policy Policy3 &&
log_this ods-zone-add-2 ods-ksmutil zone add --zone ods2 --policy Policy3 &&
log_this ods-zone-add-3 ods-ksmutil zone add --zone ods3 --policy Policy3 &&
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1  "ods-enforcerd: 3 zone(s) found on policy \"Policy3\""  &&
syslog_grep_count 2  'ods-enforcerd: 6 new KSK(s) (2048 bits) need to be created.'  &&
syslog_grep_count 2  'ods-enforcerd: 9 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_3   ods-hsmutil list &&
log_grep enforcer-keylist_3   stdout "15 keys found." &&

##################
# Then when there are some keys in the queue
log_this ods-zone-add-4 ods-ksmutil zone add --zone ods4 --policy Policy3 &&
log_this ods-zone-add-5 ods-ksmutil zone add --zone ods5 --policy Policy3 &&
log_this ods-zone-add-6 ods-ksmutil zone add --zone ods6 --policy Policy3 &&
log_this ods-zone-add-7 ods-ksmutil zone add --zone ods7 --policy Policy3 &&
log_this ods-zone-add-8 ods-ksmutil zone add --zone ods8 --policy Policy3 &&
log_this ods-zone-add-9 ods-ksmutil zone add --zone ods9 --policy Policy3 &&
log_this ods-zone-add-10 ods-ksmutil zone add --zone ods10 --policy Policy3 &&
log_this ods-zone-add-11 ods-ksmutil zone add --zone ods11 --policy Policy3 &&
log_this ods-zone-add-12 ods-ksmutil zone add --zone ods12 --policy Policy3 &&
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1  "ods-enforcerd: 12 zone(s) found on policy \"Policy3\""  &&
syslog_grep_count 1  'ods-enforcerd: 18 new KSK(s) (2048 bits) need to be created.'  &&
# 3 more ZSKs have been made active so we need more keys than when we run the test from ods-ksmutil
syslog_grep_count 1  'ods-enforcerd: 30 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_4   ods-hsmutil list &&
log_grep enforcer-keylist_4   stdout "63 keys found." &&
 

##################  3. Keys not shared, same alg & length. Standby enabled ###########################
ods_setup_conf zonelist.xml zonelist.xml &&
ods_reset_env &&

# Generate keys where standby also is enabled on alg 7, length 2048
log_this ods-zone-add-1 ods-ksmutil zone add --zone ods1 --policy Policy4 &&
log_this ods-zone-add-2 ods-ksmutil zone add --zone ods2 --policy Policy4 &&
log_this ods-zone-add-3 ods-ksmutil zone add --zone ods3 --policy Policy4 &&
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1  "ods-enforcerd: 3 zone(s) found on policy \"Policy4\""  &&
syslog_grep_count 1  'ods-enforcerd: 9 new KSK(s) (2048 bits) need to be created.'  &&
syslog_grep_count 3  'ods-enforcerd: 9 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist_5   ods-hsmutil list &&
log_grep enforcer-keylist_5   stdout "18 keys found." &&


##################  4. Keys not shared, same alg & length ###########################
ods_setup_conf zonelist.xml zonelist.xml &&
ods_reset_env &&

# Generate keys - now a policy with shared keys both with alg 7, length 2048
log_this ods-zone-add-1 ods-ksmutil zone add --zone ods1 --policy Policy5 &&
log_this ods-zone-add-2 ods-ksmutil zone add --zone ods2 --policy Policy5 &&
log_this ods-zone-add-3 ods-ksmutil zone add --zone ods3 --policy Policy5 &&
log_this ods-zone-add-4 ods-ksmutil zone add --zone ods4 --policy Policy5 &&
log_this ods-zone-add-5 ods-ksmutil zone add --zone ods5 --policy Policy5 &&
log_this ods-zone-add-6 ods-ksmutil zone add --zone ods6 --policy Policy5 &&
log_this ods-zone-add-7 ods-ksmutil zone add --zone ods7 --policy Policy5 &&
log_this ods-zone-add-8 ods-ksmutil zone add --zone ods8 --policy Policy5 &&
log_this ods-zone-add-9 ods-ksmutil zone add --zone ods9 --policy Policy5 &&
log_this ods-zone-add-10 ods-ksmutil zone add --zone ods10 --policy Policy5 &&
log_this ods-zone-add-11 ods-ksmutil zone add --zone ods11 --policy Policy5 &&
log_this ods-zone-add-12 ods-ksmutil zone add --zone ods12 --policy Policy5 &&
log_this ods-zone-add-13 ods-ksmutil zone add --zone ods13 --policy Policy5 &&
log_this ods-zone-add-14 ods-ksmutil zone add --zone ods14 --policy Policy5 &&
log_this ods-zone-add-15 ods-ksmutil zone add --zone ods15 --policy Policy5 &&
# Now a policy with shared keys one with alg 7, length 1024 and one with alg 8, length 2048
log_this ods-zone-add-16 ods-ksmutil zone add --zone ods16 --policy Policy6 &&
log_this ods-zone-add-17 ods-ksmutil zone add --zone ods17 --policy Policy6 &&
log_this ods-zone-add-18 ods-ksmutil zone add --zone ods18 --policy Policy6 &&
log_this ods-zone-add-19 ods-ksmutil zone add --zone ods19 --policy Policy6 &&
log_this ods-zone-add-20 ods-ksmutil zone add --zone ods20 --policy Policy6 &&
log_this ods-zone-add-21 ods-ksmutil zone add --zone ods21 --policy Policy6 &&
log_this ods-zone-add-22 ods-ksmutil zone add --zone ods22 --policy Policy6 &&
log_this ods-zone-add-23 ods-ksmutil zone add --zone ods23 --policy Policy6 &&
log_this ods-zone-add-24 ods-ksmutil zone add --zone ods24 --policy Policy6 &&
log_this ods-zone-add-25 ods-ksmutil zone add --zone ods25 --policy Policy6 &&
log_this ods-zone-add-26 ods-ksmutil zone add --zone ods26 --policy Policy6 &&
log_this ods-zone-add-27 ods-ksmutil zone add --zone ods27 --policy Policy6 &&
log_this ods-zone-add-28 ods-ksmutil zone add --zone ods28 --policy Policy6 &&
log_this ods-zone-add-29 ods-ksmutil zone add --zone ods29 --policy Policy6 &&
log_this ods-zone-add-30 ods-ksmutil zone add --zone ods30 --policy Policy6 &&
export ENFORCER_TIMESHIFT='01-01-2010 12:00' &&
ods_start_enforcer_timeshift &&

syslog_grep_count 1 "ods-enforcerd: 15 zone(s) found on policy \"Policy5\""  &&
syslog_grep_count 1  "ods-enforcerd: 15 zone(s) found on policy \"Policy6\""  &&
syslog_grep_count 1  'ods-enforcerd: 2 new KSK(s) (2048 bits) need to be created.' &&
syslog_grep_count 1  'ods-enforcerd: 2 new KSK(s) (1024 bits) need to be created.' &&
syslog_grep_count 2  'ods-enforcerd: 2 new ZSK(s) (2048 bits) need to be created.'  &&
log_this enforcer-keylist_8   ods-hsmutil list &&
log_grep enforcer-keylist_8   stdout "8 keys found." &&

##################
# Now shorten the key lifetimes in the kasp
ods_setup_conf kasp.xml kasp_2.xml &&
log_this ods-ksmutil-update-kasp ods-ksmutil update kasp && 

# Again with some keys in the queue
ods_start_enforcer_timeshift &&

syslog_grep_count 2  "ods-enforcerd: 15 zone(s) found on policy \"Policy5\""  &&
syslog_grep_count 1  'ods-enforcerd: 10 new KSK(s) (2048 bits) need to be created.'  &&
syslog_grep_count 2  'ods-enforcerd: 20 new ZSK(s) (2048 bits) need to be created.' &&

syslog_grep_count 2  "ods-enforcerd: 15 zone(s) found on policy \"Policy6\""  &&
syslog_grep_count 1  'ods-enforcerd: 10 new KSK(s) (1024 bits) need to be created.'  &&
syslog_grep_count 2  'ods-enforcerd: 20 new ZSK(s) (2048 bits) need to be created.' &&
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

