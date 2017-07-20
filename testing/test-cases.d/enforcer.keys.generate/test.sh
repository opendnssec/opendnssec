#!/usr/bin/env bash
#
#TEST: Test to check to check that the enforcer automatically generates keys correctly
#TEST: This test does mulitple runs of the enforcer with zones
#TEST: on different policies and checks it generates the right number
#TEST: of the right kind of key. Tries to test algorithm and length mixtures
#TEST: shared keys and standby


ODS_ENFORCER_WAIT_STOP_LOG=600

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

##################  Basic behaviour  ###########################
# Fail with no zones
ods_start_enforcer &&

# Generate keys with algorithm 7, length 2048
log_this ods-zone-add-1 ods-enforcer zone add --zone ods1 --policy Policy1 &&
ods_enforcer_idle &&

syslog_waitfor 60 "ods-enforcerd: .*1 zone(s) found on policy \"Policy1\""  &&
syslog_waitfor 60 'ods-enforcerd: .*1 new KSK(s) (2048 bits) need to be created.'  &&
syslog_waitfor 60 'ods-enforcerd: .*5 new ZSK(s) (2048 bits) need to be created.' &&
log_this enforcer-keylist   ods-hsmutil list &&
#log_grep enforcer-keylist   stdout "8 keys found." && 

##################  1. Keys not shared, same alg & length ###########################

ods_stop_enforcer &&
ods_setup_conf zonelist.xml zonelist.xml &&
ods_reset_env &&
ods_start_enforcer &&

log_this enforcer-keylist_0 ods-hsmutil list &&
log_grep enforcer-keylist_0 stdout "0 keys found." && 

# Generate keys on a policy where the keys have the same algorithm (7) and length (2048)
# Firstly for an empty queue
log_this ods-zone-add-2 ods-enforcer zone add --zone ods2 --policy Policy2 &&
ods_enforcer_idle &&
log_this ods-zone-add-3 ods-enforcer zone add --zone ods3 --policy Policy2 &&
ods_enforcer_idle &&
log_this ods-zone-add-4 ods-enforcer zone add --zone ods4 --policy Policy2 &&
ods_enforcer_idle &&
ods_enforcer_leap_over 60 &&

syslog_waitfor 60 "ods-enforcerd: 3 zone(s) found on policy \"Policy2\""  &&
log_this enforcer-keylist_1   ods-hsmutil list &&
log_grep enforcer-keylist_1   stdout "12 keys found." && 

log_this ods-zone-add-5 ods-enforcer zone add --zone ods5 --policy Policy2 &&
ods_enforcer_idle &&
log_this ods-zone-add-6 ods-enforcer zone add --zone ods6 --policy Policy2 &&
ods_enforcer_idle &&
log_this ods-zone-add-7 ods-enforcer zone add --zone ods7 --policy Policy2 &&
ods_enforcer_idle &&
log_this ods-zone-add-8 ods-enforcer zone add --zone ods8 --policy Policy2 &&
ods_enforcer_idle &&
log_this ods-zone-add-9 ods-enforcer zone add --zone ods9 --policy Policy2 &&
ods_enforcer_idle &&
log_this ods-zone-add-10 ods-enforcer zone add --zone ods10 --policy Policy2 &&
ods_enforcer_idle &&
sleep 10 &&
ods_enforcer_idle &&
ods_enforcer_leap_over 60 &&

syslog_waitfor 60 "ods-enforcerd: 9 zone(s) found on policy \"Policy2\""  &&
log_this enforcer-keylist_1a   ods-hsmutil list &&
log_grep enforcer-keylist_1a   stdout "24 keys found." &&

##################
# Then when there are some keys in the queue: more than the number of KSK needed but less than the total
log_this ods-zone-add-11 ods-enforcer zone add --zone ods11 --policy Policy2 &&
ods_enforcer_idle &&
log_this ods-zone-add-12 ods-enforcer zone add --zone ods12 --policy Policy2 &&
ods_enforcer_idle &&
log_this ods-zone-add-13 ods-enforcer zone add --zone ods13 --policy Policy2 &&
ods_enforcer_idle &&
log_this ods-zone-add-14 ods-enforcer zone add --zone ods14 --policy Policy2 &&
ods_enforcer_idle &&
log_this ods-zone-add-15 ods-enforcer zone add --zone ods15 --policy Policy2 &&
ods_enforcer_idle &&
log_this ods-zone-add-16 ods-enforcer zone add --zone ods16 --policy Policy2 &&
ods_enforcer_idle &&
log_this ods-zone-add-17 ods-enforcer zone add --zone ods17 --policy Policy2 &&
ods_enforcer_idle &&

syslog_waitfor 120 'update zone: ods11' &&
syslog_waitfor 120 'update zone: ods12' &&
syslog_waitfor 120 'update zone: ods13' &&
syslog_waitfor 120 'update zone: ods14' &&
syslog_waitfor 120 'update zone: ods15' &&
syslog_waitfor 120 'update zone: ods16' &&
syslog_waitfor 120 'update zone: ods17' &&
ods_enforcer_leap_over 60 &&
ods_enforcer_idle &&
syslog_waitfor 120 'ods-enforcerd: 16 zone(s) found on policy \"Policy2\"' &&
# 6 more ZSKs have been made active so we need more keys than when we run the test from ods-enforcer
log_this enforcer-keylist_2   ods-hsmutil list &&
log_grep enforcer-keylist_2   stdout "38 keys found." &&

##################  2. Keys not shared, diff alg & length ###########################

ods_stop_enforcer &&
ods_setup_conf zonelist.xml zonelist.xml &&
ods_reset_env &&
ods_start_enforcer &&

# Generate keys where the algorithms/lengths are different - use algorithm 7/2048 and 8/2048 
# Firstly for an empty queue
ods-enforcer zone list &&
log_this ods-zone-add-1 ods-enforcer zone add --zone ods1 --policy Policy3 &&
ods_enforcer_idle &&
log_this ods-zone-add-2 ods-enforcer zone add --zone ods2 --policy Policy3 &&
ods_enforcer_idle &&
log_this ods-zone-add-3 ods-enforcer zone add --zone ods3 --policy Policy3 &&
ods_enforcer_idle &&
ods_enforcer_leap_over 60 &&

syslog_grep "ods-enforcerd: .*3 zone(s) found on policy \"Policy3\""  &&
log_this enforcer-keylist_3   ods-hsmutil list &&
log_grep enforcer-keylist_3   stdout "12 keys found." &&

##################
# Then when there are some keys in the queue
log_this ods-zone-add-4 ods-enforcer zone add --zone ods4 --policy Policy3 &&
ods_enforcer_idle &&
log_this ods-zone-add-5 ods-enforcer zone add --zone ods5 --policy Policy3 &&
ods_enforcer_idle &&
log_this ods-zone-add-6 ods-enforcer zone add --zone ods6 --policy Policy3 &&
ods_enforcer_idle &&
log_this ods-zone-add-7 ods-enforcer zone add --zone ods7 --policy Policy3 &&
ods_enforcer_idle &&
log_this ods-zone-add-8 ods-enforcer zone add --zone ods8 --policy Policy3 &&
ods_enforcer_idle &&
log_this ods-zone-add-9 ods-enforcer zone add --zone ods9 --policy Policy3 &&
ods_enforcer_idle &&
log_this ods-zone-add-10 ods-enforcer zone add --zone ods10 --policy Policy3 &&
ods_enforcer_idle &&
log_this ods-zone-add-11 ods-enforcer zone add --zone ods11 --policy Policy3 &&
ods_enforcer_idle &&
log_this ods-zone-add-12 ods-enforcer zone add --zone ods12 --policy Policy3 &&
ods_enforcer_idle &&
ods_enforcer_leap_over 60 &&

syslog_grep "ods-enforcerd: .*12 zone(s) found on policy \"Policy3\""  &&
log_this enforcer-keylist_4   ods-hsmutil list &&
log_grep enforcer-keylist_4   stdout "30 keys found." &&
 

##################  3. Keys not shared, same alg & length. Standby enabled ###########################
ods_stop_enforcer &&
ods_setup_conf zonelist.xml zonelist.xml &&
ods_reset_env &&
ods_start_enforcer &&

# Generate keys where standby also is enabled on alg 7, length 2048
ods-enforcer zone list &&
log_this ods-zone-add-1 ods-enforcer zone add --zone ods1 --policy Policy4 &&
ods_enforcer_idle &&
log_this ods-zone-add-2 ods-enforcer zone add --zone ods2 --policy Policy4 &&
ods_enforcer_idle &&
log_this ods-zone-add-3 ods-enforcer zone add --zone ods3 --policy Policy4 &&
ods_enforcer_idle &&
ods_enforcer_leap_over 60 &&

syslog_grep "ods-enforcerd: .*3 zone(s) found on policy \"Policy4\""  &&
log_this enforcer-keylist_5   ods-hsmutil list &&
log_grep enforcer-keylist_5   stdout "10 keys found." &&


##################  4. Keys not shared, same alg & length ###########################
ods_stop_enforcer &&
ods_setup_conf zonelist.xml zonelist.xml &&
ods_reset_env &&
ods_start_enforcer &&

# Generate keys - now a policy with shared keys both with alg 7, length 2048
log_this ods-zone-add-1 ods-enforcer zone add --zone ods1 --policy Policy5 &&
ods_enforcer_idle &&
log_this ods-zone-add-2 ods-enforcer zone add --zone ods2 --policy Policy5 &&
ods_enforcer_idle &&
log_this ods-zone-add-3 ods-enforcer zone add --zone ods3 --policy Policy5 &&
ods_enforcer_idle &&
log_this ods-zone-add-4 ods-enforcer zone add --zone ods4 --policy Policy5 &&
ods_enforcer_idle &&
log_this ods-zone-add-5 ods-enforcer zone add --zone ods5 --policy Policy5 &&
ods_enforcer_idle &&
log_this ods-zone-add-6 ods-enforcer zone add --zone ods6 --policy Policy5 &&
ods_enforcer_idle &&
log_this ods-zone-add-7 ods-enforcer zone add --zone ods7 --policy Policy5 &&
ods_enforcer_idle &&
log_this ods-zone-add-8 ods-enforcer zone add --zone ods8 --policy Policy5 &&
ods_enforcer_idle &&
log_this ods-zone-add-9 ods-enforcer zone add --zone ods9 --policy Policy5 &&
ods_enforcer_idle &&
log_this ods-zone-add-10 ods-enforcer zone add --zone ods10 --policy Policy5 &&
ods_enforcer_idle &&
log_this ods-zone-add-11 ods-enforcer zone add --zone ods11 --policy Policy5 &&
ods_enforcer_idle &&
log_this ods-zone-add-12 ods-enforcer zone add --zone ods12 --policy Policy5 &&
ods_enforcer_idle &&
log_this ods-zone-add-13 ods-enforcer zone add --zone ods13 --policy Policy5 &&
ods_enforcer_idle &&
log_this ods-zone-add-14 ods-enforcer zone add --zone ods14 --policy Policy5 &&
ods_enforcer_idle &&
log_this ods-zone-add-15 ods-enforcer zone add --zone ods15 --policy Policy5 &&
ods_enforcer_idle &&
# Now a policy with shared keys one with alg 7, length 1024 and one with alg 8, length 2048
## YBS: NOTE, this is a wierd policy, having KSK a different algorithm than 
## the ZSK
log_this ods-zone-add-16 ods-enforcer zone add --zone ods16 --policy Policy6 &&
ods_enforcer_idle &&
log_this ods-zone-add-17 ods-enforcer zone add --zone ods17 --policy Policy6 &&
ods_enforcer_idle &&
log_this ods-zone-add-18 ods-enforcer zone add --zone ods18 --policy Policy6 &&
ods_enforcer_idle &&
log_this ods-zone-add-19 ods-enforcer zone add --zone ods19 --policy Policy6 &&
ods_enforcer_idle &&
log_this ods-zone-add-20 ods-enforcer zone add --zone ods20 --policy Policy6 &&
ods_enforcer_idle &&
log_this ods-zone-add-21 ods-enforcer zone add --zone ods21 --policy Policy6 &&
ods_enforcer_idle &&
log_this ods-zone-add-22 ods-enforcer zone add --zone ods22 --policy Policy6 &&
ods_enforcer_idle &&
log_this ods-zone-add-23 ods-enforcer zone add --zone ods23 --policy Policy6 &&
ods_enforcer_idle &&
log_this ods-zone-add-24 ods-enforcer zone add --zone ods24 --policy Policy6 &&
ods_enforcer_idle &&
log_this ods-zone-add-25 ods-enforcer zone add --zone ods25 --policy Policy6 &&
ods_enforcer_idle &&
log_this ods-zone-add-26 ods-enforcer zone add --zone ods26 --policy Policy6 &&
ods_enforcer_idle &&
log_this ods-zone-add-27 ods-enforcer zone add --zone ods27 --policy Policy6 &&
ods_enforcer_idle &&
log_this ods-zone-add-28 ods-enforcer zone add --zone ods28 --policy Policy6 &&
ods_enforcer_idle &&
log_this ods-zone-add-29 ods-enforcer zone add --zone ods29 --policy Policy6 &&
ods_enforcer_idle &&
log_this ods-zone-add-30 ods-enforcer zone add --zone ods30 --policy Policy6 &&
ods_enforcer_idle &&
ods_enforcer_leap_over 60 &&

syslog_waitfor 120 "ods-enforcerd: .*1 zone(s) found on policy \"Policy5\""  &&
syslog_waitfor 120 "ods-enforcerd: .*1 zone(s) found on policy \"Policy6\""  &&
log_this enforcer-keylist_8   ods-hsmutil list &&
## 3xKSK, 3xZSK Policy5, 3xKSK(1024bit), 3xZSK Policy6
log_grep enforcer-keylist_8   stdout "12 keys found." &&

ods_stop_enforcer &&

echo && 
echo "************OK******************" &&
echo &&

return 0 

echo
echo "************ERROR******************"
echo
ods_kill
return 1

