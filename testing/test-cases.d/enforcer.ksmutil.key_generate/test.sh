#!/usr/bin/env bash
#
#TEST: Test to check the operation of the 'ods-ksmutil key generate' command
#TEST: including the new -zonetotal parameter

#DISABLED: ON SOLARIS T2000- as key generation takes too long!

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

##################  Default behaviour ###########################
# Fail with no zones
log_this ods-ksmutil-no_zones_policy   ods-ksmutil key generate --interval PT40M --policy  Policy1 &&
log_grep ods-ksmutil-no_zones_policy   stdout "Info: 0 zone(s) found on policy \"Policy1\"" &&
log_grep ods-ksmutil-no_zones_policy   stdout "No zones on policy Policy1, skipping..." &&

# Add a zone
log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil zone add --zone ods --input $INSTALL_ROOT/var/opendnssec/unsigned/ods.xml --policy Policy1 --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods.xml &&
log_grep ods-ksmutil-setup_zone_and_keys   stdout "Imported zone: ods" &&
log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil zone list &&
log_grep ods-ksmutil-setup_zone_and_keys   stdout "Found Zone: ods; on policy Policy1" &&

# Generate keys with algorithm 7, length 2048
echo "y" | log_this ods-ksmutil-default   ods-ksmutil key generate --interval PT4M --policy  Policy1 &&
log_grep ods-ksmutil-default   stdout "Info: 1 zone(s) found on policy \"Policy1\"" &&
log_grep ods-ksmutil-default   stdout "This will create 1 KSKs (2048 bits) and 5 ZSKs (2048 bits)" &&
log_grep ods-ksmutil-default   stdout "all done!" &&
log_this ods-ksmutil-keylist   ods-hsmutil list &&
log_grep ods-ksmutil-keylist   stdout "6 keys found." && 


##################  Using zone count ###########################
# Fail with 0 zone count
! log_this ods-ksmutil-zonetotal_fail   ods-ksmutil key generate --interval PT40M --policy  Policy2 --zonetotal 0 &&
log_grep ods-ksmutil-zonetotal_fail     stdout "Error: zonetotal parameter value of 0 is invalid - the value must be greater than 0" &&
# Fail with non-numeric zone count
! log_this ods-ksmutil-zonetotal_fail   ods-ksmutil key generate --interval PT40M --policy  Policy2 --zonetotal bob &&
log_grep ods-ksmutil-zonetotal_fail     stdout "Error: zonetotal \"bob\"; should be numeric only" &&

##################
ods_reset_env &&

# 1. Generate keys on a policy where the keys have the same algorithm (7) and length (2048)
# Firstly for an empty queue
echo "y" | log_this ods-ksmutil-zonetotal_same_1   ods-ksmutil key generate --interval PT40M --policy Policy2 --zonetotal 3 &&
log_grep ods-ksmutil-zonetotal_same_1   stdout "Info: 0 zone(s) found on policy \"Policy2\"" &&
log_grep ods-ksmutil-zonetotal_same_1   stdout "Info: Keys will actually be generated for a total of 3 zone(s) as specified by zone total parameter" &&
log_grep ods-ksmutil-zonetotal_same_1   stdout "all done!" &&
log_grep ods-ksmutil-zonetotal_same_1   stdout "This will create 6 KSKs (2048 bits) and 9 ZSKs (2048 bits)" &&
log_this ods-ksmutil-keylist_1   ods-hsmutil list &&
log_grep ods-ksmutil-keylist_1   stdout "15 keys found." && 

# Then when there are not enough keys for even the KSKs
echo "y" | log_this ods-ksmutil-zonetotal_same_2   ods-ksmutil key generate --interval PT40M --policy Policy2 --zonetotal 9 &&
log_grep ods-ksmutil-zonetotal_same_2   stdout "Info: 0 zone(s) found on policy \"Policy2\"" &&
log_grep ods-ksmutil-zonetotal_same_2   stdout "Info: Keys will actually be generated for a total of 9 zone(s) as specified by zone total parameter" &&
log_grep ods-ksmutil-zonetotal_same_2   stdout "all done!" &&
log_grep ods-ksmutil-zonetotal_same_2   stdout "This will create 18 KSKs (2048 bits) and 27 ZSKs (2048 bits)" &&
log_this ods-ksmutil-keylist_1a   ods-hsmutil list &&
log_grep ods-ksmutil-keylist_1a   stdout "60 keys found." &&

# Then when there are some keys in the queue: more than the number of KSK needed but less than the total
echo "y" | log_this ods-ksmutil-zonetotal_same_3   ods-ksmutil key generate --interval PT40M --policy Policy2 --zonetotal 16 &&
log_grep ods-ksmutil-zonetotal_same_3   stdout "Info: 0 zone(s) found on policy \"Policy2\"" &&
log_grep ods-ksmutil-zonetotal_same_3   stdout "Info: Keys will actually be generated for a total of 16 zone(s) as specified by zone total parameter" &&
log_grep ods-ksmutil-zonetotal_same_3   stdout "all done!" &&
log_grep ods-ksmutil-zonetotal_same_3   stdout "This will create 32 KSKs (2048 bits) and 48 ZSKs (2048 bits)" &&
log_this ods-ksmutil-keylist_2   ods-hsmutil list &&
log_grep ods-ksmutil-keylist_2   stdout "140 keys found." &&

# Then when there are more than enough keys in the queue
echo "y" | log_this ods-ksmutil-zonetotal_same_4   ods-ksmutil key generate --interval PT40M --policy Policy2 --zonetotal 4 &&
log_grep ods-ksmutil-zonetotal_same_4   stdout "Info: 0 zone(s) found on policy \"Policy2\"" &&
log_grep ods-ksmutil-zonetotal_same_4   stdout "Info: Keys will actually be generated for a total of 4 zone(s) as specified by zone total parameter" &&
log_grep ods-ksmutil-zonetotal_same_4   stdout "all done!" &&
log_grep ods-ksmutil-zonetotal_same_4   stdout "This will create 8 KSKs (2048 bits) and 12 ZSKs (2048 bits)" &&
log_this ods-ksmutil-keylist_2a   ods-hsmutil list &&
log_grep ods-ksmutil-keylist_2a   stdout "160 keys found." &&

##################
ods_reset_env &&

# 2. Generate keys where the algorithms/lengths are different - use algorithm 7/2048 and 8/2048 
# Firstly for an empty queue
echo "y" | log_this ods-ksmutil-zonetotal_diff_1   ods-ksmutil key generate --interval PT40M --policy Policy3 --zonetotal 3 &&
log_grep ods-ksmutil-zonetotal_diff_1   	stdout "Info: 0 zone(s) found on policy \"Policy3\"" &&
log_grep ods-ksmutil-zonetotal_diff_1   	stdout "Info: Keys will actually be generated for a total of 3 zone(s) as specified by zone total parameter" &&
log_waitfor ods-ksmutil-zonetotal_diff_1   	stdout 30 "all done!" &&
log_grep ods-ksmutil-zonetotal_diff_1   	stdout "This will create 6 KSKs (2048 bits) and 9 ZSKs (2048 bits)" &&
log_grep ods-ksmutil-zonetotal_diff_1   	stdout "all done!" &&
log_this ods-ksmutil-keylist_3   ods-hsmutil list &&
log_grep ods-ksmutil-keylist_3   stdout "15 keys found." &&

# Then when there are some keys in the queue
echo "y" | log_this ods-ksmutil-zonetotal_diff_2   ods-ksmutil key generate --interval PT40M --policy Policy3 --zonetotal 12 &&
log_grep ods-ksmutil-zonetotal_diff_2   	stdout "Info: 0 zone(s) found on policy \"Policy3\"" &&
log_grep ods-ksmutil-zonetotal_diff_2   	stdout "Info: Keys will actually be generated for a total of 12 zone(s) as specified by zone total parameter" &&
log_waitfor ods-ksmutil-zonetotal_diff_2    stdout 30 "all done!" &&
log_grep ods-ksmutil-zonetotal_diff_2   	stdout "This will create 24 KSKs (2048 bits) and 36 ZSKs (2048 bits)" &&
log_this ods-ksmutil-keylist_4   ods-hsmutil list &&
log_grep ods-ksmutil-keylist_4   stdout "75 keys found." &&
 
##################
ods_reset_env &&

# 3. Generate keys where standby also is enabled on alg 7, length 2048
echo "y" | log_this ods-ksmutil-zonetotal_standby   ods-ksmutil key generate --interval PT40M --policy Policy4 --zonetotal 3 &&
log_grep ods-ksmutil-zonetotal_standby   	stdout "Info: 0 zone(s) found on policy \"Policy4\"" &&
log_grep ods-ksmutil-zonetotal_standby   	stdout "Info: Keys will actually be generated for a total of 3 zone(s) as specified by zone total parameter" &&
log_waitfor ods-ksmutil-zonetotal_standby   stdout 30 "all done!" &&
log_grep ods-ksmutil-zonetotal_standby   	stdout "This will create 9 KSKs (2048 bits) and 9 ZSKs (2048 bits)" &&
log_grep ods-ksmutil-zonetotal_standby   	stdout "all done!" &&
log_this ods-ksmutil-keylist_5   ods-hsmutil list &&
log_grep ods-ksmutil-keylist_5   stdout "18 keys found." &&

##################
ods_reset_env &&

# 4. Generate keys - now a policy with shared keys both with alg 7, length 2048
echo "y" | log_this ods-ksmutil-zonetotal_shared   ods-ksmutil key generate --interval PT40M --policy Policy5 --zonetotal 15 &&
log_grep ods-ksmutil-zonetotal_shared   stdout "Info: 0 zone(s) found on policy \"Policy5\"" &&
log_grep ods-ksmutil-zonetotal_shared   stdout "Info: Keys will actually be generated for a total of 15 zone(s) as specified by zone total parameter" &&
log_grep ods-ksmutil-zonetotal_shared   stdout "all done!" &&
log_grep ods-ksmutil-zonetotal_shared   stdout "This will create 2 KSKs (2048 bits) and 2 ZSKs (2048 bits)" &&
log_this ods-ksmutil-keylist_6   ods-hsmutil list &&
log_grep ods-ksmutil-keylist_6   stdout "4 keys found." &&

# Again with some keys in the queue
echo "y" | log_this ods-ksmutil-zonetotal_shared_1   ods-ksmutil key generate --interval PT80M --policy Policy5 --zonetotal 15 &&
log_grep ods-ksmutil-zonetotal_shared_1   stdout "Info: 0 zone(s) found on policy \"Policy5\"" &&
log_grep ods-ksmutil-zonetotal_shared_1   stdout "Info: Keys will actually be generated for a total of 15 zone(s) as specified by zone total parameter" &&
log_grep ods-ksmutil-zonetotal_shared_1   stdout "all done!" &&
log_grep ods-ksmutil-zonetotal_shared_1   stdout "This will create 3 KSKs (2048 bits) and 4 ZSKs (2048 bits)" &&
log_this ods-ksmutil-keylist_7   ods-hsmutil list &&
log_grep ods-ksmutil-keylist_7   stdout "11 keys found." &&

# Now a policy with shared keys one with alg 7, length 1024 and one with alg 8, length 2048
echo "y" | log_this ods-ksmutil-zonetotal_shared_2   ods-ksmutil key generate --interval PT40M --policy Policy6 --zonetotal 15 &&
log_grep ods-ksmutil-zonetotal_shared_2   stdout "Info: 0 zone(s) found on policy \"Policy6\"" &&
log_grep ods-ksmutil-zonetotal_shared_2   stdout "Info: Keys will actually be generated for a total of 15 zone(s) as specified by zone total parameter" &&
log_grep ods-ksmutil-zonetotal_shared_2   stdout "all done!" &&
log_grep ods-ksmutil-zonetotal_shared_2   stdout "This will create 2 KSKs (1024 bits) and 2 ZSKs (2048 bits)" &&
log_this ods-ksmutil-keylist_8   ods-hsmutil list &&
log_grep ods-ksmutil-keylist_8   stdout "15 keys found." &&

# Again with some keys in the queue
echo "y" | log_this ods-ksmutil-zonetotal_shared_3   ods-ksmutil key generate --interval PT80M --policy Policy6 --zonetotal 15 &&
log_grep ods-ksmutil-zonetotal_shared_3   stdout "Info: 0 zone(s) found on policy \"Policy6\"" &&
log_grep ods-ksmutil-zonetotal_shared_3   stdout "Info: Keys will actually be generated for a total of 15 zone(s) as specified by zone total parameter" &&
log_grep ods-ksmutil-zonetotal_shared_3   stdout "all done!" &&
log_grep ods-ksmutil-zonetotal_shared_3   stdout "This will create 3 KSKs (1024 bits) and 4 ZSKs (2048 bits)" &&
log_this ods-ksmutil-keylist_9   ods-hsmutil list &&
log_grep ods-ksmutil-keylist_9   stdout "22 keys found." &&

echo &&
echo "************OK******************" &&
echo &&

return 0 

echo
echo "************ERROR******************"
echo
ods_kill
return 1

