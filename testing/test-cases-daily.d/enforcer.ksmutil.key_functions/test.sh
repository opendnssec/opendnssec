#!/usr/bin/env bash
#
#TEST: Test to check that key import/export/purge works correctly

#DISABLED: ON FREEBSD - due to pthread seg fault on freebsd64

# Lets use parameters for the timing intervals so they are easy to change
SHORT_TIMEOUT=11    # Timeout when checking log output. DS lock out wait is 10 sec so use 11 for this
LONG_TIMEOUT=40     # Timeout when waiting for enforcer run to have happened
SLEEP_INTERVAL=50   # This should be just shorter than the enforcer run interval in conf.xml

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
else 
        ods_setup_conf conf.xml conf.xml
fi &&

case "$DISTRIBUTION" in
	freebsd )
		return 0
		;;
esac

ods_reset_env &&


##################  SETUP ###########################
# Add a zone
log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil zone add --zone ods --input $INSTALL_ROOT/var/opendnssec/unsigned/ods --policy Policy1 --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods.xml &&
log_grep ods-ksmutil-setup_zone_and_keys   stdout "Imported zone: ods" &&
log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil zone list &&
log_grep ods-ksmutil-setup_zone_and_keys   stdout "Found Zone: ods; on policy Policy1" &&

# Generate keys
echo "y" | log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil key generate --interval PT40M --policy  Policy1 &&
log_grep ods-ksmutil-setup_zone_and_keys   stdout "This will create 22 KSKs" &&
log_this ods-ksmutil-setup_zone_and_keys   ods-ksmutil update conf &&
log_grep ods-ksmutil-setup_zone_and_keys   stdout "RequireBackup NOT set; " &&

# Start enforcer in timeshift mode. It will run only once and think it is the specified time.
export ENFORCER_TIMESHIFT='21-08-2013 10:40:40' &&
log_this_timeout ods-control-enforcer-start $LONG_TIMEOUT ods-enforcerd -1 &&
syslog_waitfor_count $LONG_TIMEOUT 1 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 21-08-2013 10:40:40" &&

##################  Check the keys ###########################
# Check the output
log_this ods-ksmutil-check-0   date && log_this ods-ksmutil-check-0   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-check-0   stdout "ZSK           active" && 
log_grep ods-ksmutil-check-0   stdout "ZSK           publish" && 
log_grep ods-ksmutil-check-0   stdout "KSK           dssub" && 
log_grep ods-ksmutil-check-0   stdout "KSK           publish" &&

# Get the key tags.
ZSK_CKA_ID_1=`log_grep -o ods-ksmutil-check-0 stdout "ZSK           active" | awk '{print $9}'` &&
ZSK_CKA_ID_2=`log_grep -o ods-ksmutil-check-0 stdout "ZSK           publish" | awk '{print $9}'` &&
KSK_CKA_ID_STANDBY=`log_grep -o ods-ksmutil-check-0 stdout "KSK           dssub" | awk '{print $10}'` &&
KSK_CKA_ID_1=`log_grep -o ods-ksmutil-check-0 stdout "KSK           publish" | awk '{print $9}'` &&

##################  TEST  ###########################

##################  1. Export  the ZSKs first using 'ods-ksmutil key export --all' ######################################
# Then try the export with each of the different flags (--zone, --keystate, --keytype, --ds) and make sure it works correctly
# test --keytype
log_this ods-ksmutil-key-export  ods-ksmutil key export --all --keytype ZSK &&
log_grep_count ods-ksmutil-key-export stdout "DNSKEY	256" 1 &&
log_this ods-ksmutil-key-export  ods-ksmutil key export --all --keytype KSK &&
log_grep_count ods-ksmutil-key-export stdout "DNSKEY	257" 1 &&
# test --zone
log_this ods-ksmutil-key-export  ods-ksmutil key export --zone ods --keytype ZSK &&
log_grep_count ods-ksmutil-key-export stdout "DNSKEY	256" 2 &&
log_this ods-ksmutil-key-export  ods-ksmutil key export --zone ods --keytype KSK &&
log_grep_count ods-ksmutil-key-export stdout "DNSKEY	257" 2 &&
# test --keystate
log_this ods-ksmutil-key-export  ods-ksmutil key export --all --keytype ZSK --keystate generate &&
log_grep_count ods-ksmutil-key-export stdout "DNSKEY	256" 2 &&
log_this ods-ksmutil-key-export  ods-ksmutil key export --all --keytype ZSK --keystate publish &&
log_grep_count ods-ksmutil-key-export stdout "DNSKEY	256" 3 &&
log_this ods-ksmutil-key-export  ods-ksmutil key export --all --keytype ZSK --keystate ready &&
log_grep_count ods-ksmutil-key-export stdout "DNSKEY	256" 3 &&
log_this ods-ksmutil-key-export  ods-ksmutil key export --all --keytype ZSK --keystate active &&
# test --ds
log_this ods-ksmutil-key-export  ods-ksmutil key export --ds &&
log_grep ods-ksmutil-key-export stdout ";dssub KSK DS record (SHA1):" &&
log_grep ods-ksmutil-key-export stdout ";dssub KSK DS record (SHA256):" &&


################ 2. Import a key using the 'ods-ksmutil key import' command  ###########################################
# You will need to generate a key directly in the hsm using 'ods-hsmutil create'
# then import the key and use 'ods-ksmutil key list --verbose' and check it is available 
log_this ods-hsmutil-generate ods-hsmutil generate SoftHSM rsa 2048 && 
log_grep ods-hsmutil-generate stdout "Key generation successful:.*" && 
CKA_ID=`log_grep -o ods-hsmutil-generate stdout "Key.*" |awk '{print $4}'`&&
log_this ods-ksmutil-key-import ods-ksmutil key import --cka_id $CKA_ID --repository SoftHSM --bits 2048 --algorithm 5 --keystate 2 --keytype ZSK  --zone ods --time "2013-08-29 14:17:28" &&
log_grep ods-ksmutil-key-import stdout "Key imported into zone(s)" &&
log_this ods-ksmutil-check-1   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-check-1   stdout "$CKA_ID" &&

# You could also test a failure cases where you try to import a key that doesn't exist and where the parameters used in the command are wrong (e.g. )
log_this ods-ksmutil-key-import ods-ksmutil key import --cka_id 123456 --repository SoftHSM --bits 2048 --algorithm 5 --keystate 2 --keytype ZSK  --zone ods --time "2013-08-29 14:17:28" &&
log_grep ods-ksmutil-key-import stdout "Warning: No key with the CKA_ID 123456                            exists in the repository SoftHSM. The key will be imported into the database anyway" &&

# use the option --check-repository
! log_this ods-ksmutil-key-import ods-ksmutil key import --cka_id 654321 --repository SoftHSM --bits 2048 --algorithm 5 --keystate 2 --keytype ZSK  --zone ods --time "2013-08-29 14:17:28" --check-repository &&
log_grep ods-ksmutil-key-import stdout "Error: No key with the CKA_ID 654321                            exists in the repository SoftHSM. When the option \[--check-repository\] is used the key MUST exist in the repository for the key to be imported" &&

! log_this ods-ksmutil-key-import ods-ksmutil key import --cka_id 123 --repository SoftHSM_1 --bits 2048 --algorithm 5 --keystate 2 --keytype ZSK  --zone ods --time "2013-08-29 14:17:28" &&
log_grep ods-ksmutil-key-import   stdout "Error: unable to find a repository named \"SoftHSM_1\" in database" &&


############### 3. Then run the 'ods-ksmutil key purge' command  #######################################################
# At this stage there are no dead keys so I don't think it will do anything
log_this ods-ksmutil-key-purge ods-ksmutil key purge --policy Policy1 &&
log_grep ods-ksmutil-key-purge stdout "No keys to purge." &&


############### 4. Then move forward in time and keep running the enforcer in timeshift mode so that keys rollover and retire. ########################
# Look at the test 'enforcer.keys.rollovers_many_timeshift' to see how to do this
# When you have some keys that are dead then run the purge command again and check is actually does something!
export ENFORCER_TIMESHIFT='21-08-2013 10:41:40' &&
log_this_timeout ods-control-enforcer-start $LONG_TIMEOUT ods-enforcerd -1 &&
syslog_waitfor_count $LONG_TIMEOUT 2 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 21-08-2013 10:41:40" &&

export ENFORCER_TIMESHIFT='21-08-2013 10:43:40' &&
log_this_timeout ods-control-enforcer-start $LONG_TIMEOUT ods-enforcerd -1 &&
syslog_waitfor_count $LONG_TIMEOUT 3 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 21-08-2013 10:43:40" &&

export ENFORCER_TIMESHIFT='21-08-2013 10:44:10' &&
log_this_timeout ods-control-enforcer-start $LONG_TIMEOUT ods-enforcerd -1 &&
syslog_waitfor_count $LONG_TIMEOUT 4 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: .*DEBUG: Timeshift in operation; ENFORCER_TIMESHIFT set to 21-08-2013 10:44:10" &&

log_this ods-ksmutil-key-purge ods-ksmutil key purge --zone ods &&
log_grep ods-ksmutil-key-purge stdout "Key remove successful" &&




echo && 
echo "************OK******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1



