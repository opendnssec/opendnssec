#!/usr/bin/env bash
#
#TEST: Test to check that key import/export/purge works correctly

# Lets use parameters for the timing intervals so they are easy to change
SHORT_TIMEOUT=11    # Timeout when checking log output. DS lock out wait is 10 sec so use 11 for this
LONG_TIMEOUT=40     # Timeout when waiting for enforcer run to have happened
SLEEP_INTERVAL=50   # This should be just shorter than the enforcer run interval in conf.xml

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
else 
        ods_setup_conf conf.xml conf.xml
fi &&

ods_reset_env &&
ods_start_enforcer &&

# Add a zone
log_this ods-enforcer-setup_zone_and_keys   ods-enforcer zone add --zone ods --input $INSTALL_ROOT/var/opendnssec/unsigned/ods --policy default --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods.xml &&
log_grep ods-enforcer-setup_zone_and_keys   stdout "Zone ods added successfully" &&
log_this ods-enforcer-setup_zone_and_keys   ods-enforcer zone list &&
log_grep ods-enforcer-setup_zone_and_keys   stdout "^ods[ \t]*default[ \t]*" &&

# Get keys in stable state
ods_enforcer_leap_to 7200 &&

# Check the output and state of keys.
log_this ods-enforcer-check-0   ods-enforcer key list --verbose &&
log_grep ods-enforcer-check-0   stdout "ZSK.*active" &&
log_grep ods-enforcer-check-0   stdout "ZSK.*publish" &&
log_grep ods-enforcer-check-0   stdout "KSK.*waiting for ds-seen" &&
log_grep ods-enforcer-check-0   stdout "KSK.*publish" &&

# Get the key tags.
ZSK_CKA_ID_1=`log_grep -o ods-enforcer-check-0 stdout "ZSK.*active" | sed 's/^.*\([0-9a-fA-F]\{32\}\).*$/\1/'` &&
ZSK_CKA_ID_2=`log_grep -o ods-enforcer-check-0 stdout "ZSK.*publish" | sed 's/^.*\([0-9a-fA-F]\{32\}\).*$/\1/'` &&
KSK_CKA_ID_STANDBY=`log_grep -o ods-enforcer-check-0 stdout "KSK.*waiting for ds-seen" | sed 's/^.*\([0-9a-fA-F]\{32\}\).*$/\1/'` &&
KSK_CKA_ID_1=`log_grep -o ods-enforcer-check-0 stdout "KSK.*publish" | sed 's/^.*\([0-9a-fA-F]\{32\}\).*$/\1/'` &&

##################  TEST  ###########################

##################  1. Export  the ZSKs first using 'ods-enforcer key export --all' ######################################
# Then try the export with each of the different flags (--zone, --keystate, --keytype, --ds) and make sure it works correctly
# test
log_this ods-enforcer-key-export  ods-enforcer key export --all &&
log_grep_count ods-enforcer-key-export stdout "DNSKEY	257" 1 &&
# test --zone
log_this ods-enforcer-key-export  ods-enforcer key export --zone ods --keytype ZSK --keystate publish &&
log_grep_count ods-enforcer-key-export stdout "DNSKEY	256" 1 &&
log_this ods-enforcer-key-export  ods-enforcer key export --zone ods &&
log_grep_count ods-enforcer-key-export stdout "DNSKEY	257" 2 &&
# test --keystate and --keytype
# there is no ZSK in generate state, so the number must not be increased
log_this ods-enforcer-key-export  ods-enforcer key export --all --keytype ZSK --keystate generate &&
log_grep_count ods-enforcer-key-export stdout "DNSKEY	256" 1 &&
log_this ods-enforcer-key-export  ods-enforcer key export --all --keytype ZSK --keystate publish &&
log_grep_count ods-enforcer-key-export stdout "DNSKEY	256" 2 &&
# there is no ZSK in ready state
log_this ods-enforcer-key-export  ods-enforcer key export --all --keytype ZSK --keystate ready &&
log_grep_count ods-enforcer-key-export stdout "DNSKEY	256" 2 &&
log_this ods-enforcer-key-export  ods-enforcer key export --all --keytype ZSK --keystate active &&
log_grep_count ods-enforcer-key-export stdout "DNSKEY	256" 3 &&
# test --ds
log_this ods-enforcer-key-export  ods-enforcer key export --ds --zone ods &&
log_grep ods-enforcer-key-export stdout "KSK DS record (SHA256):" &&


################ 2. Import a key using the 'ods-enforcer key import' command  ###########################################
# You will need to generate a key directly in the hsm using 'ods-hsmutil create'
# then import the key and use 'ods-enforcer key list --verbose' and check it is available
log_this ods-hsmutil-generate ods-hsmutil generate SoftHSM rsa 2048 &&
log_grep ods-hsmutil-generate stdout "Key generation successful:.*" &&
CKA_ID=`log_grep -o ods-hsmutil-generate stdout "Key.*" | sed 's/^.*\([0-9a-fA-F]\{32\}\).*$/\1/'` &&

log_this ods-enforcer-key-import ods-enforcer key import --cka_id $CKA_ID --repository SoftHSM --bits 2048 --algorithm 5 --keystate ready --keytype ZSK  --zone ods --inception_time "2016-08-29-14:17:28" &&
log_grep ods-enforcer-key-import stdout "Key imported into zone" &&
log_this ods-enforcer-check-1   ods-enforcer key list --all --verbose &&
log_grep ods-enforcer-check-1   stdout "$CKA_ID" &&

# You could also test a failure cases where you try to import a key that doesn't exist and where the parameters used in the command are wrong (e.g. )
! log_this ods-enforcer-key-import ods-enforcer key import --cka_id 123456 --repository SoftHSM --bits 2048 --algorithm 5 --keystate ready --keytype ZSK  --zone ods --inception_time "2016-08-29-14:17:28" &&
log_grep ods-enforcer-key-import stderr "Unable to find the key with this locator: 123456" &&

! log_this ods-enforcer-key-import ods-enforcer key import --cka_id $CKA_ID --repository SoftHSM_1 --bits 2048 --algorithm 5 --keystate ready --keytype ZSK  --zone ods --inception_time "2016-08-29-14:17:28" &&
log_grep ods-enforcer-key-import   stderr "Unable to check for the repository" &&
log_grep ods-enforcer-key-import stderr "Can't find repository: SoftHSM_1" &&

! log_this ods-enforcer-key-import ods-enforcer key import --cka_id $CKA_ID --repository SoftHSM --bits 2048 --algorithm 5 --keystate ready --keytype ZSK  --zone ods23 --inception_time "2016-08-29-14:17:28" &&
log_grep ods-enforcer-key-import   stderr "Unknown zone: ods23" &&

! log_this ods-enforcer-key-import ods-enforcer key import --cka_id $CKA_ID --repository SoftHSM --bits 2048 --algorithm 5 --keystate ready1 --keytype ZSK  --zone ods --wrong-option "2016-08-29-14:17:28" &&
log_grep ods-enforcer-key-import   stderr "unknown arguments" &&

! log_this ods-enforcer-key-import ods-enforcer key import --cka_id $CKA_ID --repository SoftHSM --bits 2048 --algorithm 5 --keystate ready --keytype ZSK  --zone ods --inception_time "2016-08-29-14:17:28" --extra_option fail &&
log_grep ods-enforcer-key-import   stderr "too many arguments" &&

############### 3. Then run the 'ods-enforcer key purge' command  #######################################################
# At this stage there are no dead keys so I don't think it will do anything
log_this ods-enforcer-key-purge ods-enforcer key purge --policy default &&
log_grep ods-enforcer-key-purge stdout "No keys to purge for ods" &&


############### 4. Then move forward in time and keep running the enforcer in timeshift mode so that keys rollover and retire. ########################
# Look at the test 'enforcer.keys.rollovers_many_timeshift' to see how to do this
# When you have some keys that are dead then run the purge command again and check is actually does something!
ods_enforcer_leap_to 3600 &&
log_this ods-enforcer-key-purge ods-enforcer key purge --zone ods &&
log_grep ods-enforcer-key-purge stdout "deleting key" &&

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
