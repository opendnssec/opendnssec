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
log_this ods-ksmutil-check-0   ods-enforcer key list --verbose &&
log_grep ods-ksmutil-check-0   stdout "ZSK.*active" && 
log_grep ods-ksmutil-check-0   stdout "ZSK.*publish" && 
log_grep ods-ksmutil-check-0   stdout "KSK.*waiting for ds-seen" && 
log_grep ods-ksmutil-check-0   stdout "KSK.*publish" &&

# Get the key tags.
ZSK_CKA_ID_1=`log_grep -o ods-ksmutil-check-0 stdout "ZSK.*active" | sed 's/^.*\([0-9a-fA-F]\{32\}\).*$/\1/'` &&
ZSK_CKA_ID_2=`log_grep -o ods-ksmutil-check-0 stdout "ZSK.*publish" | sed 's/^.*\([0-9a-fA-F]\{32\}\).*$/\1/'` &&
KSK_CKA_ID_STANDBY=`log_grep -o ods-ksmutil-check-0 stdout "KSK.*waiting for ds-seen" | sed 's/^.*\([0-9a-fA-F]\{32\}\).*$/\1/'` &&
KSK_CKA_ID_1=`log_grep -o ods-ksmutil-check-0 stdout "KSK.*publish" | sed 's/^.*\([0-9a-fA-F]\{32\}\).*$/\1/'` &&

# Export KSKs
# test --keytype
log_this ods-ksmutil-key-export  ods-enforcer key export --zone ods &&
log_grep_count ods-ksmutil-key-export stdout "DNSKEY	257" 1 &&
# test --zone
log_this ods-ksmutil-key-export  ods-enforcer key export --zone ods &&
log_grep_count ods-ksmutil-key-export stdout "DNSKEY	257" 2 &&
# test --keystate
# test --ds
log_this ods-ksmutil-key-export  ods-enforcer key export --ds --zone ods &&
log_grep ods-ksmutil-key-export stdout ";KSK DS record (SHA1):" &&
log_grep ods-ksmutil-key-export stdout ";KSK DS record (SHA256):" &&


################ 2. Import a key using the 'ods-ksmutil key import' command  ###########################################
# You will need to generate a key directly in the hsm using 'ods-hsmutil create'
# then import the key and use 'ods-ksmutil key list --verbose' and check it is available 
log_this ods-hsmutil-generate ods-hsmutil generate SoftHSM rsa 2048 && 
log_grep ods-hsmutil-generate stdout "Key generation successful:.*" && 
CKA_ID=`log_grep -o ods-hsmutil-generate stdout "Key.*" | sed 's/^.*\([0-9a-fA-F]\{32\}\).*$/\1/'` &&

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
