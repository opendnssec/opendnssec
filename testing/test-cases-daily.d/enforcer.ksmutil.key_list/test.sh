#!/usr/bin/env bash
#
#TEST: Test to check that key list works correctly

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
export ENFORCER_TIMESHIFT='26-01-2014 14:10:10' &&
log_this_timeout ods-control-enforcer-start $LONG_TIMEOUT ods-enforcerd -1 &&
syslog_waitfor_count $LONG_TIMEOUT 1 'ods-enforcerd: .*all done' &&
syslog_grep "ods-enforcerd: Timeshift mode detected, running once only!" &&

##################  Check the keys ###########################
# Check the output
log_this ods-ksmutil-list-0   date && log_this ods-ksmutil-list-0   ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-list-0   stdout "ZSK[[:space:]]*active" && 
log_grep ods-ksmutil-list-0   stdout "ZSK[[:space:]]*publish" && 
log_grep ods-ksmutil-list-0   stdout "KSK[[:space:]]*dssub" && 
log_grep ods-ksmutil-list-0   stdout "KSK[[:space:]]*publish" &&

################ 1. Import a key using the 'ods-ksmutil key import' command  ###########################################
# You will need to generate a key directly in the hsm using 'ods-hsmutil create'
# then import the key and use 'ods-ksmutil key list --verbose' and check it is available 
log_this ods-hsmutil-generate ods-hsmutil generate SoftHSM rsa 2048 && 
log_grep ods-hsmutil-generate stdout "Key[[:space:]]generation[[:space:]]successful:.*" && 

################ Import a generate key and a retire key. ######################## 
log_this ods-ksmutil-key-import ods-ksmutil key import --cka_id 123456 --repository SoftHSM --bits 2048 --algorithm 5 --keystate 1 --keytype ZSK  --zone ods --time "2014-01-26 14:10:10" &&
log_grep ods-ksmutil-key-import stdout "Warning: No key with the CKA_ID 123456[[:space:]]*exists in the repository SoftHSM. The key will be imported into the database anyway" &&

log_this ods-ksmutil-key-import ods-ksmutil key import --cka_id 1234567 --repository SoftHSM --bits 2048 --algorithm 5 --keystate 5 --keytype ZSK  --zone ods --time "2014-01-26 14:10:10" &&
log_grep ods-ksmutil-key-import stdout "Warning: No key with the CKA_ID 1234567[[:space:]]*exists in the repository SoftHSM. The key will be imported into the database anyway" &&

log_this ods-ksmutil-key-import ods-ksmutil key import --cka_id 12345678 --repository SoftHSM --bits 2048 --algorithm 5 --keystate 4 --keytype ZSK  --zone ods --time "2014-01-26 14:10:10" &&
log_grep ods-ksmutil-key-import stdout "Warning: No key with the CKA_ID 12345678[[:space:]]*exists in the repository SoftHSM. The key will be imported into the database anyway" &&

################ 1. key list --verbose don't contain the generate key. ########################  
log_this ods-ksmutil-key-list-1 ods-ksmutil key list --verbose &&
log_grep ods-ksmutil-key-list-1 stdout "ods[[:space:]]*ZSK[[:space:]]*retire[[:space:]]*(not scheduled)[[:space:]]*(dead)[[:space:]]*2048[[:space:]]*5[[:space:]]*1234567[[:space:]]*SoftHSM NOT IN repository" &&
log_grep ods-ksmutil-key-list-1 stdout "ods[[:space:]]*ZSK[[:space:]]*active[[:space:]]*(not scheduled)[[:space:]]*(retire)[[:space:]]*2048[[:space:]]*5[[:space:]]*12345678[[:space:]]*SoftHSM NOT IN repository" &&
! log_grep ods-ksmutil-key-list-1 stdout "ods[[:space:]]*ZSK[[:space:]]*generate[[:space:]]*(not scheduled)[[:space:]]*(publish)[[:space:]]*2048[[:space:]]*5[[:space:]]*123456[[:space:]]*SoftHSM NOT IN repository" &&
################ 2. key list --all have the generate key. ########################
log_this ods-ksmutil-key-list-2 ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-key-list-2 stdout "ods[[:space:]]*ZSK[[:space:]]*generate[[:space:]]*(not scheduled)[[:space:]]*(publish)[[:space:]]*2048[[:space:]]*5[[:space:]]*123456[[:space:]]*SoftHSM NOT IN repository" &&
################ 3. use the --keystate. ########################
log_this ods-ksmutil-key-list-3 ods-ksmutil key list --keystate generate --verbose &&
log_grep ods-ksmutil-key-list-3 stdout "ods[[:space:]]*ZSK[[:space:]]*generate[[:space:]]*(not scheduled)[[:space:]]*(publish)[[:space:]]*2048[[:space:]]*5[[:space:]]*123456[[:space:]]*SoftHSM NOT IN repository" &&
! log_grep ods-ksmutil-key-list-3 stdout "active" &&
log_this ods-ksmutil-key-list-4 ods-ksmutil key list --keystate active --verbose &&
log_grep ods-ksmutil-key-list-4 stdout "ods[[:space:]]*ZSK[[:space:]]*active[[:space:]]*(not scheduled)[[:space:]]*(retire)[[:space:]]*2048[[:space:]]*5[[:space:]]*12345678[[:space:]]*SoftHSM NOT IN repository" &&
! log_grep ods-ksmutil-key-list-4 stdout "publish" &&
################ 4. However either a keystate or the --all option can be given, not both. ######################## 
! log_this ods-ksmutil-key-list-5 ods-ksmutil key list --keystate generate --all &&
log_grep ods-ksmutil-key-list-5 stdout "Error: --keystate and --all option cannot be given together" &&
################ 5. some of the filters can be used together e.g. ods-ksmutil --keystate active --keytype ZSK ########################
log_this ods-ksmutil-key-list-6 ods-ksmutil key list --verbose --keystate active --keytype ZSK &&
log_grep ods-ksmutil-key-list-6 stdout "ods[[:space:]]*ZSK[[:space:]]*active[[:space:]]*(not scheduled)[[:space:]]*(retire)[[:space:]]*2048[[:space:]]*5[[:space:]]*12345678[[:space:]]*SoftHSM NOT IN repository" &&
! log_grep ods-ksmutil-key-list-6 stdout "KSK" &&
################ 6. start enforcer again. ########################
export ENFORCER_TIMESHIFT='26-01-2014 14:20:20' &&
log_this_timeout ods-control-enforcer-start $LONG_TIMEOUT ods-enforcerd -1 &&
syslog_waitfor_count $LONG_TIMEOUT 2 'ods-enforcerd: .*all done' &&
################ 7. the key which cka_id=1234567 changed to the dead state. ########################
log_this ods-ksmutil-key-list-7 ods-ksmutil key list --verbose &&
! log_grep ods-ksmutil-key-list-7 stdout "ods[[:space:]]*ZSK[[:space:]]*dead[[:space:]]*to be deleted[[:space:]]*(deleted)[[:space:]]*2048[[:space:]]*5[[:space:]]*1234567[[:space:]]*SoftHSM NOT IN repository" &&
log_this ods-ksmutil-key-list-8 ods-ksmutil key list --all --verbose &&
log_grep ods-ksmutil-key-list-8 stdout "ods[[:space:]]*ZSK[[:space:]]*dead[[:space:]]*to be deleted[[:space:]]*(deleted)[[:space:]]*2048[[:space:]]*5[[:space:]]*1234567[[:space:]]*SoftHSM NOT IN repository" &&
log_this ods-ksmutil-key-list-9 ods-ksmutil key list --keystate dead --verbose &&
log_grep ods-ksmutil-key-list-9 stdout "ods[[:space:]]*ZSK[[:space:]]*dead[[:space:]]*to be deleted[[:space:]]*(deleted)[[:space:]]*2048[[:space:]]*5[[:space:]]*1234567[[:space:]]*SoftHSM NOT IN repository" &&
   
############### 8. purge the dead key. ########################
# TODO: there fails because the key does not exist in the HSM. it's better to push a auto-generated ZSK to retire and dead and then purge that
! log_this ods-ksmutil-key-purge ods-ksmutil key purge --zone ods &&
log_grep ods-ksmutil-key-purge stdout "Key not found: 1234567" &&

############## 10. check the key is no longer in the output. #####################
log_this ods-ksmutil-key-list-10 ods-ksmutil key list --all --verbose &&
! log_grep ods-ksmutil-key-list-10 stdout "1234567[[:space:]]*SoftHSM" &&

echo && 
echo "************OK******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1



