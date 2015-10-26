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

ods_ods-control_enforcer_start &&

##################  SETUP ###########################
# Add a zone
log_this ods-enforcer-setup_zone_and_keys   ods-enforcer zone add --zone ods --policy Policy1 &&
log_grep ods-enforcer-setup_zone_and_keys   stdout "Zone ods added successfully" &&
log_this ods-enforcer-setup_zone_and_keys   ods-enforcer zone list &&
log_grep ods-enforcer-setup_zone_and_keys   stdout "ods[ \t][ \t]*Policy1[ \t]" &&

ods_enforcer_idle &&
ods_enforcer_leap_over 900 &&
echo `ods-enforcer key ds-seen 2>/dev/null | sed -e 's/^ods[[:space:]]\+KSK[[:space:]]\+[[:digit:]]\+[[:space:]]\+\([[:xdigit:]]\{32\}\)[[:space:]]*/\1/p' -e d` &&
ods-enforcer key ds-seen -z ods -k `ods-enforcer key ds-seen 2>/dev/null | sed -e 's/^ods[[:space:]]\+KSK[[:space:]]\+[[:digit:]]\+[[:space:]]\+\([[:xdigit:]]\{32\}\)[[:space:]]*/\1/p' -e d` &&
ods_enforcer_idle &&

echo -n "LINE: ${LINENO} " && log_this list-ods           ods-enforcer key list --zone ods &&
echo -n "LINE: ${LINENO} " && log_this list-nonods        ods-enforcer key list --zone ods &&
echo -n "LINE: ${LINENO} " && log_this list-zsk           ods-enforcer key list --keytype ZSK &&
echo -n "LINE: ${LINENO} " && log_this list-ksk           ods-enforcer key list --keytype KSK &&
echo -n "LINE: ${LINENO} " && log_this list-active        ods-enforcer key list --keystate active &&
echo -n "LINE: ${LINENO} " && log_this list-activepublish ods-enforcer key list --keystate active,publish &&
echo -n "LINE: ${LINENO} " && log_this list-publishzsk    ods-enforcer key list --keystate publish --keytype ZSK &&
echo -n "LINE: ${LINENO} " && log_this list-all           ods-enforcer key list --all &&
echo -n "LINE: ${LINENO} " && log_this list-allzsk        ods-enforcer key list --all --keytype ZSK &&

i=0 &&
while [ $i -lt 25 ]; do
  log_this list-$i ods-enforcer key list --verbose &&
  log_this list-$i ods-enforcer time leap &&
  i=`expr $i + 1`
done &&

ods_ods-control_enforcer_stop &&

echo && 
echo "************OK******************" &&
echo &&
return 0

echo
echo "************ERROR******************"
echo
ods_kill
return 1
