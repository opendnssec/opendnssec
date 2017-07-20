#!/usr/bin/env bash
#
#TEST: Test to check that key list works correctly

# expect <filepattern> <regexpattern>
# expect that the regular expression pattern is present in at least
# one of the files
expect ()
{
  local name=$1
  local pattern=$2
  echo expecting $2
  cat _log.$BUILD_TAG.$name.stdout | sed -e '/^[[:alpha:]]*:/d' | $GREP  -- "$pattern"
}
# expectbut <filepattern> <regexpattern>
# expect that no other than the regular expression pattern is present in any of
# the files
expectbut ()
{
  local name=$1
  local pattern=$2
  echo expecting-but $2
  cat _log.$BUILD_TAG.$name.stdout | sed -e '/^[[:alpha:]]*:/d' | $GREP  -v -- "$pattern"
}

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

ods_start_enforcer &&

##################  SETUP ###########################
# Add a zone
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-setup_zone_and_keys   ods-enforcer zone add --zone ods --policy default &&
echo -n "LINE: ${LINENO} " && log_this list-first                         ods-enforcer key list --verbose --all &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-setup_zone_and_keys   stdout "Zone ods added successfully" &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-setup_zone_and_keys   ods-enforcer zone list &&
echo -n "LINE: ${LINENO} " && log_grep ods-enforcer-setup_zone_and_keys   stdout "ods[ \t][ \t]*default[ \t]" &&
echo -n "LINE: ${LINENO} " && log_this list-second                        ods-enforcer key list --verbose --all &&
echo -n "LINE: ${LINENO} " && log_this list-third                         ods-enforcer key list --verbose --all &&
echo -n "LINE: ${LINENO} " && log_this list-fourth                        ods-enforcer key list --verbose --all &&
echo -n "LINE: ${LINENO} " && log_this list-fifth                        ods-enforcer key list --verbose --all &&

echo -n "LINE: ${LINENO} " && ods_enforcer_idle &&
echo -n "LINE: ${LINENO} " && ods_timeleap_search_key ods KSK ready &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-cka-id ods-enforcer key list --verbose &&
echo -n "LINE: ${LINENO} " && KSK_CKA_ID=`log_grep -o ods-enforcer-cka-id stdout "ods[[:space:]]*KSK[[:space:]]*ready" | awk '{print $9}'` &&
echo $KSK_CKA_ID &&
#echo -n "LINE: ${LINENO} " && ods-enforcer key ds-seen -z ods -k `ods-enforcer key ds-seen 2>/dev/null | sed -e 's/^ods[[:space:]]\+KSK[[:space:]]\+[[:digit:]]\+[[:space:]]\+\([[:xdigit:]]\{32\}\)[[:space:]]*/\1/p' -e d` &&
echo -n "LINE: ${LINENO} " && ods-enforcer key ds-seen -z ods -k $KSK_CKA_ID &&
echo -n "LINE: ${LINENO} " && ods_enforcer_idle &&

# using --zone you should only get keys for that selected zone
echo -n "LINE: ${LINENO} " && log_this list-ods    ods-enforcer key list --zone ods &&
echo -n "LINE: ${LINENO} " && log_this list-nonods ods-enforcer key list --zone sdo &&
echo -n "LINE: ${LINENO} " && expect list-ods '^ods ' &&
echo -n "LINE: ${LINENO} " && ! expect list-nonods '^ods ' &&

# using --keystate and --all you should get an error
echo -n "LINE: ${LINENO} " && ! log_this list-conflict ods-enforcer key list --keystate publish --all &&

for i in `seq 0 24`; do
  log_this list-$i-zsk              ods-enforcer key list --keytype ZSK &&
  log_this list-$i-ksk              ods-enforcer key list --keytype KSK &&
  log_this list-$i-active           ods-enforcer key list --keystate active &&
  log_this list-$i-activepublish    ods-enforcer key list --keystate active,publish &&
  log_this list-$i-publishzsk       ods-enforcer key list --keystate publish --keytype ZSK &&
  log_this list-$i-generateverbose  ods-enforcer key list --keystate generate --verbose &&
  log_this list-$i-all              ods-enforcer key list --all &&
  log_this list-$i-allzsk           ods-enforcer key list --all --keytype ZSK &&
  log_this list-$i-activezskverbose ods-enforcer key list --verbose --keystate active --keytype ZSK &&
  log_this list-$i-plain ods-enforcer key list &&
  log_this list-$i-verbose ods-enforcer key list --verbose &&
  log_this list-$i-verboseall ods-enforcer key list --verbose --all &&
  log_this list-$i-parsable ods-enforcer key list --parsable &&
  log_this list-$i-debug ods-enforcer key list --debug &&
  sleep 3 && log_this timeleap ods-enforcer time leap && sleep 3
done &&

# When listing ZSKs, we should only see ZSKs, and see a ZSK at least
# once.  Likewise for KSKs of course.
echo -n "LINE: ${LINENO} " && ! expectbut list-*-zsk "ZSK" &&
echo -n "LINE: ${LINENO} " && ! expectbut list-*-ksk "KSK" &&
echo -n "LINE: ${LINENO} " && expect list-*-zsk "ZSK" &&
echo -n "LINE: ${LINENO} " && expect list-*-ksk "KSK" &&

# key list --verbose may not contain keys in state generate
echo -n "LINE: ${LINENO} " && ! expect list-*-verbose "generate" &&
# key list --verbose may not contain keys in state dead
echo -n "LINE: ${LINENO} " && ! expect list-*-verbose "dead" &&

# key list --verbose --all could contain keys in state generate
# TODO without pre-generation of keys it is currently not possible to guarantee
#      that a key in state generate will exist, otherwise we could check it with:
# echo -n "LINE: ${LINENO} " && expect list-*-verboseall "generate" &&

# with --keystate generate --verbose we should not see keys in active state
echo -n "LINE: ${LINENO} " && ! expect list-*-generateverbose "active" &&
# TODO but possible in state generate, without pre-generation of keys it is
#      currently not possible to guarantee that a key in state will exist
#      otherwise we could check it with:
# echo -n "LINE: ${LINENO} " && expect list-*-generateverbose "generate" &&

# with --keystate active we should not see keys in publish state
echo -n "LINE: ${LINENO} " && ! expect list-*-active "publish" &&

# it is valid to use --verbose --keystate active --keytype ZSK
echo -n "LINE: ${LINENO} " && expect list-*-activezskverbose "ZSK" &&
echo -n "LINE: ${LINENO} " && expect list-*-activezskverbose "active" &&
# this should not list KSK keys and show at least once a ZSK in active state
# this should list only active, zsk keys
echo -n "LINE: ${LINENO} " && ! expectbut list-*-activezskverbose "ZSK" &&
echo -n "LINE: ${LINENO} " && ! expectbut list-*-activezskverbose "active" &&

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
