#!/usr/bin/env bash

#TEST: Start and stop using ods-control and default conf files. Check the deamons behave.

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&
echo -n "LINE: ${LINENO} " && ods_reset_env &&

echo -n "LINE: ${LINENO} " && ods_start_ods-control &&
echo -n "LINE: ${LINENO} " && ods_stop_ods-control &&

echo -n "LINE: ${LINENO} " && log_this ods-enforcer-start ods-enforcer start &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-stop ods-enforcer stop &&
echo -n "LINE: ${LINENO} " && log_this ods-enforcer-start ods-enforcer start &&

echo -n "LINE: ${LINENO} " && log_this ods-signer-start ods-signer start &&
echo -n "LINE: ${LINENO} " && log_this ods-signer-stop ods-signer stop &&
echo -n "LINE: ${LINENO} " && log_this ods-signer-start ods-signer start &&

echo -n "LINE: ${LINENO} " && log_this ods-control-stop ods-control stop &&
echo -n "LINE: ${LINENO} " && log_this ods-control-start ods-control start &&
echo -n "LINE: ${LINENO} " && log_this ods-control-stop ods-control stop &&
return 0

ods_kill
return 1
