#!/usr/bin/env bash

#TEST: Start and stop using ods-control and default conf files. Check the deamons behave.

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

ods_start_ods-control &&
ods_stop_ods-control &&

ods-enforcer start &&
ods-enforcer stop &&
ods-enforcer start &&
ods-enforcer stop &&

ods-signer start &&
ods-signer stop &&
ods-signer start &&
ods-signer sign --all &&
ods-signer stop &&

return 0

ods_kill
return 1
