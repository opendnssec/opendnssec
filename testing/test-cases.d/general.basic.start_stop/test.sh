#!/usr/bin/env bash

#TEST: Start and stop using ods-control and default conf files. Check the deamons behave.

ods_reset_env &&

ods_start_ods-control &&
ods_stop_ods-control &&

log_this ods-enforcer-start ods-enforcer start &&
log_this ods-enforcer-stop ods-enforcer stop &&
log_this ods-enforcer-start ods-enforcer start &&

log_this ods-signer-start ods-signer start &&
log_this ods-signer-stop ods-signer stop &&
log_this ods-signer-start ods-signer start &&

log_this ods-control-stop ods-control stop &&
log_this ods-control-start ods-control start &&
log_this ods-control-stop ods-control stop &&
return 0

cat _log.$BUILD_TAG.ods-enforcer-start.stdout
cat _log.$BUILD_TAG.ods-enforcer-start.stderr
cat _log.$BUILD_TAG.ods-signer-start.stdout
cat _log.$BUILD_TAG.ods-signer-start.stderr
cat _log.$BUILD_TAG.ods-control-start.stdout
cat _log.$BUILD_TAG.ods-control-start.stderr
ods_kill
return 1
