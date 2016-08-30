#!/usr/bin/env bash

#TEST: Start and stop using ods-control and default conf files. Check the deamons behave.

ods_reset_env &&

ods_start_ods-control &&
ods_stop_ods-control &&

ods-enforcer start &&
ods-enforcer zone add -z ods &&
ods-enforcer stop &&
ods-enforcer start &&
ods-enforcer stop &&

return 0

ods_kill
return 1
