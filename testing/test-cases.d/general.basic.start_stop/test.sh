#!/usr/bin/env bash

#TEST: Start and stop using ods-control and default conf files. Check the deamons behave.

ods_reset_env &&

ods_start_ods-control &&
ods_stop_ods-control &&

return 0

ods_kill
return 1
