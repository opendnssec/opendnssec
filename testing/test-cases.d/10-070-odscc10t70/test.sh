#!/usr/bin/env bash
#
# Test of the PIN storage feature, new in 1.4
# Configure no PIN while PIN is needed, expect failure
# Then login and start everything successfully

ods_reset_env &&

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

# Make sure the PIN is cleared from shared memory
log_this clear-pin "ipcrm -M 0x0d50d5ec"

! log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 10 'ods-enforcerd: .*hsm_check_pin(): No PIN in shared memory. Please login with "ods-hsmutil login"' &&

! log_this_timeout ods-control-signer-start 60 ods-control signer start &&
syslog_waitfor 10 'ods-signerd: .*\[hsm\].*hsm_check_pin(): No PIN in shared memory. Please login with "ods-hsmutil login"' &&

# Now login and expect succes
#log_this ods-hsmutil-login ods-hsmutil login SoftHSM &&

! pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null &&
return 0

ods_kill
return 1
