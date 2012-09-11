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
log_this clear-pin "ipcrm -M 0x0d50d5ec" &&

! log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 10 'ods-enforcerd: .*hsm_check_pin(): No PIN in shared memory. Please login with "ods-hsmutil login"' &&

! log_this_timeout ods-control-signer-start 60 ods-control signer start &&
syslog_waitfor 10 'ods-signerd: .*\[hsm\].*hsm_check_pin(): No PIN in shared memory. Please login with "ods-hsmutil login"' &&

! pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null &&

# Now login and expect succes

# Problems using a pipe in the log_this command so doing it directly for now...
log_this ods-hsmutil-login echo "Logging in with PIN...." &&
echo "1234" | ods-hsmutil login && 
log_this ods-hsmutil-login echo "Successfully logged in" &&
#log_this ods-hsmutil-login 'echo "1234" | ods-hsmutil login'  &&
#log_grep ods-hsmutil-login stdout "Enter PIN for token SoftHSM:" && 
#log_grep ods-hsmutil-login stdout "The tokens are now logged in." &&

log_this_timeout ods-control-start 60 ods-control start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

log_this_timeout ods-control-stop 60 ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' && 
return 0

ods_kill
return 1
