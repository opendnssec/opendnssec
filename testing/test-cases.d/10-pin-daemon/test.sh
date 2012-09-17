#!/usr/bin/env bash
#
# Test of the PIN storage feature, new in 1.4
# Configure no PIN while PIN is needed, expect failure
# Then login and start everything successfully

# Make sure the PIN is cleared from shared memory
# try key as hex and int, ignore results
log_this clear-pin-hex ipcrm -M 0x0d50d5ec
log_this clear-pin-int ipcrm -M 223401452

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

# Make sure the login fails 
! echo "123" | log_this ods-hsmutil-login-fail ods-hsmutil login &&
log_grep ods-hsmutil-login-fail stderr 'hsm_session_init(): Incorrect PIN for repository SoftHSM' &&

! log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 10 'ods-enforcerd: .*hsm_check_pin(): No PIN in shared memory. Please login with "ods-hsmutil login"' &&

! log_this_timeout ods-control-signer-start 60 ods-control signer start &&
syslog_waitfor 10 'ods-signerd: .*\[hsm\].*hsm_check_pin(): No PIN in shared memory. Please login with "ods-hsmutil login"' &&

! pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null &&

# Now login and expect success
echo "1234" | log_this ods-hsmutil-login ods-hsmutil login && 
log_grep ods-hsmutil-login stdout 'The tokens are now logged in.' &&

log_this_timeout ods-control-start 60 ods-control start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

log_this_timeout ods-control-stop 60 ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' && 
return 0

ods_kill
return 1
