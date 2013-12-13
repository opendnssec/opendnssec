#!/usr/bin/env bash

#TEST: Test of the PIN storage feature, new in 1.4
#TEST: Configure no PIN while PIN is needed, expect failure
#TEST: Then login and start everything successfully

#DISABLED: ON SOLARIS due to unreproducible core dump when
#DISABLED: running on the sparc64 box. !Needs investigating!        

case "$DISTRIBUTION" in
	sunos )
		return 0
		;;
esac


# Make sure the PIN is cleared from shared memory
log_this clear-pin ods-hsmutil logout

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

ods_start_ods-control &&
ods_stop_ods-control &&
return 0

ods_kill
return 1
