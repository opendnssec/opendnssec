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
echo -n "LINE: ${LINENO} " && log_this clear-pin ods-hsmutil logout

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

echo -n "LINE: ${LINENO} " && ods_reset_env_noenforcer &&

# Make sure the login fails 
echo -n "LINE: ${LINENO} " && ! echo "123" | log_this ods-hsmutil-login-fail ods-hsmutil login &&
echo -n "LINE: ${LINENO} " && log_grep ods-hsmutil-login-fail stderr 'hsm_session_init(): Incorrect PIN for repository SoftHSM' &&

echo -n "LINE: ${LINENO} " && ! log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
echo -n "LINE: ${LINENO} " && #syslog_waitfor 10 'ods-enforcerd: .*hsm_check_pin(): No PIN in shared memory. Please login with "ods-hsmutil login"' &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 10 'ods-enforcerd: .*\[engine\] hsm_session_init(): Incorrect PIN for repository SoftHSM' &&

echo -n "LINE: ${LINENO} " && ! log_this_timeout ods-control-signer-start 60 ods-control signer start &&
echo -n "LINE: ${LINENO} " && syslog_waitfor 10 'ods-signerd: .*hsm_check_pin(): No PIN in shared memory. Please login with "ods-hsmutil login"' &&

echo -n "LINE: ${LINENO} " && ! pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null &&

echo -n "LINE: ${LINENO} " && # Now login and expect success
echo -n "LINE: ${LINENO} " && echo "1234" | log_this ods-hsmutil-login ods-hsmutil login && 
echo -n "LINE: ${LINENO} " && log_grep ods-hsmutil-login stdout 'The tokens are now logged in.' &&

echo -n "LINE: ${LINENO} " && ods_start_ods-control &&
echo -n "LINE: ${LINENO} " && ods_stop_ods-control &&
return 0

ods_kill
return 1
