#!/usr/bin/env bash
#
# Configure no module location and expect failure

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

! log_this ods-control-start ods-control start &&
syslog_waitfor 10 'ods-enforcerd: .*PKCS#11 module load failed: '"$INSTALL_ROOT/var/libsofthsm.so" &&
syslog_waitfor 10 'ods-signerd: .*\[hsm\].*PKCS#11 module load failed: '"$INSTALL_ROOT/var/libsofthsm.so" &&
! pgrep '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null &&
return 0

ods_kill
return 1
