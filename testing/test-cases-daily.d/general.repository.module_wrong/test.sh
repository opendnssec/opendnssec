#!/usr/bin/env bash

#TEST: Configure wrong repository module location and expect failure 

#TODO: Merge with 10-030 (fail_no_module)?

ods_reset_env &&

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql-no-module.xml
else
	ods_setup_conf conf.xml conf-no-module.xml
fi &&

! ods_start_enforcer &&
syslog_waitfor 10 'ods-enforcerd: .*PKCS#11 module load failed: '"$INSTALL_ROOT/var/libsofthsm2.so" &&

! ods_start_signer &&
syslog_waitfor 10 'ods-signerd: .*\[hsm\].*PKCS#11 module load failed: '"$INSTALL_ROOT/var/libsofthsm2.so" &&

! pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null &&
return 0

ods_kill
return 1
