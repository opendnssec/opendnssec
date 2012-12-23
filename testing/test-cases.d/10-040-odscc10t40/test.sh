#!/usr/bin/env bash

#TEST: Configure wrong repository module location and expect failure 

#CATEGORY: general-repository-fail_wrong_module

#TODO: Merge with 10-030 (fail_no_module)?

ods_reset_env &&

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql-no-module.xml
else
	ods_setup_conf conf.xml conf-no-module.xml
fi &&

! log_this_timeout ods-control-enforcer-start 30 ods-control enforcer start &&
syslog_waitfor 10 'ods-enforcerd: .*PKCS#11 module load failed: '"$INSTALL_ROOT/var/libsofthsm.so" &&

! log_this_timeout ods-control-signer-start 30 ods-control signer start &&
syslog_waitfor 10 'ods-signerd: .*\[hsm\].*PKCS#11 module load failed: '"$INSTALL_ROOT/var/libsofthsm.so" &&

! pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null &&
return 0

ods_kill
return 1
