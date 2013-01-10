#!/usr/bin/env bash

#TEST: Configure no repository module location and expect failure 

#CATEGORY: general-repository-fail_no_module

ods_reset_env &&

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql-no-module.xml
else
	ods_setup_conf conf.xml conf-no-module.xml
fi &&

! log_this_timeout ods-control-enforcer-start 60 ods-control enforcer start &&
syslog_waitfor 10 'ods-enforcerd: .*PKCS#11 module load failed' &&

! log_this_timeout ods-control-signer-start 60 ods-control signer start &&
syslog_waitfor 10 'ods-signerd: .*\[hsm\].*PKCS#11 module load failed' &&

! pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null &&
return 0

ods_kill
return 1
