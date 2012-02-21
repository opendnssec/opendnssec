#!/usr/bin/env bash
#
# Configure no module location and expect failure

ods_reset_env &&

log_this ods-control-start ods-control start &&
syslog_waitfor 2 'ods-enforcerd: .*PKCS#11 module load failed: '"$INSTALL_ROOT/var/libsofthsm.so" &&
syslog_grep 'ods-signerd: .*\[hsm\].*PKCS#11 module load failed: '"$INSTALL_ROOT/var/libsofthsm.so" &&
return 0

ods_kill
return 1
