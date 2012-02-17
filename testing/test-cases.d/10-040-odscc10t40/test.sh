#!/usr/bin/env bash
#
# Configure no module location and expect failure

log_this ods-control-start ods-control start &&
log_grep ods-control-start stdout 'Could not start enforcer' &&
log_grep ods-control-start stdout 'Could not start signer' &&
syslog_grep 'ods-signerd: .*\[engine\].*PKCS#11 module load failed: '"$INSTALL_ROOT/var/libsofthsm.so" &&
syslog_grep 'ods-enforcerd: .*PKCS#11 module load failed: '"$INSTALL_ROOT/var/libsofthsm.so" &&
return

ods_kill
return 1
