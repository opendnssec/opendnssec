#!/usr/bin/env bash
#
# Set logging to a invalid channel and expect failure

! ods_reset_env &&
log_grep ods-ksmutil-setup stdout 'Error validating file' &&
log_grep ods-ksmutil-setup stderr 'element Facility: Relax-NG validity error : Error validating value' &&
log_grep ods-ksmutil-setup stderr 'element Facility: Relax-NG validity error : Element Facility failed to validate content' &&

ods_setup_conf conf.xml conf-correct.xml &&
ods_reset_env &&
ods_setup_conf conf.xml conf.xml &&

log_this ods-control-start ods-control start &&
syslog_waitfor 60 'ods-enforcerd: .*Error validating file' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

syslog_grep 'ods-enforcerd: .*Error validating value' &&
syslog_grep 'ods-enforcerd: .*Element Facility failed to validate content' &&

log_this ods-control-stop ods-control stop &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
return 0

ods_kill
return 1
