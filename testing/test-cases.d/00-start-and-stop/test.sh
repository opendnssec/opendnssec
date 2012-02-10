#!/usr/bin/env bash

ods_reset_env &&
log_this ods-control-start ods-control start &&
log_grep ods-control-start stdout 'OpenDNSSEC ods-enforcerd started' &&
log_grep ods-control-start stdout 'Engine running' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&
syslog_grep 'ods-enforcerd: .*Sleeping for' &&
log_this ods-control-stop ods-control stop &&
log_grep ods-control-stop stdout 'Engine shut down' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
syslog_grep 'ods-enforcerd: .*all done' &&
return

ods-control stop
return 1
