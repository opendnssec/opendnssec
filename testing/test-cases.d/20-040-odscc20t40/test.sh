#!/usr/bin/env bash
#
# Change the zonelist.xml location and change ZoneListFile in conf.xml accordingly

ods_reset_env &&

ods_setup_conf conf.xml conf2.xml &&
mv -- "$INSTALL_ROOT/etc/opendnssec/zonelist.xml" "$INSTALL_ROOT/etc/opendnssec/zonelist2.xml" &&

log_this ods-control-start ods-control start &&
syslog_waitfor 60 'ods-enforcerd: .*Sleeping for' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer started' &&

log_this ods-control-stop ods-control stop &&
syslog_waitfor 60 'ods-enforcerd: .*all done' &&
syslog_waitfor 60 'ods-signerd: .*\[engine\] signer shutdown' &&
return 0

ods_kill
return 1
