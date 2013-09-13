#!/usr/bin/env bash

#TEST: Start, sign a single zone with one repository, stop.
#TEST: On redhat, also perform basic validation of the zone with validns

# So we can use validns 0.7 it is installed from source so need to
# specify this path

case "$DISTRIBUTION" in
        redhat )
                append_path /usr/sbin
                ;;
esac

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env 20 && 

ods_start_ods-control &&

syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

# Validate the output on redhat
# case "$DISTRIBUTION" in
#         redhat )
#                 log_this validate-zone-ods validns -s -p all "$INSTALL_ROOT/var/opendnssec/signed/ods" &&
#                 log_grep validate-zone-ods stdout 'validation errors:   0'
#                 ;;
# esac &&

ods_stop_ods-control &&
return 0

ods_kill
return 1