#!/usr/bin/env bash

#TEST: Use a simple script as NotifyCommand and check if it is executed after signing


cat >"$INSTALL_ROOT/var/opendnssec/signer/test-notify-command.sh" 2>/dev/null <<"EOF"
#!/usr/bin/env bash

echo "zone: $1 zonefile: $2" >`dirname "$0"`/test-notify.output
EOF

if [ -n "$HAVE_MYSQL" ]; then
	ods_setup_conf conf.xml conf-mysql.xml
fi &&

test -f "$INSTALL_ROOT/var/opendnssec/signer/test-notify-command.sh" &&
chmod a+x "$INSTALL_ROOT/var/opendnssec/signer/test-notify-command.sh" &&

ods_reset_env 20 &&

ods_start_ods-control && 

syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&
test -f "$INSTALL_ROOT/var/opendnssec/signed/ods" &&

ods_stop_ods-control && 

test -f "$INSTALL_ROOT/var/opendnssec/signer/test-notify.output" &&
$GREP -q -- "zone: ods zonefile: $INSTALL_ROOT/var/opendnssec/signed/ods" "$INSTALL_ROOT/var/opendnssec/signer/test-notify.output" &&
rm "$INSTALL_ROOT/var/opendnssec/signer/test-notify-command.sh" "$INSTALL_ROOT/var/opendnssec/signer/test-notify.output" &&
return 0

ods_kill
return 1
