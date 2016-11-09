#!/usr/bin/env bash

#TEST: Stresstest OpenDNSSEC: Many notifies and no updates may go missing.

PATH=$PATH:/usr/sbin

# Start with some BIND9 config
BIND9_TEST_ROOTDIR=`pwd`
BIND9_NAMED_CONFDIR=$BIND9_TEST_ROOTDIR/bind9
BIND9_NAMED_RUNDIR=$BIND9_TEST_ROOTDIR/bind9
BIND9_NAMED_PIDFILE=$BIND9_NAMED_RUNDIR/named.pid
BIND9_NAMED_PORT=10053
BIND9_NAMED_RNDC_PORT=10953
BIND9_NAMED_CONF=$BIND9_NAMED_CONFDIR/named.conf

if named -V | grep -q "^BIND 9.8.2rc1-RedHat" ; then
	# This test will fail on old, no longer in LTS RedHat version
	# that cannot be updated.  The bind actually core dumps
	return 0
fi

case "$DISTRIBUTION" in
	redhat|suse )
		append_path /usr/sbin
		;;
esac

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

## Start master name server
cp ods $BIND9_NAMED_RUNDIR/ods
ods_bind9_info &&
ods_bind9_start &&

## Start OpenDNSSEC
ods_start_ods-control &&

## Send updates
ods_bind9_dynupdate 100 10000 ods &&

## Stop
ods_stop_ods-control &&
ods_bind9_stop &&
rm -f $BIND9_NAMED_RUNDIR/bind.log &&
rm -f $BIND9_NAMED_RUNDIR/update.txt &&
rm -f $BIND9_NAMED_RUNDIR/update.log &&
rm -f $BIND9_NAMED_RUNDIR/ods.jnl &&
return 0

## Test failed. Kill stuff
ods_bind9_stop || ods_process_kill '(named)'
rm -f $BIND9_NAMED_RUNDIR/bind.log
rm -f $BIND9_NAMED_RUNDIR/ods.jnl
rm -f $BIND9_NAMED_PIDFILE
ods_kill
return 1
