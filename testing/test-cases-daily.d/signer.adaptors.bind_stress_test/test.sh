#!/usr/bin/env bash

#TEST: Stresstest OpenDNSSEC: Many notifies and no updates may go missing.

# Start with some BIND9 config
BIND9_TEST_ROOTDIR=`pwd`
BIND9_NAMED_CONFDIR=$BIND9_TEST_ROOTDIR/bind9
BIND9_NAMED_RUNDIR=$BIND9_TEST_ROOTDIR/bind9
BIND9_NAMED_PIDFILE=$BIND9_NAMED_RUNDIR/named.pid
BIND9_NAMED_PORT=10053
BIND9_NAMED_RNDC_PORT=10953
BIND9_NAMED_CONF=$BIND9_NAMED_CONFDIR/named.conf

case "$DISTRIBUTION" in
	redhat )
		append_path /usr/sbin
		;;
esac

case "$DISTRIBUTION" in
        redhat )

		if [ -n "$HAVE_MYSQL" ]; then
		        ods_setup_conf conf.xml conf-mysql.xml
		fi &&

		ods_reset_env &&

		## Start master name server
		cp $BIND9_NAMED_RUNDIR/ods.bak $BIND9_NAMED_RUNDIR/ods
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
		rm -f $BIND9_NAMED_RUNDIR/ods &&
		return 0

		## Test failed. Kill stuff
		ods_bind9_stop || ods_process_kill '(named)'
		rm -f $BIND9_NAMED_RUNDIR/bind.log
		rm -f $BIND9_NAMED_RUNDIR/ods.jnl
		rm -f $BIND9_NAMED_RUNDIR/ods
		rm -f $BIND9_NAMED_PIDFILE
		ods_kill
		return 1
		;;
esac

# This test is only ran on redhat
return 0



