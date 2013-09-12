#!/usr/bin/env bash

## Test basic Output DNS Adapter
## Start OpenDNSsEC, see if NOTIFY messages are send and accepted.

#TEST: Test basic Output DNS Adapter
#TEST: Start OpenDNSSEC and see if zone gets transferred and signed to Bind,
#TEST: and see if NOTIFY messages are sent and accepted.

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

		## Wait for signed zone file
		syslog_waitfor 60 'ods-signerd: .*\[STATS\] ods' &&

		## Transfer should not take more than 60 seconds
		sleep 60 &&

		## SOA query to Bind
		log_this_timeout soa 10 drill -p 10053 @127.0.0.1 soa ods &&
		log_grep soa stdout 'ods\..*3600.*IN.*SOA.*ns1\.ods\..*postmaster\.ods\..*1001.*1200.*180.*1209600.*3600' &&
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
                rm -f $BIND9_NAMED_RUNDIR/ods.jnl
                rm -f $BIND9_NAMED_RUNDIR/ods
                rm -f $BIND9_NAMED_PIDFILE
                ods_kill
                return 1
                ;;
esac

# This test is only ran on redhat
return 0
