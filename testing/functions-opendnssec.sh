#!/usr/bin/env bash

ods_pre_test ()
{
	ods_nuke_env &&
	ods_setup_conf &&
	ods_setup_zone &&
	return 0
	
	return 1
}

ods_post_test ()
{
	true
}

ods_nuke_env ()
{
	local kasp_files=`cd "$INSTALL_ROOT/var/opendnssec/" && ls kasp*db* 2>/dev/null`
	local tmp_files=`ls "$INSTALL_ROOT/var/opendnssec/tmp/" 2>/dev/null`
	local unsigned_files=`ls "$INSTALL_ROOT/var/opendnssec/unsigned/" 2>/dev/null`
	local signed_files=`ls "$INSTALL_ROOT/var/opendnssec/signed/" 2>/dev/null`
	local signconf_files=`ls "$INSTALL_ROOT/var/opendnssec/signconf/" 2>/dev/null`
	local softhsm_files=`ls "$INSTALL_ROOT/var/softhsm/" 2>/dev/null`
	
	if [ -n "$kasp_files" ]; then
		(
			cd "$INSTALL_ROOT/var/opendnssec/" &&
			rm -rf -- $kasp_files 2>/dev/null
		)
	fi &&
	if [ -n "$tmp_files" ]; then
		(
			cd "$INSTALL_ROOT/var/opendnssec/tmp/" &&
			rm -rf -- $tmp_files 2>/dev/null
		)
	fi &&
	if [ -n "$unsigned_files" ]; then
		(
			cd "$INSTALL_ROOT/var/opendnssec/unsigned/" &&
			rm -f -- $unsigned_files 2>/dev/null
		)
	fi &&
	if [ -n "$signed_files" ]; then
		(
			cd "$INSTALL_ROOT/var/opendnssec/signed/" &&
			rm -f -- $signed_files 2>/dev/null
		)
	fi &&
	if [ -n "$signconf_files" ]; then
		(
			cd "$INSTALL_ROOT/var/opendnssec/signconf/" &&
			rm -f -- $signconf_files 2>/dev/null
		)
	fi &&
	if [ -n "$softhsm_files" ]; then
		(
			cd "$INSTALL_ROOT/var/softhsm/" &&
			rm -f -- $softhsm_files 2>/dev/null
		)
	fi &&
	return 0
	
	return 1
}

ods_setup_conf ()
{
	local conf="$1"
	local file="$2"
	local conf_file
	
	if [ -n "$conf" ]; then
		case "$conf" in
			softhsm.conf | addns.xml | conf.xml | kasp.xml | zonelist.xml )
				;;
			* )
				echo "ods_setup_conf: Unknown conf file specified: $conf" >&2
				return 1
				;;
		esac
	fi
	
	if [ -n "$file" -a ! -f "$file" ]; then
		echo "ods_setup_conf: Conf file $file does not exist" >&2
		return 1
	fi

	# Conf files under /etc	
	for conf_file in softhsm.conf; do
		if [ -n "$conf" -a "$conf" != "$conf_file" ]; then
			continue
		fi

		if [ -n "$file" ]; then
			if ! cp -- "$file" "$INSTALL_ROOT/etc/$conf_file" 2>/dev/null; then
				echo "ods_setup_conf: unable to copy/install test specific $file to $INSTALL_ROOT/etc/$conf_file" >&2
				return 1
			fi
		elif [ -f "$conf_file" ]; then
			if ! cp -- "$conf_file" "$INSTALL_ROOT/etc/$conf_file" 2>/dev/null; then
				echo "ods_setup_conf: unable to copy/install test specific $conf_file to $INSTALL_ROOT/etc/$conf_file" >&2
				return 1
			fi
		else
			if ! cp -- "$INSTALL_ROOT/etc/$conf_file.build" "$INSTALL_ROOT/etc/$conf_file" 2>/dev/null; then
				echo "ods_setup_conf: unable to copy/install build default $INSTALL_ROOT/etc/$conf_file.build to $INSTALL_ROOT/etc/$conf_file" >&2
				return 1
			fi
		fi
		
		apply_parameter "INSTALL_ROOT" "$INSTALL_ROOT" "$INSTALL_ROOT/etc/$conf_file" ||
		return 1
	done

	# Conf files under /etc/opendnssec
	for conf_file in addns.xml conf.xml kasp.xml zonelist.xml; do
		if [ -n "$conf" -a "$conf" != "$conf_file" ]; then
			continue
		fi
		
		if [ -n "$file" ]; then
			if ! cp -- "$file" "$INSTALL_ROOT/etc/opendnssec/$conf_file" 2>/dev/null; then
				echo "ods_setup_conf: unable to copy/install test specific $file to $INSTALL_ROOT/etc/opendnssec/$conf_file" >&2
				return 1
			fi
		elif [ -f "$conf_file" ]; then
			if ! cp -- "$conf_file" "$INSTALL_ROOT/etc/opendnssec/$conf_file" 2>/dev/null; then
				echo "ods_setup_conf: unable to copy/install test specific $conf_file to $INSTALL_ROOT/etc/opendnssec/$conf_file" >&2
				return 1
			fi
		else
			if ! cp -- "$INSTALL_ROOT/etc/opendnssec/$conf_file.build" "$INSTALL_ROOT/etc/opendnssec/$conf_file" 2>/dev/null; then
				echo "ods_setup_conf: unable to copy/install build default $INSTALL_ROOT/etc/opendnssec/$conf_file.build to $INSTALL_ROOT/etc/opendnssec/$conf_file" >&2
				return 1
			fi
		fi
		
		apply_parameter "INSTALL_ROOT" "$INSTALL_ROOT" "$INSTALL_ROOT/etc/opendnssec/$conf_file" &&
		apply_parameter "SOFTHSM_MODULE" "$SOFTHSM_MODULE" "$INSTALL_ROOT/etc/opendnssec/$conf_file" ||
		return 1
	done
	
	return 0
}

ods_setup_zone ()
{
	local zone="$1"
	
	if [ -n "$zone" -a ! -f "$zone" ]; then
		echo "ods_setup_zone: Zone file $zone does not exist" >&2
		return 1
	fi
	
	if [ -n "$zone" ]; then
		if ! cp -- "$zone" "$INSTALL_ROOT/var/opendnssec/unsigned/" 2>/dev/null; then
			echo "ods_setup_zone: unable to copy/install zone file $zone to $INSTALL_ROOT/var/opendnssec/unsigned/" >&2
			return 1
		fi
		
		return 0
	fi
	
	if [ -d unsigned ]; then
		ls -1 unsigned/ | while read zone; do
			if [ -f "unsigned/$zone" ]; then
				if ! cp -- "unsigned/$zone" "$INSTALL_ROOT/var/opendnssec/unsigned/" 2>/dev/null; then
					echo "ods_setup_zone: unable to copy/install zone file $zone to $INSTALL_ROOT/var/opendnssec/unsigned/" >&2
					return 1
				fi
			fi
		done
	fi
	
	return 0
}

ods_reset_env ()
{
	echo "ods_reset_env: resetting opendnssec environment"
	
	ods_softhsm_init_token 0 &&
	echo "y" | log_this "ods-ksmutil-setup" ods-ksmutil setup &&
	return 0
	
	return 1
}

ods_process_kill ()
{
	if [ -z "$1" ]; then
		echo "usage: ods_process_kill <pgrep syntax>" >&2
		exit 1
	fi
	
	local process="$1"
	
	if pgrep -u `id -u` "$process" >/dev/null 2>/dev/null; then
		sleep 2
		pkill -QUIT "$process" 2>/dev/null
		if pgrep -u `id -u` "$process" >/dev/null 2>/dev/null; then
			sleep 2
			pkill -TERM "$process" 2>/dev/null
			if pgrep -u `id -u` "$process" >/dev/null 2>/dev/null; then
				sleep 2
				pkill -KILL "$process" 2>/dev/null
				pgrep -u `id -u` "$process" >/dev/null 2>/dev/null &&
				sleep 2
			fi
		fi
	fi

	if pgrep -u `id -u` "$process" >/dev/null 2>/dev/null; then
		echo "process_kill: Tried to kill $process some are still alive!" >&2
		return 1
	fi

	return 0
}

ods_kill ()
{
	local process='(ods-enforcerd|ods-signerd)'

	if ! pgrep -u `id -u` "$process" >/dev/null 2>/dev/null; then
		return 0
	fi

	echo "ods_kill: Killing OpenDNSSEC"
	try_run 15 ods-control stop

	ods_process_kill "$process" && return 0
	echo "ods_kill: Killing OpenDNSSEC failed"
	return 1
}

ods_ldns_testns_kill ()
{
	local process='(ldns-testns)'

	if ! pgrep -u `id -u` "$process" >/dev/null 2>/dev/null; then
		return 0
	fi

	ods_process_kill "$process" && return 0
	echo "ods_ldns_testns_kill: Killing ldns-testns failed"
	return 1
}

ods_softhsm_init_token ()
{
	if [ -z "$1" ]; then
		echo "usage: ods_softhsm_init_token <slot> [label] [pin] [so-pin]" >&2
		exit 1
	fi

	local slot="$1"
	local label="$2"
	local pin="$3"
	local so_pin="$4"
	
	if [ -z "$label" ]; then
		label=OpenDNSSEC
	fi
	if [ -z "$pin" ]; then
		pin=1234
	fi
	if [ -z "$so_pin" ]; then
		so_pin=1234
	fi
	
	if [ "$slot" -ge 0 -a "$slot" -lt 20 ] 2>/dev/null; then
		log_remove "softhsm-init-token-$slot" &&
		log_this "softhsm-init-token-$slot" softhsm --init-token --slot "$slot" --label "$label" --pin "$pin" --so-pin "$so_pin" ||
		return 1
		
		if ! log_grep "softhsm-init-token-$slot" stdout "The token has been initialized."; then
			return 1
		fi
	else
		echo "ods_softhsm_init_token: Slot $slot invalid, must be integer between 0 and 20" >&2
		exit 1
	fi
	
	return 0
}

ods_find_softhsm_module ()
{
	local path
	
	for path in lib64/softhsm lib/softhsm lib64 lib; do
		if [ -f "$INSTALL_ROOT/$path/libsofthsm.so" ]; then
			export SOFTHSM_MODULE="$INSTALL_ROOT/$path/libsofthsm.so"
			return 0
		fi
	done
	
	return 1
}

ods_ldns_testns ()
{
	if [ -z "$1" -o -z "$2" ]; then
		echo "usage: ods_ldns_testns <port> <data file>" >&2
		exit 1
	fi
	
	local port="$1"
	local datafile="$2"

	log_init ldns-testns
	
	echo "ods_ldns_testns: starting ldns-testns port $port data file $datafile"
	log_this ldns-testns ldns-testns -v -p "$port" "$datafile" &
	
	if log_waitfor ldns-testns stdout 5 "Listening on port"; then
		return 0
	fi

	echo "ods_ldns_testns: unable to start ldns-testns"
	ods_ldns_testns_kill
	return 1
}


# These functions depend on environment variables:
# BIND9_NAMED_CONF
# BIND9_NAMED_CONFDIR
# BIND9_NAMED_PIDFILE
# BIND9_NAMED_PORT
# BIND9_NAMED_RNDC_PORT
# BIND9_TEST_ROOTDIR

ods_bind9_start ()
{
	local username=jenkins
	local named_pid
	local exit_code
	
	if [ -z "$BIND9_NAMED_PIDFILE" -o -z "$BIND9_NAMED_PORT" -o -z "$BIND9_NAMED_CONF" ]; then
		echo "ods_bind9_start: one or more required environment variables missing: BIND9_NAMED_PIDFILE BIND9_NAMED_PORT BIND9_NAMED_CONF" >&2
		return 1
	fi

	# check pidfile
	if [ -f "$BIND9_NAMED_PIDFILE" ]; then
		echo "ods_bind9_start: cannot start named, another process still running ($BIND9_NAMED_PIDFILE exists)" >&2
		return 1
	fi

	# start named
	echo "ods_bind9_start: starting named -p $BIND9_NAMED_PORT -c $BIND9_NAMED_CONF -u $username"
	log_this named named -p "$BIND9_NAMED_PORT" -c "$BIND9_NAMED_CONF" -u "$username"
	exit_code="$?"
	# log waitfor?

	if [ "$exit_code" -ne 0 ] 2>/dev/null; then
		echo "ods_bind9_start: failed to start named, exit code $exit_code" >&2
		return 1
	fi

	# display pid
	if [ -f "$BIND9_NAMED_PIDFILE" ]; then
		named_pid=`cat "$BIND9_NAMED_PIDFILE"`
		echo "ods_bind9_start: named started (pid=$named_pid)"
		return 0
	fi

	# failed
	echo "ods_bind9_start: failed to start named, no pidfile" >&2
	return 1
}

ods_bind9_stop ()
{
	local named_pid
	local time_start=`$DATE '+%s' 2>/dev/null`
	local time_stop
	local time_now
	local timeout=60
	local exit_code
		
	if [ -z "$BIND9_NAMED_PIDFILE" -o -z "$BIND9_NAMED_RNDC_PORT" -o -z "$BIND9_NAMED_CONFDIR" ]; then
		echo "ods_bind9_stop: one or more required environment variables missing: BIND9_NAMED_PIDFILE BIND9_NAMED_RNDC_PORT BIND9_NAMED_CONFDIR" >&2
		return 1
	fi
	
	# check pidfile
	if [ ! -f "$BIND9_NAMED_PIDFILE" ]; then
		echo "ods_bind9_stop: cannot stop named, pidfile $BIND9_NAMED_PIDFILE does not exist" >&2
		return 1
	fi
	
	named_pid=`cat $BIND9_NAMED_PIDFILE`

	if [ -z "$named_pid" -o "$named_pid" -lt 1 ]; then
		echo "ods_bind9_stop: invalid named pid ($named_pid) in pidfile" >&2
		return 1
	fi

	# stop named
	echo "ods_bind9_stop: running rndc stop"
	rndc -p "$BIND9_NAMED_RNDC_PORT" -c "$BIND9_NAMED_CONFDIR/rndc.conf" stop
	exit_code="$?"

	if [ "$exit_code" -ne 0 ] 2>/dev/null; then
		echo "ods_bind9_stop: failed to stop named, rndc exit code $exit_code" >&2
		return 1
	fi
	
	# wait for it to finish & flush zonefile
	time_start=`$DATE '+%s' 2>/dev/null`
	time_stop=$(( time_start + timeout ))

	echo "ods_bind9_stop: waiting for named (pid $named_pid) to stop (timeout $timeout)"
	while true; do
		if ! ps -p "$named_pid" > /dev/null 2>/dev/null; then
			echo "ods_bind9_stop: named stopped"
			return 0
		fi
		time_now=`$DATE '+%s' 2>/dev/null`
		if [ "$time_now" -ge "$time_stop" ] 2>/dev/null; then
			break
		fi
		if [ -z "$time_now" -o ! "$time_now" -lt "$time_stop" ] 2>/dev/null; then
			echo "ods_bind9_stop: Invalid timestamp from date!" >&2
			exit 1
		fi
		sleep 2
	done
	
	echo "ods_bind9_stop: unable to stop named, timed out" >&2
	return 1
}

ods_bind9_info ()
{
	echo "test rootdir: $BIND9_TEST_ROOTDIR"
	echo "named confdir: $BIND9_NAMED_CONFDIR"
	echo "named rundir: $BIND9_NAMED_RUNDIR"
	echo "named pidfile: $BIND9_NAMED_PIDFILE"
	echo "named port: $BIND9_NAMED_PORT"
	echo "named rndc port: $BIND9_NAMED_RNDC_PORT"
	echo "named conf: $BIND9_NAMED_CONF"
	return 0
}

ods_bind9_kill ()
{
	local process='(named)'

	if ! pgrep -u `id -u` "$process" >/dev/null 2>/dev/null; then
		return 0
	fi

	ods_process_kill "$process" && return 0
	echo "ods_bind9_kill: Killing named failed"
	return 1
}

ods_bind9_dynupdate ()
{
	local update_iter
	local update_iterrun
	local update_perrun="$1"
	local update_total="$2"
	local zone_name="$3"
	local update_file="$BIND9_TEST_ROOTDIR/update.txt"
	local log_file="$BIND9_TEST_ROOTDIR/update.log"
	local exit_code

	if [ -z "$BIND9_TEST_ROOTDIR" -o -z "$BIND9_NAMED_CONF" ]; then
		echo "ods_bind9_dynupdate: one or more required environment variables missing: BIND9_TEST_ROOTDIR BIND9_NAMED_CONF" >&2
		return 1
	fi

	# do updates
	echo "ods_bind9_dynupdate: do $update_total updates in zone $zone_name"
	rm -rf "$update_file"
	update_iter=0
	update_iterrun=0
	while [ "$update_iter" -lt "$update_total" ] 2>/dev/null; do
		# write file
		echo "rr_add test$update_iter.$zone_name. 7200 NS ns1.test$update_iter.$zone_name." >> "$update_file"
		echo "rr_add ns1.test$update_iter.$zone_name. 7200 A 1.2.3.4" >> "$update_file"
		
		# next update
		update_iter=$(( update_iter + 1 ))
		update_iterrun=$(( update_iterrun + 1 ))
		
		if [ "$update_iterrun" -ge "$update_perrun" ] 2>/dev/null; then
			# call perl script
			"$BIND9_TEST_ROOTDIR/send_update.pl" -z "$zone_name." -k "$BIND9_NAMED_CONF" -u "$update_file" -l "$log_file" >/dev/null 2>/dev/null
			exit_code="$?"
				
			if [ "$exit_code" -ne 0 ] 2>/dev/null; then
				echo "ods_bind9_dynupdate: send_update.pl failed, exit code $exit_code" >&2
				return 1
			fi
			
			update_iterrun=0
			rm -rf "$update_file"
		fi
	done

	# check updates
	echo "ods_bind9_dynupdate: check $update_total updates in zone $zone_name"
	
	if [ ! -f "$INSTALL_ROOT/var/opendnssec/signed/$zone_name" ]; then
		echo "ods_bind9_dynupdate: zone file $zone_name not found under $INSTALL_ROOT/var/opendnssec/signed" >&2
		return 1
	fi
	
	update_iter=0
	while [ "$update_iter" -lt "$update_total" ] ; do
		if ! waitfor_this "$INSTALL_ROOT/var/opendnssec/signed/$zone_name" 10 "test$update_iter\.$zone_name\..*7200.*IN.*NS.*ns1\.test$update_iter\.$zone_name\." >/dev/null 2>/dev/null; then
			echo "ods_bind9_dynupdate: update failed, test$udpdate_iter.$zone_name\. NS not in signed zonefile" >&2
			return 1
		fi
		if ! waitfor_this "$INSTALL_ROOT/var/opendnssec/signed/$zone_name" 10 "ns1\.test$update_iter\.$zone_name\..*7200.*IN.*A.*1\.2\.3\.4" >/dev/null 2>/dev/null; then
			echo "ods_bind9_dynupdate: update failed, ns1.test$udpdate_iter.$zone_name\. A not in signed zonefile" >&2
			return 1
		fi

		# next update
		update_iter=$(( update_iter + 1 ))
	done

	rm -rf "$update_file" "$log_file"
	return 0
}
