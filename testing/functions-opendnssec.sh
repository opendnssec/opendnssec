#!/usr/bin/env bash

ODS_ENFORCER_WAIT_START=90
ODS_SIGNER_WAIT_START=90
ODS_ODS_CONTROL_WAIT_START=90

ODS_ENFORCER_WAIT_START_LOG=90
ODS_SIGNER_WAIT_START_LOG=90

ODS_ENFORCER_WAIT_STOP=90
ODS_SIGNER_WAIT_STOP=90
ODS_ODS_CONTROL_WAIT_STOP=90

ODS_ENFORCER_WAIT_STOP_LOG=90
ODS_SIGNER_WAIT_STOP_LOG=90

ODS_ENFORCER_START_LOG_STRING='ods-enforcerd: .*\[engine\] enforcer started'
ODS_ENFORCER_START_COUNT=0
ODS_SIGNER_START_LOG_STRING='ods-signerd: .*\[engine\] signer started'
ODS_SIGNER_START_COUNT=0

ODS_ENFORCER_STOP_LOG_STRING='ods-enforcerd: .*\[engine\] enforcer shutdown'
ODS_ENFORCER_STOP_COUNT=0
ODS_SIGNER_STOP_LOG_STRING='ods-signerd: .*\[engine\] signer shutdown'
ODS_SIGNER_STOP_COUNT=0

ODS_ENFORCER_TIMESHIFT_WAIT=30

ods_pre_test ()
{
	ODS_ENFORCER_START_COUNT=0
	ODS_SIGNER_START_COUNT=0
	ODS_ENFORCER_STOP_COUNT=0
	ODS_SIGNER_STOP_COUNT=0

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

ods_interrupt_test ()
{
	ods_kill
	ods_ldns_testns_kill
	ods_bind9_kill
}

ods_nuke_env ()
{
	local kasp_files=`cd "$INSTALL_ROOT/var/opendnssec/" && ls kasp*db* 2>/dev/null`
	local tmp_files=`ls "$INSTALL_ROOT/var/opendnssec/signer/" 2>/dev/null`
	local tmp_files2=`ls "$INSTALL_ROOT/var/opendnssec/tmp/" 2>/dev/null`
	local tmp_files3=`ls "$INSTALL_ROOT/var/opendnssec/enforcer/" 2>/dev/null`
	local unsigned_files=`ls "$INSTALL_ROOT/var/opendnssec/unsigned/" 2>/dev/null`
	local signed_files=`ls "$INSTALL_ROOT/var/opendnssec/signed/" 2>/dev/null`
	local signconf_files=`ls "$INSTALL_ROOT/var/opendnssec/signconf/" 2>/dev/null`
	local softhsm_files=`ls "$INSTALL_ROOT/var/softhsm/" 2>/dev/null`
	local softhsm_files2=`ls "$INSTALL_ROOT/var/lib/softhsm/" 2>/dev/null`
	local tables
	local drop_table_count
	local drop_table_max_count=20

	if [ -n "$kasp_files" ]; then
		(
			cd "$INSTALL_ROOT/var/opendnssec/" &&
			rm -rf -- $kasp_files 2>/dev/null
		)
	fi &&
	if [ -n "$tmp_files" ]; then
		(
			cd "$INSTALL_ROOT/var/opendnssec/signer/" &&
			rm -rf -- $tmp_files 2>/dev/null
		)
	fi &&
	if [ -n "$tmp_files2" ]; then
		(
			cd "$INSTALL_ROOT/var/opendnssec/tmp/" &&
			rm -rf -- $tmp_files2 2>/dev/null
		)
	fi &&
	if [ -n "$tmp_files3" ]; then
		(
			cd "$INSTALL_ROOT/var/opendnssec/enforcer/" &&
			rm -rf -- $tmp_files3 2>/dev/null
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
	if [ -n "$softhsm_files2" ]; then
		(
			cd "$INSTALL_ROOT/var/lib/softhsm/" &&
			rm -f -- $softhsm_files2 2>/dev/null
		)
	fi &&
	if [ -n "$HAVE_MYSQL" ]; then
		for database in test build; do
			drop_table_count=0
			while true; do
				tables=`mysql -u $database -p$database $database -NBe 'show tables'`
				if [ -z "$tables" ]; then
					break;
				fi
				mysql -u $database -p$database $database -NBe 'show tables' | while read table; do
					mysql -u $database -p$database $database -e "drop table $table" >/dev/null 2>/dev/null ||
					mysql -u $database -p$database $database -e "drop view $table" >/dev/null 2>/dev/null
				done
				drop_table_count=$(( drop_table_count + 1 ))
				if [ "$drop_table_count" -gt "$drop_table_max_count" ]; then
					return 1
				fi
			done
		done
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
	local no_enforcer_stop=""
	OPTIND=1
	while getopts ":n" opt; do
		case "$opt" in
			n)
				no_enforcer_stop=1
				;;
			\?)
				echo "ods_reset_env: Invalid option: -$OPTARG" >&2
				exit 1
				;;
		esac
	done
	shift $((OPTIND-1))

	echo "ods_reset_env: resetting opendnssec environment (no_enforcer_stop=$no_enforcer_stop)"

	if [ -z "$1" ]; then
                ods_softhsm_init_token 0 
        else
                ods_softhsm_init_token $1 $2 $3 $4 
        fi &&

	ods_setup_env $no_enforcer_stop &&
	return 0

	return 1
}

ods_reset_env_noenforcer ()
{
        echo "ods_reset_env: resetting opendnssec environment "
	
	if [ -z "$1" ]; then
        	ods_softhsm_init_token 0 
	else
		ods_softhsm_init_token $1 $2 $3 $4 
	fi &&
 
        echo 'y' | log_this ods-enforcer-setup ods-enforcer-db-setup &&
        return 0

        return 1
}


ods_setup_env ()
{
	local no_enforcer_stop=""
	OPTIND=1
	while getopts ":n" opt; do
		case "$opt" in
			n)
				no_enforcer_stop=1
				;;
			\?)
				echo "ods_setup_env: Invalid option: -$OPTARG" >&2
				exit 1
				;;
		esac
	done
	shift $((OPTIND-1))

	echo 'y' | log_this ods-enforcer-setup ods-enforcer-db-setup &&
	echo "ods_setup_env: setting up opendnssec environment" &&
	ods_start_enforcer &&
	log_this ods-enforcer-setup ods-enforcer policy import &&
	log_this ods-enforcer-setup ods-enforcer zonelist import &&
	( log_this ods-enforcer-stup ods-enforcer signconf || true ) &&
	sleep 10 &&
	echo "ods_setup_env: setup complete" &&
	if [ -z "$no_enforcer_stop" ]; then
		ods_stop_enforcer
	fi &&
	echo "ods_setup_env: setup env suceeded!" &&
	return 0

	echo "ods_setup_env: setup failed!" >&2
	return 1
}

# returns true if enforcer is running
ods_is_enforcer_running ()
{
	if $PGREP -u `id -u` 'ods-enforcerd' >/dev/null 2>/dev/null; then
		return 0
	fi
	return 1
}

# returns true if signer is running
ods_is_signer_running ()
{
	if $PGREP -u `id -u` 'ods-signerd' >/dev/null 2>/dev/null; then
		return 0
	fi
	return 1
}

ods_ods-control_enforcer_start ()
{
	if [ "$ODS_ENFORCER_WAIT_START" -lt 1 ] 2>/dev/null; then
		echo "ods_ods-control_enforcer_start: ODS_ENFORCER_WAIT_START not set" >&2
		exit 1
	fi

	if ! log_this_timeout ods_ods-control_enforcer_start "$ODS_ENFORCER_WAIT_START" ods-control enforcer start ; then
		echo "ods_ods-control_enforcer_start: Could not start ods-enforcerd" >&2
		return 1
	fi
	return 0
}

ods_ods-control_enforcer_stop ()
{
	if [ "$ODS_ENFORCER_WAIT_STOP" -lt 1 ] 2>/dev/null; then
		echo "ods_ods-control_enforcer_stop: ODS_ENFORCER_WAIT_STOP not set" >&2
		exit 1
	fi

	if ! log_this_timeout ods_ods-control_enforcer_stop "$ODS_ENFORCER_WAIT_STOP" ods-control enforcer stop ; then
		echo "ods_ods-control_enforcer_stop: Could not stop ods-enforcerd" >&2
		return 1
	fi
	return 0
}

ods_enforcer_start_timeshift ()
{
	if [ -z "$1" ]; then
		echo "usage: ods_enforcer_start_timeshift <timeout in seconds waiting for output>" >&2
		exit 1
	fi

	local time_start=`$DATE '+%s' 2>/dev/null`
	local time_stop
	local time_now
	local timeout="$1"
	local pid
	local last_count=`syslog_grep_count2 ods-enforcerd`
	local count

	time_stop=$(( time_start + timeout ))

	( log_this ods_enforcer_start_timeshift ods-enforcerd -1 ) &
	pid="$!"

	if [ -z "$pid" -o "$pid" -le 0 ] 2>/dev/null; then
		echo "ods_enforcer_start_timeshift: No pid from backgrounded program?" >&2
		return 1
	fi

	while true; do
		time_now=`$DATE '+%s' 2>/dev/null`
		if [ "$time_now" -ge "$time_stop" ] 2>/dev/null; then
			break
		fi
		if [ -z "$time_now" -o ! "$time_now" -lt "$time_stop" ] 2>/dev/null; then
			echo "ods_enforcer_start_timeshift: Invalid timestamp from date!" >&2
			exit 1
		fi
		if ! kill -0 "$pid" 2>/dev/null; then
			wait "$pid"
			return "$?"
		fi
		sleep 5
		count=`syslog_grep_count2 ods-enforcerd`
		if [ "$count" -gt "$last_count" ] 2>/dev/null; then
			time_stop=$(( time_now + timeout ))
		fi
		last_count="$count"
	done

	kill -TERM "$pid"
	sleep 1
	if kill -0 "$pid" 2>/dev/null; then
		kill -KILL "$pid"
	fi
	return 1
}

ods_ods-control_signer_start ()
{
	if [ "$ODS_SIGNER_WAIT_START" -lt 1 ] 2>/dev/null; then
		echo "ods_ods-control_signer_start: ODS_SIGNER_WAIT_START not set" >&2
		exit 1
	fi

	if ! log_this_timeout ods_ods-control_signer_start "$ODS_SIGNER_WAIT_START" ods-control signer start ; then
		echo "ods_ods-control_signer_start: Could not start ods-signerd" >&2
		return 1
	fi
	return 0
}

ods_ods-control_signer_stop ()
{
	if [ "$ODS_SIGNER_WAIT_STOP" -lt 1 ] 2>/dev/null; then
		echo "ods_ods-control_signer_stop: ODS_SIGNER_WAIT_STOP not set" >&2
		exit 1
	fi

	if ! log_this_timeout ods_ods-control_signer_stop "$ODS_SIGNER_WAIT_STOP" ods-control signer stop ; then
		echo "ods_ods-control_signer_stop: Could not stop ods-signerd" >&2
		return 1
	fi
	return 0
}

ods_ods-control_start ()
{
	if [ "$ODS_ODS_CONTROL_WAIT_START" -lt 1 ] 2>/dev/null; then
		echo "ods_ods-control_start: ODS_ODS_CONTROL_WAIT_START not set" >&2
		exit 1
	fi

	if ! log_this_timeout ods_ods-control_start "$ODS_ODS_CONTROL_WAIT_START" ods-control start ; then
		echo "ods_ods-control_start: Could not start ods-control" >&2
		return 1
	fi
	return 0
}

ods_ods-control_stop ()
{
	if [ "$ODS_ODS_CONTROL_WAIT_STOP" -lt 1 ] 2>/dev/null; then
		echo "ods_ods-control_stop: ODS_ODS_CONTROL_WAIT_STOP not set" >&2
		exit 1
	fi

	if ! log_this_timeout ods_ods-control_stop "$ODS_ODS_CONTROL_WAIT_STOP" ods-control stop ; then
		echo "ods_ods-control_stop: Could not stop ods-control" >&2
		return 1
	fi
	return 0
}

# Counts the number of times the enforcer has already run
ods_enforcer_count_starts ()
{
	if [ -z "$ODS_ENFORCER_START_LOG_STRING" ]; then
		echo "ods_enforcer_count_starts: ODS_ENFORCER_START_LOG_STRING not set" >&2
		exit 1
	fi

	echo "ods_enforcer_count_starts: Checking how many times enforcer has started already"
	ODS_ENFORCER_START_COUNT=`syslog_grep_count2 "$ODS_ENFORCER_START_LOG_STRING"`
	echo "ods_enforcer_count_starts: Enforcer has started $ODS_ENFORCER_START_COUNT times so far"
	return 0
}

# Counts the number of times the enforcer has already stopped
ods_enforcer_count_stops ()
{
	if [ -z "$ODS_ENFORCER_STOP_LOG_STRING" ]; then
		echo "ods_enforcer_count_stops: ODS_ENFORCER_STOP_LOG_STRING not set" >&2
		exit 1
	fi

	echo "ods_enforcer_count_stops: Checking how many times enforcer has stopped already"
	ODS_ENFORCER_STOP_COUNT=`syslog_grep_count2 "$ODS_ENFORCER_STOP_LOG_STRING"`
	echo "ods_enforcer_count_stops: Enforcer has stopped $ODS_ENFORCER_STOP_COUNT times so far"
	return 0
}

# Waits for the enforcer to have run the specified number of times
ods_enforcer_waitfor_starts ()
{
	if [ -z "$1" ]; then
		echo "usage: ods_enforcer_waitfor_starts <expected_starts> <(optional) timeout>" >&2
		exit 1
	fi

	local count="$1"
	local enforcer_start_wait_timer="$ODS_ENFORCER_WAIT_START_LOG"

	if [ -n "$2" ]; then
		enforcer_start_wait_timer="$2"
	fi
	if [ "$enforcer_start_wait_timer" -lt 1 ] 2>/dev/null; then
		echo "ods_enforcer_waitfor_starts: Timer supplied or ODS_ENFORCER_WAIT_START_LOG is invalid" >&2
		exit 1
	fi
	if [ -z "$ODS_ENFORCER_START_LOG_STRING" ]; then
		echo "ods_enforcer_waitfor_starts: ODS_ENFORCER_START_LOG_STRING not set" >&2
		exit 1
	fi

	echo "ods_enforcer_waitfor_starts: Waiting for the $count start of enforcer"
	if ! syslog_waitfor_count "$enforcer_start_wait_timer" "$count" "$ODS_ENFORCER_START_LOG_STRING" ; then
		echo "ods_enforcer_waitfor_starts: ods-enforcerd start count timed out" >&2
		return 1
	fi
	return 0
}

# Waits for the enforcer to have stopped the specified number of times
ods_enforcer_waitfor_stops ()
{
	if [ -z "$1" ]; then
		echo "usage: ods_enforcer_waitfor_stops <expected_stops> <(optional) timeout>" >&2
		exit 1
	fi

	local count="$1"
	local enforcer_stop_wait_timer="$ODS_ENFORCER_WAIT_STOP_LOG"

	if [ -n "$2" ]; then
		enforcer_stop_wait_timer="$2"
	fi
	if [ "$enforcer_stop_wait_timer" -lt 1 ] 2>/dev/null; then
		echo "ods_enforcer_waitfor_stops: Timer supplied or ODS_ENFORCER_WAIT_STOP_LOG is invalid" >&2
		exit 1
	fi
	if [ -z "$ODS_ENFORCER_STOP_LOG_STRING" ]; then
		echo "ods_enforcer_waitfor_stops: ODS_ENFORCER_STOP_LOG_STRING not set" >&2
		exit 1
	fi

	echo "ods_enforcer_waitfor_stops: Waiting for latest stop of enforcer"
	if ! syslog_waitfor_count "$enforcer_stop_wait_timer" "$count" "$ODS_ENFORCER_STOP_LOG_STRING" ; then
		echo "ods_enforcer_waitfor_stops: ods-enforcerd stop count timed out" >&2
		return 1
	fi
	return 0
}

# Counts the number of times the signer has already run
ods_signer_count_starts ()
{
	if [ -z "$ODS_SIGNER_START_LOG_STRING" ]; then
		echo "ods_signer_count_starts: ODS_SIGNER_START_LOG_STRING not set" >&2
		exit 1
	fi

	echo "ods_signer_count_starts: Checking how many times signer has started already"
	ODS_SIGNER_START_COUNT=`syslog_grep_count2 "$ODS_SIGNER_START_LOG_STRING"`
	echo "ods_signer_count_starts: Signer has started $ODS_SIGNER_START_COUNT times so far"
}

# Counts the number of times the signer has already run
ods_signer_count_stops ()
{
	if [ -z "$ODS_SIGNER_STOP_LOG_STRING" ]; then
		echo "ods_signer_count_stops: ODS_SIGNER_STOP_LOG_STRING not set" >&2
		exit 1
	fi

	echo "ods_signer_count_stops: Checking how many times signer has stopped already"
	ODS_SIGNER_STOP_COUNT=`syslog_grep_count2 "$ODS_SIGNER_STOP_LOG_STRING"`
	echo "ods_signer_count_stops: Signer has stopped $ODS_SIGNER_STOP_COUNT times so far"
}

# Waits for the signer to have run the specified number of times
ods_signer_waitfor_starts ()
{
	if [ -z "$1" ]; then
		echo "usage: ods_signer_waitfor_starts <expected_starts> <(optional) timeout>" >&2
		return 1
	fi

	local count="$1"
	local signer_start_wait_timer="$ODS_SIGNER_WAIT_START_LOG"

	if [ -n "$2" ]; then
		signer_start_wait_timer="$2"
	fi
	if [ "$signer_start_wait_timer" -lt 1 ] 2>/dev/null; then
		echo "ods_signer_waitfor_starts: Timer supplied or ODS_SIGNER_WAIT_START_LOG is invalid" >&2
		exit 1
	fi
	if [ -z "$ODS_SIGNER_START_LOG_STRING" ]; then
		echo "ods_signer_waitfor_starts: ODS_SIGNER_START_LOG_STRING not set" >&2
		exit 1
	fi

	echo "ods_signer_waitfor_starts: Waiting for latest start of signer"
	if ! syslog_waitfor_count "$signer_start_wait_timer" "$count" "$ODS_SIGNER_START_LOG_STRING" ; then
		echo "ods_signer_waitfor_starts: ods-signerd start count timed out" >&2
		return 1
	fi
	return 0
}

# Waits for the signer to have stopped the specified number of times
ods_signer_waitfor_stops ()
{
	if [ -z "$1" ]; then
		echo "usage: ods_signer_waitfor_stops <expected_stops> <(optional) timeout>" >&2
		return 1
	fi

	local count="$1"
	local signer_stop_wait_timer="$ODS_SIGNER_WAIT_STOP_LOG"

	if [ -n "$2" ]; then
		signer_stop_wait_timer="$2"
	fi
	if [ "$signer_stop_wait_timer" -lt 1 ] 2>/dev/null; then
		echo "ods_signer_waitfor_stops: Timer supplied or ODS_SIGNER_WAIT_STOP_LOG is invalid" >&2
		exit 1
	fi
	if [ -z "$ODS_SIGNER_STOP_LOG_STRING" ]; then
		echo "ods_signer_waitfor_stops: ODS_SIGNER_STOP_LOG_STRING not set" >&2
		exit 1
	fi

	echo "ods_signer_waitfor_stops: Waiting for latest stop of signer"
	if ! syslog_waitfor_count "$signer_stop_wait_timer" "$count" "$ODS_SIGNER_STOP_LOG_STRING" ; then
		echo "ods_signer_waitfor_stops: ods-signerd stop count timed out" >&2
		return 1
	fi
	return 0
}

# Takes an optional parameter that will override the timeout on waiting for
# the log to confirm the action
ods_start_enforcer ()
{
	if ods_is_enforcer_running; then
		echo "ods_start_enforcer: ods-enforcerd is already running" >&2
		return 1
	fi

	local timeout="$1"

	echo "ods_start_enforcer: Starting ods-enforcer now..."

 	ods_enforcer_count_starts &&
	ods_ods-control_enforcer_start &&
	ods_enforcer_waitfor_starts "$(( ODS_ENFORCER_START_COUNT + 1 ))" "$timeout" &&

	echo "ods_start_enforcer: ods-enforcer started OK" &&
	return 0

	echo "ods_start_enforcer: ods-enforcer started FAILED" >&2
	return 1
}

# Takes an optional parameter that will override the timeout on waiting for
# the log to confirm the action
ods_stop_enforcer ()
{
	if ! ods_is_enforcer_running; then
		echo "ods_stop_enforcer: ods-enforcerd is not running" >&2
		return 1
	fi

	local timeout="$1"
	local running_timeout=15

	echo "ods_stop_enforcer: Stopping ods-enforcer now..."

 	ods_enforcer_count_stops &&
	ods_ods-control_enforcer_stop &&
	ods_enforcer_waitfor_stops "$(( ODS_ENFORCER_STOP_COUNT + 1 ))" "$timeout" &&

	# double check the process is killed as this seems to take a little while on some platforms
	if ods_is_enforcer_running; then
		echo "ods_stop_enforcer: waiting for process to terminate..."
		while true; do
			sleep 1
			if ! ods_is_enforcer_running; then
				break
			fi

			if [ "$running_timeout" = "0" ]; then
				echo "ods_stop_enforcer: ods-enforcerd process is still running" >&2
				return 1
			fi
			running_timeout=$(( running_timeout - 1 ))
		done
	fi &&

	echo "ods_stop_enforcer: ods-enforcer stopped OK" &&
	return 0

	echo "ods_stop_enforcer: ods-enforcer stopped FAILED" >&2
	return 1
}

# Takes an optional parameter that will override the timeout on waiting for
# the log to confirm the action
ods_start_enforcer_timeshift ()
{
	if ods_is_enforcer_running; then
		echo "ods_start_enforcer_timeshift: ods-enforcerd is already running" >&2
		return 1
	fi

	local timeout="$1"
	local running_timeout=15

	echo "ods_start_enforcer_timeshift: Starting ods-enforcer now..."
 	ods_enforcer_count_stops &&
	ods_enforcer_start_timeshift "$ODS_ENFORCER_TIMESHIFT_WAIT" &&
	ods_enforcer_waitfor_stops "$(( ODS_ENFORCER_STOP_COUNT + 1 ))" "$ODS_ENFORCER_TIMESHIFT_WAIT" &&

	# double check the process is killed as this seems to take a little while on some platforms
	if ods_is_enforcer_running; then
		echo "ods_start_enforcer_timeshift: waiting for process to terminate..."
		while true; do
			sleep 1
			if ! ods_is_enforcer_running; then
				break
			fi

			if [ "$running_timeout" = "0" ]; then
				echo "ods_start_enforcer_timeshift: ods-enforcerd process is still running" >&2
				return 1
			fi
			running_timeout=$(( running_timeout - 1 ))
		done
	fi &&

	echo "ods_start_enforcer_timeshift: ods-enforcer started OK" &&
	return 0

	echo "ods_start_enforcer_timeshift: ods-enforcer start FAILED" >&2
	return 1
}

# Takes an optional parameter that will override the timeout on waiting for
# the log to confirm the action
ods_start_signer ()
{
	if ods_is_signer_running; then
		echo "ods_start_signer: ods-signerd is already running" >&2
		return 1
	fi

	local timeout="$1"

	echo "ods_start_signer: Starting ods-signer now..."

 	ods_signer_count_starts &&
	ods_ods-control_signer_start &&
	ods_signer_waitfor_starts "$(( ODS_SIGNER_START_COUNT + 1 ))" "$timeout" &&

	echo "ods_start_signer: ods-signer started OK" &&
	return 0

	echo "ods_start_signer: ods-signer started FAILED" >&2
	return 1
}

# Takes an optional parameter that will override the timeout on waiting for
# the log to confirm the action
ods_stop_signer ()
{
	if ! ods_is_signer_running; then
		echo "ods_stop_signer: ods-signerd is not running" >&2
		return 1
	fi

	local timeout="$1"

	echo "ods_stop_signer: Stopping ods-signer now..."

 	ods_signer_count_stops &&
	ods_ods-control_signer_stop	&&
	ods_signer_waitfor_stops "$(( ODS_SIGNER_STOP_COUNT + 1 ))" "$timeout" &&

	# double check the process is killed as this seems to take a little while on some platforms
	if ods_is_signer_running; then
		echo "ods_stop_signer: waiting for process to terminate..."
		while true; do
			sleep 1
			if ! ods_is_signer_running; then
				break
			fi

			if [ "$running_timeout" = "0" ]; then
				echo "ods_stop_signer: ods-signerd process is still running" >&2
				return 1
			fi
			running_timeout=$(( running_timeout - 1 ))
		done
	fi &&

	echo "ods_stop_signer: ods-signer stopped OK" &&
	return 0

	echo "ods_stop_signer: ods-signer stopped FAILED" >&2
	return 1
}

# Takes an optional parameter that will override the timeout on waiting for
# the log to confirm the action
ods_start_ods-control ()
{
	if ods_is_signer_running; then
		echo "ods_start_ods-control: ods-signerd is already running" >&2
		return 1
	fi
	if ods_is_enforcer_running; then
		echo "ods_start_ods-control: ods-enforcerd is already running" >&2
		return 1
	fi

	local timeout="$1"

	echo "ods_start_ods-control: Starting with ods-control now..."

 	ods_signer_count_starts &&
 	ods_enforcer_count_starts &&
	ods_ods-control_start &&
	ods_signer_waitfor_starts "$(( ODS_SIGNER_START_COUNT + 1 ))" "$timeout" &&
	ods_enforcer_waitfor_starts "$(( ODS_ENFORCER_START_COUNT + 1 ))" "$timeout" &&

	echo "ods_start_ods-control: ods-control started OK" &&
	return 0

	echo "ods_start_ods-control: ods-control started FAILED" >&2
	return 1
}

# Takes an optional parameter that will override the timeout on waiting for
# the log to confirm the action
ods_stop_ods-control ()
{
	if ! ods_is_signer_running; then
		echo "ods_stop_ods-control: ods-signerd is not running" >&2
		return 1
	fi
	if ! ods_is_enforcer_running; then
		echo "ods_stop_ods-control: ods-enforcerd is not running" >&2
		return 1
	fi

	local timeout="$1"
	local running_timeout="20"

	echo "ods_stop_ods-control: Stopping with ods-control now..."

 	ods_signer_count_stops &&
 	ods_enforcer_count_stops &&
	ods_ods-control_stop &&
	ods_signer_waitfor_stops "$(( ODS_SIGNER_STOP_COUNT + 1 ))" "$timeout" &&
	ods_enforcer_waitfor_stops "$(( ODS_ENFORCER_STOP_COUNT + 1 ))" "$timeout" &&

	# double check the process is killed as this seems to take a little while on some platforms
	if ods_is_signer_running; then
		echo "ods_stop_ods-control: waiting for signer to terminate..."
		while true; do
			sleep 1
			if ! ods_is_signer_running; then
				break
			fi

			if [ "$running_timeout" = "0" ]; then
				echo "ods_stop_ods-control: ods-signerd process is still running" >&2
				return 1
			fi
			running_timeout=$(( running_timeout - 1 ))
		done
	fi &&
	if ods_is_enforcer_running; then
		echo "ods_stop_ods-control: waiting for enforcer to terminate..."
		while true; do
			sleep 1
			if ! ods_is_enforcer_running; then
				break
			fi

			if [ "$running_timeout" = "0" ]; then
				echo "ods_stop_ods-control: ods-enforcerd process is still running" >&2
				return 1
			fi
			running_timeout=$(( running_timeout - 1 ))
		done
	fi &&

	echo "ods_stop_ods-control: ods-control stopped OK" &&
	return 0

	echo "ods_stop_ods-control: ods-control stopped FAILED" >&2
	return 1
}

ods_process_kill ()
{
	if [ -z "$1" ]; then
		echo "usage: ods_process_kill <pgrep syntax>" >&2
		exit 1
	fi

	local process="$1"

	if $PGREP -u `id -u` "$process" >/dev/null 2>/dev/null; then
		sleep 2
		pkill -QUIT "$process" 2>/dev/null
		if $PGREP -u `id -u` "$process" >/dev/null 2>/dev/null; then
			sleep 2
			pkill -TERM "$process" 2>/dev/null
			if $PGREP -u `id -u` "$process" >/dev/null 2>/dev/null; then
				sleep 2
				pkill -KILL "$process" 2>/dev/null
				$PGREP -u `id -u` "$process" >/dev/null 2>/dev/null &&
				sleep 2
			fi
		fi
	fi

	if $PGREP -u `id -u` "$process" >/dev/null 2>/dev/null; then
		echo "process_kill: Tried to kill $process some are still alive!" >&2
		return 1
	fi

	return 0
}

ods_kill ()
{
	local process='(ods-enforcerd|ods-signerd)'

	if ! $PGREP -u `id -u` "$process" >/dev/null 2>/dev/null; then
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

	if ! $PGREP -u `id -u` "$process" >/dev/null 2>/dev/null; then
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

# This function depend on environment variables:
#   BIND9_NAMED_CONF
#   BIND9_NAMED_PIDFILE
#   BIND9_NAMED_PORT
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

# This function depend on environment variables:
#   BIND9_NAMED_CONFDIR
#   BIND9_NAMED_PIDFILE
#   BIND9_NAMED_RNDC_PORT
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

	if [ -z "$named_pid" -o "$named_pid" -lt 1 ] 2>/dev/null; then
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

	if ! $PGREP -u `id -u` "$process" >/dev/null 2>/dev/null; then
		return 0
	fi

	ods_process_kill "$process" && return 0
	echo "ods_bind9_kill: Killing named failed"
	return 1
}

# This function depend on environment variables:
#   BIND9_NAMED_CONF
#   BIND9_TEST_ROOTDIR
ods_bind9_dynupdate ()
{
	if [ -z "$1" -o -z "$2" -o -z "$3" ]; then
		echo "usage: ods_bind9_dynupdate <update perrun> <update total> <zone name>" >&2
		exit 1
	fi

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
	while [ "$update_iter" -lt "$update_total" ] 2>/dev/null; do
		if ! waitfor_this "$INSTALL_ROOT/var/opendnssec/signed/$zone_name" 10 "test$update_iter\.$zone_name\..*7200.*IN.*NS.*ns1\.test$update_iter\.$zone_name\." >/dev/null 2>/dev/null; then
			echo "ods_bind9_dynupdate: update failed, test$update_iter.$zone_name. NS not in signed zonefile" >&2
			return 1
		fi
		if ! waitfor_this "$INSTALL_ROOT/var/opendnssec/signed/$zone_name" 10 "ns1\.test$update_iter\.$zone_name\..*7200.*IN.*A.*1\.2\.3\.4" >/dev/null 2>/dev/null; then
			echo "ods_bind9_dynupdate: update failed, ns1.test$update_iter.$zone_name. A not in signed zonefile" >&2
			return 1
		fi

		# next update
		update_iter=$(( update_iter + 1 ))
	done

	rm -rf "$update_file" "$log_file"
	return 0
}

# Method to compare a 'gold' directory containing signconfs with a 'base' directory
# generated during a test run. Assumes the directories are called 'gold' and 'base'
# and the script is called from the directory which holds both of them.
# It replaces the key CKS_IDS in the <Locator> tags with indexes to allow a diff.
# It also ignores the <Salt> tag contents
# See enforcer.keys.rollovers_and_zones_many for an example of how it is used.
ods_compare_gold_vs_base_signconf ()
{
	local all_locators
	local unique_locators
	local indexed_locators
	local test_dir
	local temp_dir
	local file
	local line_no
	local index
	local replace_string
	local i

	for test_dir in gold base; do
		if [ ! -d "$test_dir" ]; then
			echo "ods_compare_gold_vs_base_signconf: directory $test_dir no found" >&2
			return 1
		fi

		temp_dir="${test_dir}_temp"

		rm -rf -- "$temp_dir"
		if ! mkdir -- "$temp_dir" 2>/dev/null; then
			echo "ods_compare_gold_vs_base_signconf: Unable to create directory $temp_dir" >&2
			return 1
		fi

		unset all_locators
		unset unique_locators
		unset indexed_locators

		# Subshell from here
		(
			if ! cd "$test_dir" 2>/dev/null; then
				echo "ods_compare_gold_vs_base_signconf: unable to change to test directory $test_dir!" >&2
				return 1
			fi

			files=( $(ls -1 2>/dev/null ) )
			if [ "${#files[@]}" -le 0 ] 2>/dev/null; then
				echo "ods_compare_gold_vs_base_signconf: no files found!" >&2
				return 1
			fi

			# fish out the key locators
			for file in ${files[@]}; do
				all_locators+=( $($GREP -- "<Locator>" "$file" | awk -F">" '{print $2}' | awk -F"<" '{print $1}' ) )
			done

			# remove duplicates, retaining order (OpenBSD doesn't support nl utility add line numbers the long way)
			line_no=0
			for file in ${all_locators[@]}; do
				indexed_locators+=( $(echo "$line_no-${file}_") )
				line_no=$(( $line_no + 1 ))
			done

			# sort routine requires -s (stable sort) to give consistent results across all platforms
			unique_locators=( $(echo "${indexed_locators[@]}" | tr -d ' ' | tr '_' '\n' | tr '-' ' ' | $SORT -u -k2 -s | $SORT -n | cut -f2 -d ' ') )

			# create a replacement string for all the locators
			index=0
			replace_string="sed "
			for i in ${unique_locators[@]}; do
				replace_string+=" -e 's#$i#$index#' "
				index=$(( $index + 1 ))
			done

			# ignore the contents of the <Salt> tag
			replace_string+=" -e 's#<Salt>.*#<Salt></Salt>#' "

			#apply to each of the files
			for file in ${files[@]}; do
				eval $replace_string "$file" > "../$temp_dir/$file"
			done
		)
		# Exit subshell
	done

	if ! diff gold_temp base_temp; then
		return 1
	fi

	rm -rf gold_temp
	rm -rf base_temp
	return 0
}
