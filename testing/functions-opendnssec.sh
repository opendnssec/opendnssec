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

ODS_ENFORCER_START_LOG_STRING='ods-enforcerd: .*Sleeping for'
ODS_ENFORCER_START_COUNT=0
ODS_SIGNER_START_LOG_STRING='ods-signerd: .*\[engine\] signer started'
ODS_SIGNER_START_COUNT=0

ODS_ENFORCER_STOP_LOG_STRING='ods-enforcerd: .*all done'
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
	local softhsm2=""
	if [ -d "$INSTALL_ROOT/var/softhsm/tokens" ]; then
		rm -rf -- "$INSTALL_ROOT/var/softhsm/tokens" ||
		return 1
		softhsm2="$INSTALL_ROOT/var/softhsm"
	fi
	if [ -d "$INSTALL_ROOT/var/lib/softhsm/tokens" ]; then
		rm -rf -- "$INSTALL_ROOT/var/lib/softhsm/tokens" ||
		return 1
		softhsm2="$INSTALL_ROOT/var/lib/softhsm"
	fi

	local kasp_files=`cd "$INSTALL_ROOT/var/opendnssec/" && ls kasp*db* 2>/dev/null`
	local tmp_files=`ls "$INSTALL_ROOT/var/opendnssec/tmp/" 2>/dev/null`
	local unsigned_files=`ls "$INSTALL_ROOT/var/opendnssec/unsigned/" 2>/dev/null`
	local signed_files=`ls "$INSTALL_ROOT/var/opendnssec/signed/" 2>/dev/null`
	local signconf_files=`ls "$INSTALL_ROOT/var/opendnssec/signconf/" 2>/dev/null`
	local softhsm_files=`ls "$INSTALL_ROOT/var/softhsm/" 2>/dev/null`
	local softhsm_files2=`ls "$INSTALL_ROOT/var/lib/softhsm/" 2>/dev/null`

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
	if [ -n "$softhsm_files2" ]; then
		(
			cd "$INSTALL_ROOT/var/lib/softhsm/" &&
			rm -f -- $softhsm_files2 2>/dev/null
		)
	fi &&
	if [ -n "$softhsm2" ]; then
		mkdir -- "$softhsm2/tokens"
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
			softhsm.conf | softhsm2.conf | conf.xml | kasp.xml | zonefetch.xml | zonelist.xml )
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
	local softhsm_conf="softhsm.conf"
	if [ -f "$INSTALL_ROOT/etc/softhsm2.conf.build" ]; then
		softhsm_conf="softhsm2.conf"
	fi
	for conf_file in "$softhsm_conf"; do
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
	for conf_file in conf.xml kasp.xml zonefetch.xml zonelist.xml; do
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
			echo "ods_setup_conf: unable to copy/install zone file $zone to $INSTALL_ROOT/var/opendnssec/unsigned/" >&2
			return 1
		fi

		return 0
	fi

	if [ -d unsigned ]; then
		ls -1 unsigned/ | while read zone; do
			if [ -f "unsigned/$zone" ]; then
				if ! cp -- "unsigned/$zone" "$INSTALL_ROOT/var/opendnssec/unsigned/" 2>/dev/null; then
					echo "ods_setup_conf: unable to copy/install zone file $zone to $INSTALL_ROOT/var/opendnssec/unsigned/" >&2
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
	ods_setup_env &&
	return 0

	return 1
}

ods_setup_env ()
{
	echo "y" | log_this "ods-ksmutil-setup" ods-ksmutil setup &&
	return 0

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

ods_kill ()
{
	if ! $PGREP -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null; then
		return 0
	fi

	echo "ods_kill: Killing OpenDNSSEC"
	try_run 15 ods-control stop

	if $PGREP -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null; then
		sleep 2
		pkill -QUIT '(ods-enforcerd|ods-signerd)' 2>/dev/null
		if $PGREP -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null; then
			sleep 2
			pkill -TERM '(ods-enforcerd|ods-signerd)' 2>/dev/null
			if $PGREP -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null; then
				sleep 2
				pkill -KILL '(ods-enforcerd|ods-signerd)' 2>/dev/null
				$PGREP -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null &&
				sleep 2
			fi
		fi
	fi

	if $PGREP -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null; then
		echo "ods_kill: Tried to kill ods-enforcerd and ods-signerd but some are still alive!" >&2
		return 1
	fi

	return 0
}

ods_softhsm_init_token ()
{
	if [ -z "$1" ]; then
		echo "usage: ods_softhsm_init_token <slot> [label] [pin] [so-pin]" >&2
		exit 1
	fi

	local softhsm

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

	if [ -x "$INSTALL_ROOT/bin/softhsm" ]; then
		# we're using SoftHSMv1
		softhsm="$INSTALL_ROOT/bin/softhsm"
	elif [ -x "$INSTALL_ROOT/bin/softhsm-util" ]; then
		# we're using SoftHSMv2
		softhsm="$INSTALL_ROOT/bin/softhsm-util"
		if [ -d "$INSTALL_ROOT/var/softhsm" ]; then
			mkdir -p -- "$INSTALL_ROOT/var/softhsm/tokens"
		fi
		if [ -d "$INSTALL_ROOT/var/lib/softhsm" ]; then
			mkdir -p -- "$INSTALL_ROOT/var/lib/softhsm/tokens"
		fi
	else
		echo "ods_softhsm_init_token: neither SoftHSMv1 nor SoftHSMv2 found" >&2
		exit 1
	fi

	if [ "$slot" -ge 0 -a "$slot" -lt 20 ] 2>/dev/null; then
		log_remove "softhsm-init-token-$slot" &&
		log_this "softhsm-init-token-$slot" $softhsm --init-token --slot "$slot" --label "$label" --pin "$pin" --so-pin "$so_pin" ||
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
