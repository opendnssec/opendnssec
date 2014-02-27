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
ODS_SIGNER_START_LOG_STRING='ods-signerd: .*\[engine\] signer started'

ODS_ENFORCER_STOP_LOG_STRING='ods-enforcerd: .*all done'
ODS_SIGNER_STOP_LOG_STRING='ods-signerd: .*\[engine\] signer shutdown'

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

ods_interrupt_test ()
{
    ods_kill
    ods_ldns_testns_kill
    ods_bind9_kill
}

ods_nuke_env ()
{
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
			softhsm.conf | conf.xml | kasp.xml | zonefetch.xml | zonelist.xml )
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

ods_is_enforcer_running ()
{
	# returns true if enforcer is running
	if  pgrep -u `id -u` 'ods-enforcerd' >/dev/null 2>/dev/null; then
		return 0
	fi		
	return 1
}

ods_is_signer_running ()
{
	# returns true if signer is running
	if  pgrep -u `id -u` 'ods-signerd' >/dev/null 2>/dev/null; then
		return 0
	fi		
	return 1
}

ods_ods-control_enforcer_start() {
	
	if  ! log_this_timeout ods_ods-control_enforcer_start $ODS_ENFORCER_WAIT_START ods-control enforcer start ; then
		echo "ods_ods-control_enforcer_start: ERROR: Could not start ods-enforcerd. Exiting..." >&2
		return 1
	fi
	return 0
	
}

ods_ods-control_enforcer_stop() {
	
	if  ! log_this_timeout ods_ods-control_enforcer_stop $ODS_ENFORCER_WAIT_STOP ods-control enforcer stop ; then
		echo "ods_ods-control_enforcer_stop: ERROR: Could not stop ods-enforcerd. Exiting..." >&2
		return 1
	fi
	return 0
	
}

ods_enforcer_start_timeshift() {
	
	local enforcer_start_wait_timer=$ODS_ENFORCER_WAIT_START_LOG
	if [ -n "$1" ]; then
		enforcer_start_wait_timer=$1
	fi	
	
	if  ! log_this_timeout ods_enforcer_start_timeshift $enforcer_start_wait_timer ods-enforcerd -1 ; then
		echo "ods_enforcer_start_timeshift: ERROR: Could not start ods-enforcerd. Exiting..." >&2
		return 1
	fi
	return 0
	
}

ods_ods-control_signer_start() {
	
	if  ! log_this_timeout ods_ods-control_signer_start $ODS_SIGNER_WAIT_START ods-control signer start ; then
		echo "ods_ods-control_signer_start: ERROR: Could not start ods-signerd. Exiting..." >&2
		return 1
	fi
	return 0
	
}

ods_ods-control_signer_stop() {
	
	if  ! log_this_timeout ods_ods-control_signer_stop $ODS_SIGNER_WAIT_STOP ods-control signer stop ; then
		echo "ods_ods-control_signer_stop: ERROR: Could not stop ods-signerd. Exiting..." >&2
		return 1
	fi
	return 0
	
}

ods_ods-control_start() {
	
	if  ! log_this_timeout ods_ods-control_start $ODS_ODS_CONTROL_WAIT_START ods-control start ; then
		echo "ods_ods-control_start: ERROR: Could not start ods-control. Exiting..." >&2
		return 1
	fi
	return 0
	
}

ods_ods-control_stop() {
	
	if  ! log_this_timeout ods_ods-control_stop $ODS_ODS_CONTROL_WAIT_STOP ods-control stop ; then
		echo "ods_ods-control_stop: ERROR: Could not stop ods-control. Exiting..." >&2
		return 1
	fi
	return 0
	
}

ods_enforcer_count_starts() {
	
	# Counts the number of times the enforcer has already run by
	# seting up the $syslog_grep_count_variable to contain a count of runs
	echo "ods_enforcer_count_starts: Checking how many times enforcer has started already"
    syslog_grep_count 0 "$ODS_ENFORCER_START_LOG_STRING"
    echo "ods_enforcer_count_starts: Enforcer has started" $syslog_grep_count_variable "times so far"
	
}

ods_enforcer_count_stops() {
	
	# Counts the number of times the enforcer has already stopped by
	# seting up the $syslog_grep_count_variable to contain a count of stops
	echo "ods_enforcer_count_stops: Checking how many times enforcer has stopped already"
    syslog_grep_count 0 "$ODS_ENFORCER_STOP_LOG_STRING"
    echo "ods_enforcer_count_stops: Enforcer has stopped" $syslog_grep_count_variable "times so far"

}


ods_enforcer_waitfor_starts() {
	
	# Waits for the enforcer to have run the specified number of times
	if [ -z "$1" ]; then
		echo "usage: ods_enforcer_waitfor_starts <expected_starts> <(optional) timeout>" >&2
		return 1
	fi	
	
	local enforcer_start_wait_timer=$ODS_ENFORCER_WAIT_START_LOG
	if [ -n "$2" ]; then
		enforcer_start_wait_timer=$2
	fi
	
	echo "ods_enforcer_waitfor_starts:  Waiting for latest start of enforcer"
	if ! syslog_waitfor_count $enforcer_start_wait_timer $1 "$ODS_ENFORCER_START_LOG_STRING" ; then
		echo "ods_enforcer_waitfor_starts: ERROR: ods-enforcerd has not started. Exiting..." >&2
		return 1
	fi
	return 0
	
}

ods_enforcer_waitfor_stops() {
	
	# Waits for the enforcer to have stopped the specified number of times
	if [ -z "$1" ]; then
		echo "usage: ods_enforcer_waitfor_stops <expected_stops> <(optional) timeout>" >&2
		return 1
	fi	
	
	local enforcer_stop_wait_timer=$ODS_ENFORCER_WAIT_STOP_LOG
	if [ -n "$2" ]; then
		enforcer_stop_wait_timer=$2
	fi
		
	echo "ods_enforcer_waitfor_stops:  Waiting for latest stop of enforcer"
	if ! syslog_waitfor_count $enforcer_stop_wait_timer $1 "$ODS_ENFORCER_STOP_LOG_STRING" ; then
		echo "ods_enforcer_waitfor_stops: ERROR: ods-enforcerd has not stopped. Exiting..." >&2
		return 1
	fi
	return 0
	
}

ods_signer_count_starts() {
	
	# Counts the number of times the signer has already run by
	# seting up the $syslog_grep_count_variable to contain a count of starts
	echo "ods_signer_count_starts: Checking how many times signer has started already"
    syslog_grep_count 0 "$ODS_SIGNER_START_LOG_STRING"
    echo "ods_signer_count_starts: Signer has started" $syslog_grep_count_variable "times so far"

}

ods_signer_count_stops() {
	
	# Counts the number of times the signer has already run by
	# seting up the $syslog_grep_count_variable to contain a count of stops
	echo "ods_signer_count_stops: Checking how many times signer has stopped already"
    syslog_grep_count 0 "$ODS_SIGNER_STOP_LOG_STRING"
    echo "ods_signer_count_stops: Signer has stopped" $syslog_grep_count_variable "times so far"
	
}

ods_signer_waitfor_starts() {
	
	# Waits for the signer to have run the specified number of times
	if [ -z "$1" ]; then
		echo "usage: ods_signer_waitfor_starts <expected_starts> <(optional) timeout>" >&2
		return 1
	fi	
	
	local signer_start_wait_timer=$ODS_SIGNER_WAIT_START_LOG
	if [ -n "$2" ]; then
		signer_start_wait_timer=$2
	fi	
	
	echo "ods_signer_waitfor_starts:  Waiting for latest start of signer"
	if ! syslog_waitfor_count $signer_start_wait_timer $1 "$ODS_SIGNER_START_LOG_STRING" ; then
		echo "ods_signer_waitfor_starts: ERROR: ods-signerd has not started. Exiting..." >&2
		return 1
	fi
	return 0
	
}

ods_signer_waitfor_stops() {
	
	# Waits for the signer to have stopped the specified number of times
	if [ -z "$1" ]; then
		echo "usage: ods_signer_waitfor_stops <expected_stops> <(optional) timeout>" >&2
		return 1
	fi	
	
	local signer_stop_wait_timer=$ODS_SIGNER_WAIT_STOP_LOG
	if [ -n "$2" ]; then
		signer_stop_wait_timer=$2
	fi 
		
	echo "ods_signer_waitfor_stops:  Waiting for latest stop of signer"
	if ! syslog_waitfor_count $signer_stop_wait_timer $1 "$ODS_SIGNER_STOP_LOG_STRING" ; then
		echo "ods_signer_waitfor_stops: ERROR: ods-signerd has not stopped. Exiting..." >&2
		return 1
	fi
	return 0
	
}

ods_start_enforcer() 
{
	
	# Takes an optional parameter that will override the timeout on waiting for 
	# the log to confirm the action
	
	if ods_is_enforcer_running; then
		echo "ods_start_enforcer: ERROR: ods-enforcerd is already running.." >&2
		return 1
	fi		
		
	echo "ods_start_enforcer: Starting ods-enforcer now..." >&2 &&
	
 	ods_enforcer_count_starts &&
    local ods_enforcer_start_count="$syslog_grep_count_variable" &&
	ods_ods-control_enforcer_start	&&
	ods_enforcer_waitfor_starts $(( ods_enforcer_start_count + 1 )) $1 &&
	
	echo "ods_start_enforcer: ods-enforcer started OK..." >&2 &&
	return 0
	
	return 1
}

ods_stop_enforcer() {
	
	# Takes an optional parameter that will override the timeout on waiting for 
	# the log to confirm the action	
	
	if ! ods_is_enforcer_running; then
		echo "ods_stop_enforcer: ERROR: ods-enforcerd is not running.." >&2
		return 1
	fi		
		
	echo "ods_stop_enforcer: Stopping ods-enforcer now..." >&2 &&
	
 	ods_enforcer_count_stops &&
    local ods_enforcer_stop_count="$syslog_grep_count_variable" &&
	ods_ods-control_enforcer_stop	&&
	ods_enforcer_waitfor_stops $(( ods_enforcer_stop_count + 1 )) $1 &&
	
	# double check the process is killed as this seems to take a little while on some platforms
	if ods_is_enforcer_running; then
		sleep 1
		echo "ods_stop_enforcer: waiting for process to terminate..." >&2 
		if ods_is_enforcer_running; then
				echo "ods_stop_enforcer: ERROR: ods-enforcerd process is still running..." >&2
				return 1
		fi
	fi &&
	
	echo "ods_stop_enforcer: ods-enforcer stopped OK..." >&2 &&
	return 0
	
	return 1
}

ods_start_enforcer_timeshift() {
	
	# Takes an optional parameter that will override the timeout on waiting for 
	# the log to confirm the action	
		
	if ods_is_enforcer_running; then
		echo "ods_start_enforcer_timeshift: ERROR: ods-enforcerd is already running.." >&2
		return 1
	fi		
		
	echo "ods_start_enforcer_timeshift: Starting ods-enforcer now..." >&2 &&
	
	# When the enforcer runs in timeshift mode it runs to completion
	# so it has to be measured as a stop
 	ods_enforcer_count_stops &&
    local ods_enforcer_stop_count="$syslog_grep_count_variable" &&
	ods_enforcer_start_timeshift $1 &&
	ods_enforcer_waitfor_stops $(( ods_enforcer_stop_count + 1 )) $1 &&
	
	# double check the process is killed as this seems to take a little while on some platforms
	if ods_is_enforcer_running; then
		sleep 1
		echo "ods_stop_enforcer: waiting for process to terminate..." >&2 
		if ods_is_enforcer_running; then
				echo "ods_stop_enforcer: ERROR: ods-enforcerd process is still running..." >&2 
				return 1
		fi
	fi &&
	
	echo "ods_start_enforcer_timeshift: ods-enforcer started OK..." >&2 &&
	return 0
	
	return 1
}


ods_start_signer() {
	
	# Takes an optional parameter that will override the timeout on waiting for 
	# the log to confirm the action	
		
	if ods_is_signer_running; then
		echo "ods_start_signer: ERROR: ods-signerd is already running.." >&2
		return 1
	fi		
		
	echo "ods_start_signer: Starting ods-signer now..." >&2 &&
	
 	ods_signer_count_starts &&
    local ods_signer_start_count="$syslog_grep_count_variable" &&
	ods_ods-control_signer_start	&&
	ods_signer_waitfor_starts $(( ods_signer_start_count + 1 )) $1 &&
	
	echo "ods_start_signer: ods-signer started OK..." >&2 &&
	return 0
	
	return 1
}

ods_stop_signer() {
	
	# Takes an optional parameter that will override the timeout on waiting for 
	# the log to confirm the action	
	
	if ! ods_is_signer_running; then
		echo "ods_stop_signer: ERROR: ods-signerd is not running.." >&2
		return 1
	fi		
		
	echo "ods_stop_signer: Stopping ods-signer now..." >&2 &&
	
 	ods_signer_count_stops &&
    local ods_signer_stop_count="$syslog_grep_count_variable" &&
	ods_ods-control_signer_stop	&&
	ods_signer_waitfor_stops $(( ods_signer_stop_count + 1 )) $1 &&
	
	# double check the process is killed as this seems to take a little while on some platforms
	if ods_is_signer_running; then
		sleep 1
		echo "ods_stop_signer: waiting for process to terminate..." >&2 
		if ods_is_signer_running; then
				echo "ods_stop_signer: ERROR: ods-signerd process is still running..." >&2 
				return 1
		fi
	fi	&&
	
	echo "ods_stop_signer: ods-signer stopped OK..." >&2 &&
	return 0
	
	return 1
}

ods_start_ods-control() {
	
	if ods_is_signer_running; then
		echo "ods_start_ods-control: ERROR: ods-signerd is already running.." >&2
		return 1
	fi
	if ods_is_enforcer_running; then
		echo "ods_start_ods-control: ERROR: ods-enforcerd is already running.." >&2
		return 1
	fi			
		
	echo "ods_start_ods-control: Starting ods-signer now..." >&2 &&
	
 	ods_signer_count_starts &&
    local ods_signer_start_count="$syslog_grep_count_variable" &&
 	ods_enforcer_count_starts &&
    local ods_enforcer_start_count="$syslog_grep_count_variable" &&

	ods_ods-control_start	&&
		
	ods_signer_waitfor_starts $(( ods_signer_start_count + 1 )) &&
	ods_enforcer_waitfor_starts $(( ods_enforcer_start_count + 1 )) &&	
	
	echo "ods_start_ods-control: ods-control started OK..." >&2 &&
	return 0
	
	return 1	
	
}

ods_stop_ods-control() {
	
	if ! ods_is_signer_running; then
		echo "ods_stop_ods-control: ERROR: ods-signerd is not running.." >&2
		return 1
	fi
	if ! ods_is_enforcer_running; then
		echo "ods_stop_ods-control: ERROR: ods-enforcerd is not running.." >&2
		return 1
	fi			
		
	echo "ods_stop_ods-control: Stopping ods-signer now..." >&2 &&
	
 	ods_signer_count_stops &&
    local ods_signer_stop_count="$syslog_grep_count_variable" &&
 	ods_enforcer_count_stops &&
    local ods_enforcer_stop_count="$syslog_grep_count_variable" &&

	ods_ods-control_stop &&
		
	ods_signer_waitfor_stops $(( ods_signer_stop_count + 1 )) &&
	ods_enforcer_waitfor_stops $(( ods_enforcer_stop_count + 1 )) &&	
	
	# double check the process is killed as this seems to take a little while on some platforms
	if ods_is_signer_running || ods_is_enforcer_running; then
		sleep 1
		echo "ods_stop_signer: waiting for processes to terminate..." >&2 
		if ods_is_signer_running; then
				echo "ods_stop_signer: ERROR: ods-signerd process is still running..." >&2 
				return 1
		fi
		if ods_is_enforcer_running; then
				echo "ods_stop_signer: ERROR: ods-enforcerd process is still running..." >&2 
				return 1
		fi		
	fi	&&
	
	
	echo "ods_stop_ods-control: ods-control stopped OK..." >&2 &&
	return 0
	
	return 1

}



ods_kill ()
{
	if ! pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null; then
		return 0
	fi
	
	echo "ods_kill: Killing OpenDNSSEC"
	try_run 15 ods-control stop
	
	if pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null; then
		sleep 2
		pkill -QUIT '(ods-enforcerd|ods-signerd)' 2>/dev/null
		if pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null; then
			sleep 2
			pkill -TERM '(ods-enforcerd|ods-signerd)' 2>/dev/null
			if pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null; then
				sleep 2
				pkill -KILL '(ods-enforcerd|ods-signerd)' 2>/dev/null
				pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null &&
				sleep 2
			fi
		fi
	fi
	
	if pgrep -u `id -u` '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null; then
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
		softhsm=$INSTALL_ROOT/bin/softhsm
	elif [ -x "$INSTALL_ROOT/bin/softhsm-util" ]; then
		# we're using SoftHSMv2
		softhsm=$INSTALL_ROOT/bin/softhsm-util
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

ods_compare_gold_vs_base_signconf() {
	
	
		# Method to compare a 'gold' directory containing signconfs with a 'base' directory
		# generated during a test run. Assumes the directories are called 'gold' and 'base'
		# and the script is called from the directory which holds both of them.
		# It replaces the key CKS_IDS in the <Locator> tags with indexes to allow a diff.
		# It also ignores the <Salt> tag contents
		# See enforcer.keys.rollovers_and_zones_many for an example of how it is used. 
		
		local all_locators
		local unique_locators
		local indexed_locators	
		local unique_sort_command

        for test_dir in gold base; do
                if [ ! -d "$test_dir" ]; then
                          echo "compare_gold_vs_base: directory $test_dir no found" >&2
                          return 1
                 fi
	
                temp_dir="$test_dir"_temp
				rm -rf $temp_dir
				mkdir  $temp_dir
				unset $"all_locators"
				unset $"unique_locators"
				unset $"indexed_locators"
				
                if ! cd "$test_dir" 2>/dev/null; then
                        echo "compare_gold_vs_base: unable to change to test directory $test_dir!" >&2
                        return 1
                fi      

				files=( $(ls -1 2>/dev/null ) )
                if [ "${#files[@]}" -le 0 ] 2>/dev/null; then
                        echo "compare_gold_vs_base: no files found!" >&2
                        return 1
                fi
				
				# fish out the key locators
				for f in ${files[@]};do
                        all_locators+=( $($GREP -- "<Locator>" $f | awk -F">" '{print $2}' | awk -F"<" '{print $1}' ) )							
				done					
				
				# remove duplicates, retaining order (OpenBSD doesn't support nl utility add line numbers the long way)
				line_no=0
				for f in ${all_locators[@]};do
					indexed_locators+=($(echo $line_no"-"$f"_"))
					line_no=$(($line_no+1))
				done	
				
				# sort routine requires -s (stable sort) to give consistent results across all platforms. 
				# However solaris doesn't support -s, but gives consistent result without it 
				unique_sort_command="sort -u -k2 -s"
				case "$DISTRIBUTION" in
					sunos )
						unique_sort_command="sort -u -k2"
						;;
				esac
											
				unique_locators=($(echo "${indexed_locators[@]}"  | tr -d ' ' | tr '_' '\n' | tr '-' ' ' | $unique_sort_command | sort -n | cut -f2 -d ' '))						

				# create a replacement string for all the locators
				index=0
				replace_string="sed "
				for i in ${unique_locators[@]}; do
				   replace_string+=" -e 's#$i#$index#' "
				   index=$(($index+1))
				done
				
				# ignore the contents of the <Salt> tag
				replace_string+=" -e 's#<Salt>.*#<Salt></Salt>#' "				
				
				#apply to each of the files
				for f in ${files[@]}; do
					 eval $replace_string $f > ../$temp_dir/$f
				done

                cd ..
        done

		if ! diff gold_temp base_temp; then
			return 1
		fi
		
		rm -rf gold_temp
		rm -rf base_temp
		return 0		
        
}
