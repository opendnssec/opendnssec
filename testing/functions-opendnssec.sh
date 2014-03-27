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
ODS_SIGNER_START_LOG_STRING='ods-signerd: .*\[engine\] signer started'

ODS_ENFORCER_STOP_LOG_STRING='ods-enforcerd: .*\[engine\] enforcer shutdown'
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
	local tmp_files=`ls "$INSTALL_ROOT/var/opendnssec/signer/" 2>/dev/null`
	local tmp_files2=`ls "$INSTALL_ROOT/var/opendnssec/tmp/" 2>/dev/null`
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
	ods_setup_env $1 &&
	return 0
	
	return 1
}

ods_setup_env ()
{

	ods_start_enforcer &&

	echo "ods_setup_env: setting up opendnssec environment" &&
	
	echo 'y' | log_this ods-enforcer-setup 'ods-enforcer setup' &&	
	log_waitfor ods-enforcer-setup stdout 30 'setup completed in' &&
	! log_grep ods-enforcer-setup stdout 'failed' &&
	! log_grep ods-enforcer-setup stdout 'error starting a database transaction' &&
	! log_grep ods-enforcer-setup stdout 'could not' &&
	! log_grep ods-enforcer-setup stdout 'missing required fields' &&
	! log_grep ods-enforcer-setup stdout 'out of memory' &&
	echo "ods_setup_env: setup complete" >&2 &&
	
	# Give the enforcer a chance to do some basics after the 15 second retry
	if [ -n "$1" ]; then
		echo "Sleeping to let the enforcer do some work" &&
		sleep $1 
	fi	 &&
	
    ods_stop_enforcer &&
	echo "ods_setup_env: setup env suceeded!" >&2 && 
	return 0
	
	echo "ods_setup_env: setup failed!" >&2
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
	
	if  ! log_this_timeout ods_enforcer_start_timeshift $ODS_ENFORCER_WAIT_START ods-enforcerd -1 ; then
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
	return 0
}

ods_enforcer_count_stops() {
	
	# Counts the number of times the enforcer has already stopped by
	# seting up the $syslog_grep_count_variable to contain a count of stops
	echo "ods_enforcer_count_stops: Checking how many times enforcer has stopped already"
    syslog_grep_count 0 "$ODS_ENFORCER_STOP_LOG_STRING"
    echo "ods_enforcer_count_stops: Enforcer has stopped" $syslog_grep_count_variable "times so far"
	return 0
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
	local timeout="$1"
	local stop_count

	if ods_is_enforcer_running; then
		echo "ods_start_enforcer_timeshift: ERROR: ods-enforcerd is already running.." >&2
		return 1
	fi		
		
	echo "ods_start_enforcer_timeshift: Starting ods-enforcer now..."
	
	# When the enforcer runs in timeshift mode it runs to completion
	# so it has to be measured as a stop
 	ods_enforcer_count_stops
    stop_count=$(( syslog_grep_count_variable + 1 ))
    
	ods_enforcer_start_timeshift &&
	ods_enforcer_waitfor_stops "$stop_count" "$timeout" &&
	
	# double check the process is killed as this seems to take a little while on some platforms
	if ods_is_enforcer_running; then
		sleep 1
		echo "ods_stop_enforcer: waiting for process to terminate..."
		if ods_is_enforcer_running; then
				echo "ods_stop_enforcer: ERROR: ods-enforcerd process is still running..." >&2 
				return 1
		fi
	fi &&
	
	echo "ods_start_enforcer_timeshift: ods-enforcer started OK..." &&
	return 0
	
	echo "ods_start_enforcer_timeshift: ods-enforcer start FAILED" >&2
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
