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
	return 0
	
	return 1
}

ods_setup_env ()
{
	if ! pgrep -u `id -u` 'ods-enforcerd' >/dev/null 2>/dev/null; then
		echo "ods_setup_env: Unable to setup environment, ods-enforcerd needs to be running" >&2
		return 1
	fi

	echo "ods_setup_env: setting up opendnssec environment"
	
	echo 'y' | log_this ods-enforcer-setup 'ods-enforcer setup' &&	
	log_waitfor ods-enforcer-setup stdout 30 'setup completed in' &&
	! log_grep ods-enforcer-setup stdout 'failed' &&
	! log_grep ods-enforcer-setup stdout 'error starting a database transaction' &&
	! log_grep ods-enforcer-setup stdout 'could not' &&
	! log_grep ods-enforcer-setup stdout 'missing required fields' &&
	! log_grep ods-enforcer-setup stdout 'out of memory' &&
	echo "ods_setup_env: setup complete" &&
	return 0
	
	echo "ods_setup_env: setup failed!" >&2
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
