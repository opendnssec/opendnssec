#!/usr/bin/env bash

ods_pre_test ()
{
	ods_nuke_env &&
	ods_setup_conf &&
	ods_reset_env &&
	return 0
	
	return 1
}

ods_post_test ()
{
	true
}

ods_nuke_env ()
{
	local tmp_files=`ls "$INSTALL_ROOT/var/opendnssec/tmp/" 2>/dev/null`
	local unsigned_files=`ls "$INSTALL_ROOT/var/opendnssec/unsigned/" 2>/dev/null`
	local signed_files=`ls "$INSTALL_ROOT/var/opendnssec/signed/" 2>/dev/null`
	local softhsm_files=`ls "$INSTALL_ROOT/var/softhsm/" 2>/dev/null`
	
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
	if [ -f softhsm.conf ]; then
		if ! cp softhsm.conf "$INSTALL_ROOT/etc/softhsm.conf" 2>/dev/null; then
			echo "pre_test: unable to copy/install test specific softhsm.conf to $INSTALL_ROOT/etc/softhsm.conf" >&2
			return 1
		fi
		
		apply_parameter "INSTALL_ROOT" "$INSTALL_ROOT" "$INSTALL_ROOT/etc/softhsm.conf" ||
		return 1
	else
		if ! cp "$INSTALL_ROOT/etc/softhsm.conf.build" "$INSTALL_ROOT/etc/softhsm.conf" 2>/dev/null; then
			echo "pre_test: unable to copy/install build default $INSTALL_ROOT/etc/softhsm.conf.build to $INSTALL_ROOT/etc/softhsm.conf" >&2
			return 1
		fi
	fi

	for file in conf.xml kasp.xml zonefetch.xml zonelist.xml; do
		if [ -f "$file" ]; then
			if ! cp "$file" "$INSTALL_ROOT/etc/opendnssec/$file" 2>/dev/null; then
				echo "pre_test: unable to copy/install test specific $file to $INSTALL_ROOT/etc/opendnssec/$file" >&2
				return 1
			fi
			
			apply_parameter "INSTALL_ROOT" "$INSTALL_ROOT" "$INSTALL_ROOT/etc/opendnssec/$file" &&
			apply_parameter "SOFTHSM_MODULE" "$SOFTHSM_MODULE" "$INSTALL_ROOT/etc/opendnssec/$file" ||
			return 1
		else
			if ! cp "$INSTALL_ROOT/etc/opendnssec/$file.build" "$INSTALL_ROOT/etc/opendnssec/$file" 2>/dev/null; then
				echo "pre_test: unable to copy/install build default $INSTALL_ROOT/etc/opendnssec/$file.build to $INSTALL_ROOT/etc/opendnssec/$file" >&2
				return 1
			fi
		fi
	done
	
	if [ -d unsigned ]; then
		ls -1 unsigned/ | while read file; do
			if [ -f "unsigned/$file" ]; then
				if ! cp -f "unsigned/$file" "$INSTALL_ROOT/var/opendnssec/unsigned/" 2>/dev/null; then
					echo "pre_test: unable to copy/install zone file $file to $INSTALL_ROOT/var/opendnssec/unsigned/" >&2
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
	
	echo "y" | ods-ksmutil setup &&
	ods_softhsm_init_token 0 &&
	return 0
	
	return 1
}

ods_kill ()
{
	echo "ods_kill: Killing OpenDNSSEC"
	ods-control stop
	if pgrep '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null; then
		sleep 2
		pkill -QUIT '(ods-enforcerd|ods-signerd)' 2>/dev/null
		if pgrep '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null; then
			sleep 2
			pkill -TERM '(ods-enforcerd|ods-signerd)' 2>/dev/null
			if pgrep '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null; then
				sleep 2
				pkill -KILL '(ods-enforcerd|ods-signerd)' 2>/dev/null
				pgrep '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null &&
				sleep 2
			fi
		fi
	fi
	
	if pgrep '(ods-enforcerd|ods-signerd)' >/dev/null 2>/dev/null; then
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
	local dir
	
	for path in lib64/softhsm lib/softhsm lib64 lib; do
		if [ -f "$INSTALL_ROOT/$path/libsofthsm.so" ]; then
			export SOFTHSM_MODULE="$INSTALL_ROOT/$path/libsofthsm.so"
			return 0
		fi
	done
	
	return 1
}
