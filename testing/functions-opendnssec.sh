#!/usr/bin/env bash

ods_pre_test ()
{
	if [ -e softhsm.conf ]; then
		if ! cp softhsm.conf "$INSTALL_ROOT/etc/softhsm.conf" 2>/dev/null; then
			echo "pre_test: unable to copy/install test specific softhsm.conf to $INSTALL_ROOT/etc/softhsm.conf" >&2
			return 1
		fi
	else
		if ! cp "$INSTALL_ROOT/etc/softhsm.conf.build" "$INSTALL_ROOT/etc/softhsm.conf" 2>/dev/null; then
			echo "pre_test: unable to copy/install build default $INSTALL_ROOT/etc/softhsm.conf.build to $INSTALL_ROOT/etc/softhsm.conf" >&2
			return 1
		fi
	fi

	for file in addns.xml conf.xml kasp.xml zonelist.xml; do
		if [ -e "$file" ]; then
			if ! cp "$file" "$INSTALL_ROOT/etc/opendnssec/$file" 2>/dev/null; then
				echo "pre_test: unable to copy/install test specific $file to $INSTALL_ROOT/etc/opendnssec/$file" >&2
				return 1
			fi
		else
			if ! cp "$INSTALL_ROOT/etc/opendnssec/$file.build" "$INSTALL_ROOT/etc/opendnssec/$file" 2>/dev/null; then
				echo "pre_test: unable to copy/install build default $INSTALL_ROOT/etc/opendnssec/$file.build to $INSTALL_ROOT/etc/opendnssec/$file" >&2
				return 1
			fi
		fi
	done
}

ods_post_test ()
{
	true
}

ods_reset_env ()
{
	echo "ods_reset_env: resetting opendnssec environment"
	echo "y" | ods-enforcer setup &&
	log_this softhsm-init-token softhsm --init-token --slot 0 --label OpenDNSSEC --pin 1234 --so-pin 1234 ||
	return 1
	
	if ! log_grep softhsm-init-token stdout "The token has been initialized."; then
		return 1
	fi
}
