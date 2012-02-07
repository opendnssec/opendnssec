#!/usr/bin/env bash
source `dirname "$0"`/lib.sh && init || exit 1

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

	for	file in conf.xml kasp.xml zonelist.xml; do
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
	echo "ods_reset_env: reseting opendnssec environment"
	echo "y" | ods-ksmutil setup &&
	log_this softhsm-init-token softhsm --init-token --slot 0 --label OpenDNSSEC --pin 1234 --so-pin 1234 ||
	return 1
	
	if ! log_grep softhsm-init-token stdout "The token has been initialized."; then
		return 1
	fi
}

require opendnssec

check_if_tested opendnssec && exit 0
start_test opendnssec

PRE_TEST=ods_pre_test
POST_TEST=ods_post_test
test_ok=0
(
	run_tests test-cases.d
) &&
test_ok=1

stop_test

if [ "$test_ok" -eq 1 ]; then
	set_test_ok opendnssec || exit 1
	exit 0
fi

exit 1
