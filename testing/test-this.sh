#!/usr/bin/env bash

export INSTALL_TAG=local-test
export WORKSPACE=`pwd`
export SVN_REVISION=1

source `dirname "$0"`/lib.sh && init || exit 1
source `dirname "$0"`/functions-opendnssec.sh || exit 1

start_test opendnssec

PRE_TEST=ods_pre_test
POST_TEST=ods_post_test
INTERRUPT_TEST=ods_interrupt_test
RETRY_TEST=1

test_ok=0
(
	log_cleanup && syslog_cleanup
	ods_find_softhsm_module &&
	run_test ${PWD##*/} .
) &&
test_ok=1

stop_test
finish

if [ "$test_ok" -eq 1 ]; then
	exit 0
fi

exit 1
