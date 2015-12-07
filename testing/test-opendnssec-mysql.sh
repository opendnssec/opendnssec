#!/usr/bin/env bash
source `dirname "$0"`/lib.sh && init || exit 1
source `dirname "$0"`/functions-opendnssec.sh || exit 1

export HAVE_MYSQL="YES"

require opendnssec-mysql

check_if_tested opendnssec-mysql && exit 0
start_test opendnssec-mysql

PRE_TEST=ods_pre_test
POST_TEST=ods_post_test
INTERRUPT_TEST=ods_interrupt_test
RETRY_TEST=0
test_ok=0
(
	# occasionaly first test complains about enforcer running
	killall ods-enforcerd

	ods_find_softhsm_module &&
	run_tests test-cases.d
) &&
test_ok=1

stop_test
finish

if [ "$test_ok" -eq 1 ]; then
	set_test_ok opendnssec-mysql || exit 1
	exit 0
fi

exit 1
