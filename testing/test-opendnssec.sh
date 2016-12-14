#!/usr/bin/env bash
source `dirname "$0"`/lib.sh && init || exit 1
source `dirname "$0"`/functions-opendnssec.sh || exit 1

require opendnssec

check_if_tested opendnssec && exit 0
start_test opendnssec

# OPENDNSSEC-721, OPENDNSSEC-745, OPENDNSSEC-755:
# We cannot use the build system to build SoftHSM2 without breaking
# other builds.
# Jenkins will allow for a more flexible set-up we just use a
# temporary make script to exclude the tests on the old, no longer
# in LTS Ubuntu 10 machine, which will fail due to historic version
# of libbotan (1.8.2) and pre 1.0 version of OpenSSL, where SoftHSM
# requires at least one of them working.
if [ "`uname -n`" = "ubuntu10-ods01" ]; then
  set_test_ok opendnssec || exit 1
  exit 0
fi

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
	set_test_ok opendnssec || exit 1
	exit 0
fi

exit 1
