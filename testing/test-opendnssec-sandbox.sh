#!/usr/bin/env bash
source `dirname "$0"`/lib.sh && init || exit 1
source `dirname "$0"`/functions-opendnssec.sh || exit 1

require opendnssec

# clean out the sandbox
cd test-cases-sandbox.d
rm -rf enforcer.* signer.* general.*
cd ..

# now copy only test dirs that contain the sandbox file. ignore the 'off' status
for test_dir in test-cases.d test-cases-daily.d; do
	cd $test_dir
	ls -1  2>/dev/null >"_sb_tests.$BUILD_TAG"
	while read entry; do
		if [ -d "$entry" -a -f "$entry/test.sh" ]; then
		    if [ -f "$entry/sandbox" ]; then
				echo "Found test for sandbox: " $test_dir/$entry
				cp -r $entry ../test-cases-sandbox.d
				rm ../test-cases-sandbox.d/$entry/off
			fi
		fi
	done <"_sb_tests.$BUILD_TAG"
	rm -f "_sb_tests.$BUILD_TAG" 2>/dev/null
	cd ..
done

#check_if_tested sandbox && exit 0
start_test sandbox

PRE_TEST=ods_pre_test
POST_TEST=ods_post_test
INTERRUPT_TEST=ods_interrupt_test
RETRY_TEST=1
test_ok=0
(
	ods_find_softhsm_module &&
	run_tests test-cases-sandbox.d
) &&
test_ok=1

stop_test
finish

if [ "$test_ok" -eq 1 ]; then
	set_test_ok sandbox || exit 1
	exit 0
fi

exit 1
