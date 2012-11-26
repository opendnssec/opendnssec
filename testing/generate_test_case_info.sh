#!/usr/bin/env bash

# Script to extract information on the test cases by scanning the directories and files.
# Currently writes the information to a csv file.

# TODO
# - get platform specific grep from framework
# - offer output to text file?
# - add other info to output...

OUTPUT_FILE_NAME="test_info.csv"

generate_test_info() {
	
	test_status="ON"	
	if [ -a "off" ]; then
		test_status="OFF"
	fi
	# Replace any commas with dashes since we will write to a csv file	
	test_description=`grep "^#TEST:" test.sh | sed s/#TEST://g | sed s/,/-/g` 
	test_category=`grep "^#CATEGORY:" test.sh | sed s/#CATEGORY://g | sed s/,/-/g`
	# Just extract the issue identifier
	test_issues=`grep "^#OPENDNSSEC\|^#SUPPORT" test.sh | sed s/#//g | sed 's/ .*//' `
	test_todo=`grep "^#TODO:" test.sh | sed s/#TODO://g | sed s/,/-/g` 
	
 	echo $1","$test_path","$test_status","$test_category","$test_description","$test_issues","$test_todo >> $OUTPUT_FILE

}

if [ -n "$1" ]; then
	
	if [ "$1" == "--help" -o "$1" == "-help" -o "$1" == "-h"  ]; then
		echo "usage: generate_test_case_info <test directory (optional-default is pwd)>" >&2
		exit 0
	fi	
	
	if [ -d "$1" ]; then		
		if ! cd "$1" 2>/dev/null; then
			echo "generate_test_case_info: unable to change to test directory $1!" >&2
			exit 1
		fi
	else
		echo "generate_test_case_info: test directory $1 does not exist" >&2
		exit 1					
	fi
fi

pwd=`pwd`
echo "Searching top level directory "$pwd" for tests"
OUTPUT_FILE=$pwd/$OUTPUT_FILE_NAME
rm $OUTPUT_FILE
echo "Directory,Name,Status,Category,Description,Issues,To do" > $OUTPUT_FILE

for LOCAL_TEST_DIR in test-cases.d test-cases-daily.d test-cases-weekly.d; do

	if [ -d "$LOCAL_TEST_DIR" ]; then
		if ! cd "$LOCAL_TEST_DIR" 2>/dev/null; then
			echo "generate_test_case_info: unable to change to test directory $LOCAL_TEST_DIR!" >&2
			continue
		fi
		echo "Searching sub directory " $LOCAL_TEST_DIR " for tests"
		
		test_num=0	
		ls -1 2>/dev/null | grep '^[0-9]*'  2>/dev/null >"tests.list"
		while read entry; do
			if [ -d "$entry" -a -f "$entry/test.sh" ]; then
				test[test_num]="$entry"
				test_num=$(( test_num + 1 ))
			fi
		done <"tests.list"
		rm -f "tests.list" 2>/dev/null
	
		if [ "$test_num" -le 0 ] 2>/dev/null; then
			echo "generate_test_case_info: no tests found!" >&2
		    exit 1
		fi	
	
		test_iter=0
		while [ "$test_iter" -lt "$test_num" ] 2>/dev/null; do
			test_path="${test[test_iter]}"
			test_iter=$(( test_iter + 1 ))
			pwd2=`pwd`
			cd "$test_path" 2>/dev/null 
		
			echo "  Found $test_path... "
			
			generate_test_info $LOCAL_TEST_DIR

			if ! cd "$pwd2" 2>/dev/null; then
				echo "run_tests: unable to change back to test directory $pwd2 after checking a test!" >&2
				exit 1
			fi
		done

		if ! cd "$pwd" 2>/dev/null; then
			echo "run_tests: unable to change back to directory $pwd after checking tests!" >&2
			exit 1
		fi	
	
	fi
done

echo "Done."
echo "Output written to: " $OUTPUT_FILE

exit 0
