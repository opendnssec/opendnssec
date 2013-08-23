#!/usr/bin/env bash
#
#TEST: Test to see that the DSSEEN command is dealt with as expected
#TEST: We use TIMESHIFT to get to the point where the KSK moves to the ready state

ENFORCER_WAIT=90	# Seconds we wait for enforcer to run
ZONE_STEPS=10        # Number of zones to add each step 
MAX_ZONES=20        # Maximum zones to be added in the whole test 

NUMBER_OF_ZONES=0   # Counter for number of zones currently in use
NUMBER_OF_RUNS=1    # Needed to count the syslog entries

STATUS=0

command_run_time () {

	$GREP -- "START:" _log.$BUILD_TAG.$2.stdout 1>start.log  2>/dev/null &&
	$GREP -- "STOP:"  _log.$BUILD_TAG.$2.stdout 1>stop.log   2>/dev/null &&

	measure_time "$1" "COMMAND"	 &&
	return 0
	
}

enforcer-ng_run_time () {

	local TIME_DIFF=`$GREP -- '.*completed in' _log.$BUILD_TAG.$2.stdout | awk '{print $4}'` &&
	printf "MEASURING: %-20s with %6s zones     RESULT (ENFORCER run time): %6d seconds,  which is  %2d hours  %2d minutes  %2d seconds\n" $1 $NUMBER_OF_ZONES $TIME_DIFF $((TIME_DIFF / (60*60))) $(((TIME_DIFF%(60*60))/60)) $((TIME_DIFF % 60)) >> enforcer-benchmark-times &&

	return 0
	
}


measure_time () {
	
	# Check the counts match
	local START_COUNT=`wc -l start.log | awk '{print $1}'` &&
    local STOP_COUNT=`wc -l stop.log | awk '{print $1}'` &&
	if [ $START_COUNT -ne $STOP_COUNT ]; then
		echo "Counts do not match"
		return 1
	fi &&

	# Compare the last entries
	local START_TIME=`tail -n 1 start.log | awk '{print $3}'` &&
	local STOP_TIME=`tail -n 1 stop.log | awk '{print $3}'` &&

	local START_HOUR=`echo $START_TIME | awk '{ s=substr($1,1,2); print s}' | sed 's/0*//'` &&
	local START_MIN=`echo $START_TIME | awk '{ s=substr($1,4,2); print s}' | sed 's/0*//'` &&
	local START_SEC=`echo $START_TIME | awk '{ s=substr($1,7,2); print s}' | sed 's/0*//'` &&
	local STOP_HOUR=`echo $STOP_TIME | awk '{ s=substr($1,1,2); print s}' | sed 's/0*//' ` &&
	local STOP_MIN=`echo $STOP_TIME | awk '{ s=substr($1,4,2); print s}' | sed 's/0*//'` &&
	local STOP_SEC=`echo $STOP_TIME | awk '{ s=substr($1,7,2); print s}' | sed 's/0*//'` &&

	local TIME_1=$(( START_HOUR*60*60 + START_MIN*60 + START_SEC )) &&
	local TIME_2=$(( STOP_HOUR*60*60 + STOP_MIN*60 + STOP_SEC )) &&

	local TIME_DIFF=$(( TIME_2 - TIME_1 )) &&
	printf "MEASURING: %-20s with %6s zones     RESULT (%-8s run time): %6d seconds,  which is  %2d hours  %2d minutes  %2d seconds\n" $1 $NUMBER_OF_ZONES $2 $TIME_DIFF $((TIME_DIFF / (60*60))) $(((TIME_DIFF%(60*60))/60)) $((TIME_DIFF % 60)) >> enforcer-benchmark-times &&
	return 0
}

# Clear out the zone dir
rm unsigned/ods_* 
rm enforcer-benchmark-times start.log stop.log

if [ -n "$HAVE_MYSQL" ]; then
        ods_setup_conf conf.xml conf-mysql.xml
fi &&

ods_reset_env &&

log_this_timeout ods-control-enforcer-start 30 ods-control enforcer start &&
syslog_waitfor 60 'ods-enforcerd: .*\[engine\] enforcer started' &&

ods_setup_env &&

#log_this_timeout ods-control-enforcer-start $ENFORCER_WAIT ods-control enforcer stop  &&
#syslog_waitfor 60 'ods-enforcerd: .*\[engine\] enforcer shutdown' &&

log_this ods-control-enforcer-start echo "-------Setup complete" &&

while ( [ $STATUS -eq 0 ] && [ $NUMBER_OF_ZONES -lt $MAX_ZONES ] ); do
	
	##################  ADD THE ZONES FOR THIS STEP ###########################	
	log_this ods-control-enforcer-start echo " "  &&
	log_this ods-control-enforcer-start echo " " &&	
	log_this ods-control-enforcer-start echo "------- Starting zone add" && 	
	if [ $? -eq 1 ]; then
		echo "could not start enforcer for zone add"
		return 1
	fi		
	for (( ZONE_COUNT=1; ZONE_COUNT<=$ZONE_STEPS; ZONE_COUNT++ )); do
		NUMBER_OF_ZONES=$((NUMBER_OF_ZONES + 1)) &&
		sed s/ods./ods_$NUMBER_OF_ZONES./g unsigned/ods > unsigned/ods_$NUMBER_OF_ZONES &&
		log_this ods-control-enforcer-start ods-enforcer zone add --zone ods_$NUMBER_OF_ZONES  --policy default --signerconf $INSTALL_ROOT/var/opendnssec/signconf/ods_$NUMBER_OF_ZONES.xml --input unsigned/ods_$NUMBER_OF_ZONES --output $INSTALL_ROOT/var/opendnssec/signed/ods_$NUMBER_OF_ZONES &&
	    log_this ods-control-enforcer-start echo "Added zone" 
		if [ $? -eq 1 ]; then
			echo "could not perform zone add"
			return 1
		fi	
	done
#	log_waitfor ods-control-enforcer-start stdout 90 "update Zone complete: ods_$NUMBER_OF_ZONES" &&
	#syslog_waitfor $ENFORCER_WAIT  "ods-enforcerd: .*\[enforcer\] update Zone complete: ods_$NUMBER_OF_ZONES" && 
	sleep 10 &&
	log_this ods-control-enforcer-start echo "------- Zone add complete" &&
	log_this ods-control-enforcer-start echo " "  &&
	log_this ods-control-enforcer-start echo " " &&

	##################  RUN SOME STUFF ###########################
	# Start enforcer 

    log_this ods-control-enforcer-start echo "------- First timing run " &&		
	log_this ods-control-enforcer-start echo "Enforcing " &&	
	log_this_timeout ods-enforce-$NUMBER_OF_RUNS $ENFORCER_WAIT ods-enforcer enforce && 		
	sleep 3 &&			
	log_waitfor ods-enforce-$NUMBER_OF_RUNS stdout 90 "enforce completed in" &&
	log_this ods-control-enforcer-start echo "Done Enforcing " &&
	enforcer-ng_run_time "First_run" ods-enforce-$NUMBER_OF_RUNS &&	
	NUMBER_OF_RUNS=$((NUMBER_OF_RUNS+1)) &&
	
	# And run the enforcer again
    log_this ods-control-enforcer-start echo "------- Second timing run " &&	
	log_this_timeout ods-enforce-$NUMBER_OF_RUNS $ENFORCER_WAIT ods-enforcer enforce  &&
	sleep 3 &&	
	log_waitfor ods-enforce-$NUMBER_OF_RUNS stdout 90 "completed in" &&
	enforcer-ng_run_time "Second_run" ods-enforce-$NUMBER_OF_RUNS &&
	NUMBER_OF_RUNS=$((NUMBER_OF_RUNS+1)) &&	

    # Lets list the keys and see how long that takes
	log_this ods-key-list echo "START:" `date '+%d %H:%M:%S'` &&
	log_this_timeout ods-key-list $ENFORCER_WAIT ods-enforcer key list  &&
	log_this ods-key-list echo "STOP:" `date '+%d %H:%M:%S'` &&
	command_run_time "Key_list" ods-key-list &&
	log_this ods-control-enforcer-start echo "------- Completed first timing loop" 
    STATUS=$?	
    echo " "  >> enforcer-benchmark-times
	
done

if [ $STATUS -eq 0 ]; then
	echo
	echo "************Test passed******************"
	echo
	return 1
fi

echo
echo "************ERROR******************"
echo
ods_kill
return 1



