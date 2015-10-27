NUMBER_ZONES=4000
NUMBER_REPEATS=1
ZONE_COUNTER=0
STATUS=0
MYEND=0
MYSTART=0
RUN=0
DEBUG_OUTPUT=/dev/null
#DEBUG_OUTPUT=/tmp/log
RESULTS_OUTPUT="performance_results.log"

[ x$DEBUG_OUTPUT != "x/dev/null" ] && rm -f $DEBUG_OUTPUT

killall fakesigner.sh >> $DEBUG_OUTPUT 2>&1
killall nc >> $DEBUG_OUTPUT 2>&1

# Do the work...
echo "******** WORKING ********" >> $DEBUG_OUTPUT 2>&1
echo $RESULTS_TITLE > $RESULTS_OUTPUT 2>&1
log_this fakesignerlog ./fakesigner.sh &
for (( r = 1 ; r <= $NUMBER_REPEATS ; r += 1 )); do
  [ $STATUS -ne 0 ] && exit 1
  ZONE_COUNTER=$(($ZONE_COUNTER + $NUMBER_ZONES )) 
  echo " "  >> $RESULTS_OUTPUT 2>&1
  echo -n "1 to $ZONE_COUNTER," >> $RESULTS_OUTPUT 2>&1
  generate_zonelist_xml $ZONE_COUNTER 1
  MYSTART=`date +%s%N`
    cp -- zonelist.1-$ZONE_COUNTER.xml $INSTALL_ROOT/etc/opendnssec/zonelist.xml
    log_this test_output "Importing zonelist zonelist.1-$ZONE_COUNTER.xml" 
    $INSTALL_ROOT/$KSM_UTIL zonelist import >> $DEBUG_OUTPUT 2>&1
    STATUS=$?
    check_status zonelist_import q
  MYEND=`date +%s%N`
  calc_runtime
  echo -n "$RUN," >> $RESULTS_OUTPUT 2>&1

  if [ $OPENDNSSEC_VERSION -eq 2 ] ; then
    $INSTALL_ROOT/$KSM_UTIL hsm key gen -d P1Y >> $DEBUG_OUTPUT 2>&1
    MYSTART=`date +%s%N`
    $INSTALL_ROOT/$KSM_UTIL enforce >> $DEBUG_OUTPUT 2>&1
    log_this test_output "Enforcing zones"
#    syslog_waitfor 600  "update Zone: txt$ZONE_COUNTER" >> $DEBUG_OUTPUT 2>&1
#    log_waitfor fakesignerlog stdout 600 "update txt$ZONE_COUNTER"
    while [ 1 ] ; do
      [ 0`grep -c Locator $INSTALL_ROOT/var/opendnssec/signconf/txt$ZONE_COUNTER.xml 2>/dev/null` -gt 0 ] && break
      sleep 1
    done    
    MYEND=`date +%s%N`
    calc_runtime
    echo -n "$RUN,"  >> $RESULTS_OUTPUT 2>&1
    
    
   #ods_nuke_env 
   #cp zonelist.xml $INSTALL_ROOT/etc/opendnssec/zonelist.xml
   #ods_setup_env
   rm zonelist.1-*
  else

    # TESTING ENFORCER RUN
    sleep 10
    test_enforcer
    echo -n "$RUN," >> $RESULTS_OUTPUT 2>&1
  fi
    # TESTING KEY LIST
    #test_keylist
    #echo "$RUN" >> $RESULTS_OUTPUT 2>&1
done

exit 0

# Do some simple sanity checks...
# grep for 1st zone in zonelist
echo "******** SANITY CHECKS ********" >> $DEBUG_OUTPUT 2>&1
time_zonelist_export
echo "Time to export zonelist:            $RUN" >> $RESULTS_OUTPUT 2>&1
grep \"txt1\" $INSTALL_ROOT/etc/opendnssec/zonelist.xml >> $DEBUG_OUTPUT 2>&1
STATUS=$?
check_status first_grep q
# grep for $ZONE_COUNTER zone in zonelist"
grep \"txt$ZONE_COUNTER\" $INSTALL_ROOT/etc/opendnssec/zonelist.xml >> $DEBUG_OUTPUT 2>&1
STATUS=$?
check_status second_grep q
echo "Sanity checks:                      passed" >> $RESULTS_OUTPUT 2>&1
echo

if [ $OPENDNSSEC_VERSION -eq 2 ] ; then
# do a time leap (2 days?) to make ZSKs published
# do a time leap (another 2 days) to make the ZSKs active
# start timing
# do another time leap more than 90 days to force an automatic rollover
# wait until there are 3 keys in the signconfs
# stop timing
  LEAPTIME=`date --utc -d "2 days"  +%Y-%m-%d-%H:%M:%S`
  $INSTALL_ROOT/$KSM_UTIL time leap --time $LEAPTIME >> $DEBUG_OUTPUT 2>&1
  LEAPTIME=`date --utc -d "4 days"  +%Y-%m-%d-%H:%M:%S`
  $INSTALL_ROOT/$KSM_UTIL time leap --time $LEAPTIME >> $DEBUG_OUTPUT 2>&1
  LEAPTIME=`date --utc -d "100 days"  +%Y-%m-%d-%H:%M:%S`
  MYSTART=`date +%s%N`
  $INSTALL_ROOT/$KSM_UTIL time leap --time $LEAPTIME >> $DEBUG_OUTPUT 2>&1
  while [ 1 ] ; do
    [ 0`grep -c Locator $INSTALL_ROOT/var/opendnssec/signconf/txt$ZONE_COUNTER.xml 2>/dev/null` -eq 3 ] && break
  sleep 1
  done
  MYEND=`date +%s%N`
  calc_runtime
  echo "Time to run ZSK rollover:           $RUN"  >> $RESULTS_OUTPUT 2>&1
  MYSTART=`date +%s%N`
  $INSTALL_ROOT/$KSM_UTIL zone delete --zone txt1 >> $DEBUG_OUTPUT 2>&1
  MYEND=`date +%s%N`
  calc_runtime
  echo "Time to delete 1 zone:              $RUN"  >> $RESULTS_OUTPUT 2>&1

fi

# TESTING KEY ROLLOVER
#test_key_rollover
#echo "Time to run ZSK rollover:           $RUN"

# TESTING KEY LIST AFTER ROLLOVER
#test_keylist
#echo "Time to run key list:               $RUN"

# TESTING ENFORCER RUN
#test_enforcer
#echo "Time to run enforcer once:          $RUN"

# TESTING ENFORCER RUN AGAIN
#test_enforcer
#echo "Time to run enforcer a second time: $RUN"

# TESTING KEY LIST
#test_keylist
#echo "Time to run key list:               $RUN"
killall fakesigner.sh >> $DEBUG_OUTPUT 2>&1
killall nc >> $DEBUG_OUTPUT 2>&1
