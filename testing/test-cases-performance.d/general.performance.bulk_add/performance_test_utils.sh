# OpenDNSSEC version specific parameters
VERSION=`$INSTALL_ROOT/sbin/ods-enforcerd -V 2>&1 | grep 2.0.0`
if ( [ -z "$VERSION" ] ); then
  export OPENDNSSEC_VERSION=1
  export ENFORCER="ods-enforcerd -1 -d"
  export KSM_UTIL=bin/ods-ksmutil
  export XML_ARGS="--no-xml"
else
  export OPENDNSSEC_VERSION=2
  export ENFORCER="ods-enforcer enforce"
  export ENFORCERD="ods-enforcerd"
  export KSM_UTIL=sbin/ods-enforcer
  export XML_ARGS=""
fi
export RESULTS_TITLE="number of zones,time to add,wait for enforcer,keylist"

# Check the value of the STATUS variable
# Takes 2 parameters: a text string to indicate what failed
# and a flag q to indicate quiet i.e. don't print test passed messages
check_status() {
  if ( [ $STATUS -ne 0 ] ) ; then 
    echo "******** TEST $1 FAILED ********"
    exit $STATUS
  else
    [ x$2 != "xq" ] && echo "******** TEST $1 PASSED ********"
  fi
}

# calculate the runtime between $MYSTART and $MYEND which are 
# expressed in nanoseconds and convert to seconds with 3 decimal places.
calc_runtime() {
  # dc is RPN Calculator
  RUN=`echo "3k $MYEND $MYSTART - 1000000000 / p" | dc `
}

test_enforcer() {
  echo "******** TESTING ENFORCER ********" >> $DEBUG_OUTPUT 2>&1
  MYSTART=`date +%s%N`
  if ( [ x$1 == "xp" ] ) ; then
    /usr/bin/valgrind --tool=callgrind $INSTALL_ROOT/sbin/$ENFORCER >> $DEBUG_OUTPUT 2>&1
    STATUS=$?
    check_status test_enforcer q
  else 
    $INSTALL_ROOT/sbin/$ENFORCER >> $DEBUG_OUTPUT 2>&1
    STATUS=$?
    check_status test_enforcer q
  fi
  MYEND=`date +%s%N`
  calc_runtime
}

test_keylist() {
  echo "******** TESTING KEYLIST ********" >> $DEBUG_OUTPUT 2>&1
  MYSTART=`date +%s%N`
  $INSTALL_ROOT/$KSM_UTIL key list --verbose >> $DEBUG_OUTPUT 2>&1
  STATUS=$?
  check_status test_keylist q
  MYEND=`date +%s%N`
  calc_runtime
}

test_key_rollover() {
  echo "******** TESTING KEY ROLLOVER ********" >> $DEBUG_OUTPUT 2>&1
  MYSTART=`date +%s%N`
  echo "y" | $INSTALL_ROOT/$KSM_UTIL key rollover --policy default --keytype ZSK >> $DEBUG_OUTPUT 2>&1
  STATUS=$?
  check_status test_key_rollover q
  MYEND=`date +%s%N`
  calc_runtime
}

time_zonelist_export() {
  echo "******** TIMING ZONE LIST EXPORT ********" >> $DEBUG_OUTPUT 2>&1
  MYSTART=`date +%s%N`
  $INSTALL_ROOT/$KSM_UTIL zonelist export > $INSTALL_ROOT/etc/opendnssec/zonelist.xml
  STATUS=$?
  check_status time_zonelist_export q
  MYEND=`date +%s%N`
  calc_runtime
}

# Generate a zonelist file containing $1 zones numbered from $2 to $1+$2-1 and
# call it zonelist.$2-(( $1+$2-1 )).xml
generate_zonelist_xml() {
  MYFIRST=$2
  MYLAST=$(( $1+$2-1 ))
  MYZONELISTNAME=zonelist.$MYFIRST-$MYLAST.xml
  echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ZoneList>" > $MYZONELISTNAME
  for (( i = $MYFIRST ; i <= $MYLAST ; i +=1 )); do
    echo "<Zone name=\"txt$i\">" >> $MYZONELISTNAME
    echo "<Policy>default</Policy>" >> $MYZONELISTNAME
    echo "<SignerConfiguration>$INSTALL_ROOT/var/opendnssec/signconf/txt$i.xml</SignerConfiguration>" >> $MYZONELISTNAME
    echo "<Adapters>" >> $MYZONELISTNAME
    echo "<Input>" >> $MYZONELISTNAME
    echo "<Adapter type=\"File\">$INSTALL_ROOT/var/opendnssec/unsigned/zone.txt$i</Adapter>" >> $MYZONELISTNAME
    echo "</Input>" >> $MYZONELISTNAME
    echo "<Output>" >> $MYZONELISTNAME
    echo "<Adapter type=\"File\">$INSTALL_ROOT/var/opendnssec/signed/txt$i</Adapter>" >> $MYZONELISTNAME
    echo "</Output>" >> $MYZONELISTNAME
    echo "</Adapters>" >> $MYZONELISTNAME
    echo "</Zone>" >> $MYZONELISTNAME
  done
  echo "</ZoneList>" >> $MYZONELISTNAME
}

#ods_ods-control_enforcer_start() {
#
#        if  ! log_this_timeout ods_ods-control_enforcer_start $ODS_ENFORCER_WAIT_START /usr/bin/valgrind --tool=callgrind $INSTALL_ROOT/sbin/$ENFORCERD ; then
#                echo "ods_ods-control_enforcer_start: ERROR: Could not start ods-enforcerd. Exiting..." >&2
#                return 1
#        fi
#        return 0
#
#}
