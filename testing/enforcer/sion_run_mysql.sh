#!/bin/sh

MYDIR=/home/sion/temp/opendnssec

export LD_LIBRARY_PATH=$MYDIR/install/lib:/home/sion/work/subversion/ldns/lib
export SOFTHSM_CONF=$MYDIR/install/var/softhsm.conf

cd $MYDIR

echo "Test1: mysql DB in conf.xml"
cp $MYDIR/trunk/testing/enforcer/examples/mysql-sion-conf.xml $MYDIR/install/etc/opendnssec/conf.xml
cp $MYDIR/trunk/testing/enforcer/examples/sion-softhsm.conf $MYDIR/install/etc/opendnssec/softhsm.conf

#Import the example xml from /tmp/jad/opendnssec/etc/opendnssec/ in to the DB
$MYDIR/install/bin/kaspimport -h localhost -u ksm_test -p ksm_test -s ksm -i

#Start the key generator
$MYDIR/install/bin/keygend -u sion -d &

sleep 10
killall -9 keygend
echo "Look in the system logs and see what happened."

echo "Running communicator\n"

echo "THIS SHOULD BE SORTED SOMEWHERE ELSE!!!\nCREATING CONF DIRECTORY\n"
mkdir $MYDIR/install/var/config

$MYDIR/install/bin/communicated -u sion -P comm.pid -d &

sleep 10
killall -9 communicated
echo "Look in the system logs and see what happened."

#
#echo "Test2: mysql DB in conf.xml"
#cp $MYDIR/trunk/testing/enforcer/examples/mysql-bad-conf.xml $MYDIR/install/etc/opendnssec/conf.xml
#
##Import the example xml from /tmp/jad/opendnssec/etc/opendnssec/ in to the DB
#$MYDIR/install/bin/kaspimport -h localhost -u ksm_test -p ksm_test -s ksm -i
#
##Start the key generator
#$MYDIR/install/bin/keygend -u sion -d &
#
#sleep 10
#killall -9 keygend
#echo "Look in the system logs and see what happened."
