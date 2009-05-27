#!/bin/sh

MYDIR=/tmp/jad/opendnssec

cd $MYDIR

echo "Test1: sqlite DB in conf.xml"
cp $MYDIR/trunk/testing/enforcer/examples/lite-conf.xml $MYDIR/install/etc/opendnssec/conf.xml

#Import the example xml from /tmp/jad/opendnssec/etc/opendnssec/ in to the DB
$MYDIR/install/bin/kaspimport -f $MYDIR/install/var/opendnssec/enforcer.db -i

#Start the key generator
$MYDIR/install/bin/keygend -u jad -d &

sleep 10
killall -9 keygend
echo "Look in the system logs and see what happened."

echo "Test2: bad sqlite DB in conf.xml"
cp $MYDIR/trunk/testing/enforcer/examples/lite-bad-conf.xml $MYDIR/install/etc/opendnssec/conf.xml

#Import the example xml from /tmp/jad/opendnssec/etc/opendnssec/ in to the DB
$MYDIR/install/bin/kaspimport -f $MYDIR/install/var/opendnssec/enforcer.db -i

#Start the key generator
$MYDIR/install/bin/keygend -u jad -d &

sleep 10
killall -9 keygend
echo "Look in the system logs and see what happened."

echo "Test3: short sleep in conf.xml"
cp $MYDIR/trunk/testing/enforcer/examples/lite-short-sleep-conf.xml $MYDIR/install/etc/opendnssec/conf.xml

#Import the example xml from /tmp/jad/opendnssec/etc/opendnssec/ in to the DB
$MYDIR/install/bin/kaspimport -f $MYDIR/install/var/opendnssec/enforcer.db -i

#Start the key generator
$MYDIR/install/bin/keygend -u jad -d &

sleep 10
killall -9 keygend
echo "Look in the system logs and see what happened."