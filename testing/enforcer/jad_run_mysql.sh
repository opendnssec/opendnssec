#!/bin/sh

MYDIR=/tmp/jad/opendnssec

cd $MYDIR

echo "Test1: mysql DB in conf.xml"
cp $MYDIR/trunk/testing/enforcer/examples/mysql-conf.xml $MYDIR/install/etc/opendnssec/conf.xml

#Import the example xml from /tmp/jad/opendnssec/etc/opendnssec/ in to the DB
$MYDIR/install/bin/kaspimport -h test1 -u root -s test -i

#Start the key generator
$MYDIR/install/bin/keygend -u jad -d &

sleep 10
killall -9 keygend
echo "Look in the system logs and see what happened."

echo "Test2: mysql DB in conf.xml"
cp $MYDIR/trunk/testing/enforcer/examples/mysql-bad-conf.xml $MYDIR/install/etc/opendnssec/conf.xml

#Import the example xml from /tmp/jad/opendnssec/etc/opendnssec/ in to the DB
$MYDIR/install/bin/kaspimport -h test1 -u root -s test -i

#Start the key generator
$MYDIR/install/bin/keygend -u jad -d &

sleep 10
killall -9 keygend
echo "Look in the system logs and see what happened."