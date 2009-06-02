#!/bin/sh

MYDIR=/tmp/jad/opendnssec

cd $MYDIR
syslog -s -l ERR "Test1: sqlite DB in conf.xml"
cp $MYDIR/trunk/testing/enforcer/examples/lite-conf.xml $MYDIR/install/etc/opendnssec/conf.xml
cp $MYDIR/trunk/testing/enforcer/examples/kasp.xml $MYDIR/install/etc/opendnssec/kasp.xml
cp $MYDIR/trunk/testing/enforcer/examples/softhsm.conf $MYDIR/install/etc/softhsm.conf

#Import the example xml from /tmp/jad/opendnssec/etc/opendnssec/ in to the DB
$MYDIR/install/bin/kaspimport -f $MYDIR/install/var/opendnssec/enforcer.db -i

#Start the key generator
$MYDIR/install/bin/keygend -u jad -d &

sleep 10
killall keygend
echo "Look in the system logs and see what happened."

syslog -s -l ERR "Test2: bad sqlite DB in conf.xml"
cp $MYDIR/trunk/testing/enforcer/examples/lite-bad-conf.xml $MYDIR/install/etc/opendnssec/conf.xml

#Import the example xml from /tmp/jad/opendnssec/etc/opendnssec/ in to the DB
$MYDIR/install/bin/kaspimport -f $MYDIR/install/var/opendnssec/enforcer.db -i

#Start the key generator
$MYDIR/install/bin/keygend -u jad -d &

sleep 10
killall keygend
echo "Look in the system logs and see what happened."

syslog -s -l ERR  "Test3: short sleep in conf.xml"
cp $MYDIR/trunk/testing/enforcer/examples/lite-short-sleep-conf.xml $MYDIR/install/etc/opendnssec/conf.xml

#Import the example xml from /tmp/jad/opendnssec/etc/opendnssec/ in to the DB
$MYDIR/install/bin/kaspimport -f $MYDIR/install/var/opendnssec/enforcer.db -i

#Start the key generator
$MYDIR/install/bin/keygend -u jad -d &

sleep 10
killall keygend
echo "Look in the system logs and see what happened."