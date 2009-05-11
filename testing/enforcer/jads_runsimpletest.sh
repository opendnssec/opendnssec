#!/bin/sh

MYDIR=/tmp/jad/opendnssec

cd $MYDIR

#Import the example xml from /tmp/jad/opendnssec/etc/opendnssec/ in to the DB
$MYDIR/install/bin/kaspimport -h test1 -u root -s test -i -d

#Start the key generator
$MYDIR/install/bin/keygend -u jad -n root -p "" -s test -h test1 -P $MYDIR/install/etc/opendnssec/keygend.pid


sleep 10

killall -9 keygend


echo "Look in the system logs and see what happened."