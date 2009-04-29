#!/bin/sh

cd /tmp/jad/opendnssec

#Import the example xml from /tmp/jad/opendnssec/etc/opendnssec/ in to the DB
/tmp/jad/opendnssec/bin/kaspimport.pl -h test1 -u root -s test -i -d

#Start the key generator
/tmp/jad/opendnssec/bin/keygend -u jad -n root -p "" -s test -h test1 -P /tmp/jad/opendnssec/keygend.pid


sleep 10

killall -9 keygend


echo "Look in the system logs and see what happened."