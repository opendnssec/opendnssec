#!/bin/sh

MYDIR=/home/sion/temp/opendnssec

export LD_LIBRARY_PATH=$MYDIR/install/lib:/home/sion/work/subversion/ldns/lib
export SOFTHSM_CONF=$MYDIR/install/etc/opendnssec/softhsm.conf

cd $MYDIR

echo "Test1: mysql DB in conf.xml"
cp $MYDIR/trunk/testing/enforcer/examples/lite-sion-loop-conf.xml $MYDIR/install/etc/opendnssec/conf.xml
cp $MYDIR/trunk/testing/enforcer/examples/kasp.xml $MYDIR/install/etc/opendnssec/kasp.xml
cp $MYDIR/trunk/testing/enforcer/examples/sion-softhsm.conf $MYDIR/install/etc/opendnssec/softhsm.conf
cp $MYDIR/trunk/testing/enforcer/examples/sion-zonelist.xml $MYDIR/install/etc/opendnssec/zonelist.xml

$MYDIR/install/bin/softhsm --init-token --slot 0 --label "alice"

#Import the example xml from /tmp/jad/opendnssec/etc/opendnssec/ in to the DB
$MYDIR/install/bin/kaspimport -f $MYDIR/install/var/opendnssec/enforcer.db -i

#Start the key generator
$MYDIR/install/sbin/keygend -u sion -d &

echo "THIS SHOULD BE SORTED SOMEWHERE ELSE!!!\nCREATING CONF DIRECTORY\n"
mkdir $MYDIR/install/var/opendnssec/config

$MYDIR/install/sbin/communicated -u sion -P comm.pid -d &

sleep 300

killall -9 keygend
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
