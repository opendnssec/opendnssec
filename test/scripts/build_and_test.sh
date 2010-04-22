#!/bin/sh
#
# $Id$

SANDBOX_ROOT=${HOME}/ODS
LIBSOFTHSM=/usr/local/lib/libsofthsm.so


# Build and test OpenDNSSEC
# Uses $HOME/ODS for install sandbox
rm -rf ${SANDBOX_ROOT}

sh autogen.sh
./configure --prefix=${SANDBOX_ROOT} --with-pkcs11-softhsm=${LIBSOFTHSM}
rc=$?
if [[ $rc != 0 ]] ; then
    exit $rc
fi
make install
rc=$?
if [[ $rc != 0 ]] ; then
    exit $rc
fi

make check 
rc=$?
if [[ $rc != 0 ]] ; then
    exit $rc
fi

export SOFTHSM_CONF=test/scripts/softhsm.conf

echo "yes" | ${SANDBOX_ROOT}/bin/ods-ksmutil setup

softhsm --init-token --slot 0  --pin 1234 --so-pin 1234 --label "OpenDNSSEC"
rc=$?
if [[ $rc != 0 ]] ; then
    exit $rc
fi

cp test/zonedata/unknown.rr.org ${SANDBOX_ROOT}/var/opendnssec/unsigned/.
${SANDBOX_ROOT}/bin/ods-ksmutil zone add -z  unknown.rr.org -p default
cp test/zonedata/example.com ${SANDBOX_ROOT}/var/opendnssec/unsigned/.
${SANDBOX_ROOT}/bin/ods-ksmutil zone add -z  example.com -p default
cp test/zonedata/all.rr.org ${SANDBOX_ROOT}/var/opendnssec/unsigned/.
${SANDBOX_ROOT}/bin/ods-ksmutil zone add -z  all.rr.org -p default
cp test/zonedata/all.rr.binary.org ${SANDBOX_ROOT}/var/opendnssec/unsigned/.
${SANDBOX_ROOT}/bin/ods-ksmutil zone add -z  all.rr.binary.org -p default
${SANDBOX_ROOT}/bin/ods-ksmutil update all
${SANDBOX_ROOT}/bin/ods-ksmutil key generate --interval P1Y --policy default

# TODO - this should be replaced by ods-control start when it is fixed
${SANDBOX_ROOT}/sbin/ods-enforcerd -1
sleep 5
${SANDBOX_ROOT}/sbin/ods-enforcerd 
sleep 5
${SANDBOX_ROOT}/sbin/ods-signerd
sleep 5
${SANDBOX_ROOT}/sbin/ods-signer zones
sleep 1
${SANDBOX_ROOT}/sbin/ods-signer sign unknown.rr.org
${SANDBOX_ROOT}/sbin/ods-signer sign example.com
echo ${SANDBOX_ROOT}/sbin/ods-signer sign all.rr.org
echo ${SANDBOX_ROOT}/sbin/ods-signer sign all.rr.binary.org
sleep 5

${SANDBOX_ROOT}/sbin/ods-control stop

echo "NOW CHECK THAT ZONES HAVE BEEN SIGNED"
echo Still to check all.rr.org and all.rr.binary.org
ruby test/scripts/check_zones_exist.sh unknown.rr.org example.com

ret=$?
exit $ret

