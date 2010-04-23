#!/bin/sh
#
# $Id$

if [ -z "${WORKSPACE}" ]; then
	echo "Workspace not defined - exiting..."
	exit 1
fi

SANDBOX=${WORKSPACE}/sandbox
SRCDIR=${WORKSPACE}/OpenDNSSEC
OBJDIR=${WORKSPACE}/obj

LIBSOFTHSM=/usr/local/lib/libsofthsm.so

SOFTHSM_TEMPLATE=${SRCDIR}/test/conf/softhsm.conf
SOFTHSM_CONF=${SANDBOX}/etc/softhsm.conf
export SOFTHSM_CONF

# Build, install and test OpenDNSSEC into ${SANDBOX}
build_opendnssec()
{
	rm -rf ${SANDBOX}
	rm -rf ${OBJDIR}

	mkdir ${SANDBOX}
	mkdir ${OBJDIR}

	(cd ${SRCDIR}; sh autogen.sh)

	(cd ${OBJDIR}; ${SRCDIR}/configure \
		--prefix=${SANDBOX} \
		--with-pkcs11-softhsm=${LIBSOFTHSM})
	rc=$?
	if [[ $rc != 0 ]] ; then
	    exit $rc
	fi

	(cd ${OBJDIR}; make)
	rc=$?
	if [[ $rc != 0 ]] ; then
	    exit $rc
	fi

	(cd ${OBJDIR}; make install)
	rc=$?
	if [[ $rc != 0 ]] ; then
	    exit $rc
	fi

	(cd ${OBJDIR}; make check)
	rc=$?
	if [[ $rc != 0 ]] ; then
	    exit $rc
	fi
}

setup_softhsm()
{
	PIN=1234
	SO_PIN=1234
	SLOT=0
	LABEL="OpenDNSSEC"

	rm -f $SOFTHSM_CONF
	mkdir -p `dirname $SOFTHSM_CONF`	
	cp $SOFTHSM_TEMPLATE $SOFTHSM_CONF
	
	softhsm --init-token \
		--slot $SLOT \
		--pin $PIN \
		--so-pin $SO_PIN \
		--label $LABEL
	rc=$?
	if [[ $rc != 0 ]] ; then
	    exit $rc
	fi	
}

configure_enforcer()
{
	echo "yes" | ${SANDBOX}/bin/ods-ksmutil setup	
}

setup_test_zones()
{
	cp test/zonedata/unknown.rr.org ${SANDBOX}/var/opendnssec/unsigned
	${SANDBOX}/bin/ods-ksmutil zone add -z  unknown.rr.org -p default

	cp test/zonedata/example.com ${SANDBOX}/var/opendnssec/unsigned
	${SANDBOX}/bin/ods-ksmutil zone add -z  example.com -p default

	cp test/zonedata/all.rr.org ${SANDBOX}/var/opendnssec/unsigned
	${SANDBOX}/bin/ods-ksmutil zone add -z  all.rr.org -p default

	cp test/zonedata/all.rr.binary.org ${SANDBOX}/var/opendnssec/unsigned
	${SANDBOX}/bin/ods-ksmutil zone add -z  all.rr.binary.org -p default

	${SANDBOX}/bin/ods-ksmutil update all

	${SANDBOX}/bin/ods-ksmutil key generate --interval P1Y --policy default
}

# TODO: - this should be replaced by ods-control start when it is fixed
ods_start()
{
	${SANDBOX}/sbin/ods-enforcerd -1
	sleep 5
	${SANDBOX}/sbin/ods-enforcerd 
	sleep 5
	${SANDBOX}/sbin/ods-signerd
	sleep 5
	${SANDBOX}/sbin/ods-signer zones
	sleep 1	
}

ods_sign()
{
	${SANDBOX}/sbin/ods-signer sign unknown.rr.org
	${SANDBOX}/sbin/ods-signer sign example.com
	echo ${SANDBOX}/sbin/ods-signer sign all.rr.org
	echo ${SANDBOX}/sbin/ods-signer sign all.rr.binary.org
	sleep 5	
}

ods_stop()
{
	${SANDBOX}/sbin/ods-control stop	
}

build_opendnssec

setup_softhsm
setup_enforcer
setup_test_zones

ods_start
ods_sign
ods_stop

echo "NOW CHECK THAT ZONES HAVE BEEN SIGNED"
echo Still to check all.rr.org and all.rr.binary.org
ruby test/scripts/check_zones_exist.sh unknown.rr.org example.com

ret=$?
exit $ret
