#!/bin/sh
#
# $Id$

if [ -z "${WORKSPACE}" ]; then
	echo "Workspace not defined - exiting..."
	exit 1
fi

SANDBOX=${WORKSPACE}/sandbox
SRCDIR=${WORKSPACE}/src
OBJDIR=${WORKSPACE}/obj

LIBSOFTHSM=/usr/local/lib/libsofthsm.so

SOFTHSM_TEMPLATE=${OBJDIR}/test/conf/softhsm.conf
SOFTHSM_CONF=${SANDBOX}/etc/opendnssec/softhsm.conf
export SOFTHSM_CONF



build_opendnssec()
{
	rm -rf ${SANDBOX}
	rm -rf ${OBJDIR}

	mkdir ${SANDBOX}
	mkdir ${OBJDIR}

	if [ ! -x ${SRCDIR}/configure ]; then
		(cd ${SRCDIR}; sh autogen.sh)
		rc=$?
		if [ $rc != 0 ]; then
			exit $rc
		fi
		if [ ! -x ${SRCDIR}/configure ]; then
			exit 1
		fi
	fi

	CONFIGURE_ARGS=""

	# on our solaris build system, ldns lives elsewhere
	if [ -f /opt/ldns/lib/libldns.a ]; then
		CONFIGURE_ARGS="$CONFIGURE_ARGS --with-ldns=/opt/ldns"
	fi

	if [ -f ${LIBSOFTHSM} ]; then
		CONFIGURE_ARGS="$CONFIGURE_ARGS --with-pkcs11-softhsm=${LIBSOFTHSM}"
	else
		echo "Failed to locate libsofthsm PKCS#11 provider"
		exit 1
	fi

	(cd ${OBJDIR}; ${SRCDIR}/configure \
		--prefix=${SANDBOX} ${CONFIGURE_ARGS})
	rc=$?
	if [ $rc != 0 ]; then
		exit $rc
	fi

	(cd ${OBJDIR}; make)
	rc=$?
	if [ $rc != 0 ]; then
		exit $rc
	fi

        cp ${OBJDIR}/auditor/lib/kasp_auditor/commands.rb ${SRCDIR}/auditor/lib/kasp_auditor/

	(cd ${OBJDIR}; make check)
	rc=$?
	if [ $rc != 0 ]; then
		exit $rc
	fi
}

install_opendnssec()
{
	(cd ${OBJDIR}; make install)
	rc=$?
	if [ $rc != 0 ]; then
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
	if [ $rc != 0 ]; then
	    exit $rc
	fi	
}

setup_enforcer()
{
	echo "yes" | ${SANDBOX}/bin/ods-ksmutil setup	
}

setup_test_zones()
{
	cp ${SRCDIR}/test/zonedata/* ${SANDBOX}/var/opendnssec/unsigned

	${SANDBOX}/bin/ods-ksmutil zone add -z  unknown.rr.org -p default
	${SANDBOX}/bin/ods-ksmutil zone add -z  example.com -p default
	${SANDBOX}/bin/ods-ksmutil zone add -z  all.rr.org -p default
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
install_opendnssec

setup_softhsm
setup_enforcer
setup_test_zones

ods_start
ods_sign
ods_stop

echo "NOW CHECK THAT ZONES HAVE BEEN SIGNED"
echo Still to check all.rr.org and all.rr.binary.org
ruby ${SRCDIR}/test/scripts/check_zones_exist.sh unknown.rr.org example.com

ret=$?
exit $ret
