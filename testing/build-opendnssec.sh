#!/usr/bin/env bash
source `dirname "$0"`/lib.sh && init || exit 1

# OPENDNSSEC-721, OPENDNSSEC-745:
# We cannot use the build system to build SoftHSM2 without breaking
# other builds.  Since changing the build-bot/tasks and upgrading
# Jenkins will allow for a more flexible set-up we just use a
# temporary make script to build botan and softhsm2.
# the LD_LIBRARY_PATH is necessary too unfortunately.
if [ -x `dirname "$0"`/make.sh ] ; then
  if [ "`uname -n`" = "ubuntu10-ods01" ]; then
    # OPENDNSSEC-755
    # Old, no longer in LTS Ubuntu 10 machine will fail due to historic
    # version of libbotan (1.8.2) and pre 1.0 version of OpenSSL, where
    # SoftHSM requires at least one of them working.
    check_if_built opendnssec && exit 0
    start_build opendnssec
    set_build_ok opendnssec || exit 1
    exit 0
  fi

  export INSTALL_TAG INSTALL_ROOT WORKSPACE
  LD_LIBRARY_PATH=$INSTALL_ROOT/lib
  `dirname "$0"`/make.sh
fi

require softhsm2

check_if_built opendnssec && exit 0
start_build opendnssec

build_ok=0
case "$DISTRIBUTION" in
	openbsd )
		export AUTOCONF_VERSION="2.69"
		export AUTOMAKE_VERSION="1.11"
		;;
	netbsd | \
	freebsd )
		;;
	redhat )
		export PATH=/usr/local/src/autoconf-2.69/bin:$PATH
		;;
	opensuse )
		append_ldflags "-lncurses -lpthread"
		;;
	debian )
		append_ldflags "-lpthread"
		;;
	sunos )	
		if uname -m 2>/dev/null | $GREP -q -i sun4v 2>/dev/null; then
			append_cflags "-std=gnu99"
			append_cflags  "-m64"
			append_ldflags "-m64"
		else
			append_cflags "-std=c99"
		fi
	    ;;		
esac
case "$DISTRIBUTION" in
	centos | \
	redhat | \
	fedora | \
	sl | \
	ubuntu | \
	debian | \
	openbsd | \
	sunos | \
	opensuse | \
	slackware | \
	suse )
		(
			sh autogen.sh &&
			mkdir -p build &&
			cd build &&
			../configure --prefix="$INSTALL_ROOT" \
				--with-enforcer-database=sqlite3 \
				--with-enforcer-database-test-database=opendnssec-build-test &&
			$MAKE &&
			$MAKE check &&
			sed_inplace 's% -ge 5 % -ge 30 %g' tools/ods-control &&
			$MAKE install &&
			cp "conf/addns.xml" "$INSTALL_ROOT/etc/opendnssec/addns.xml.build" &&
			cp "conf/conf.xml" "$INSTALL_ROOT/etc/opendnssec/conf.xml.build" &&
			cp "conf/kasp.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml.build" &&
			cp "conf/zonelist.xml" "$INSTALL_ROOT/etc/opendnssec/zonelist.xml.build"
		) &&
		build_ok=1
		;;
	netbsd )
		(
			sh autogen.sh &&
			mkdir -p build &&
			cd build &&
			../configure --prefix="$INSTALL_ROOT" \
				--with-cunit=/usr/pkg \
				--with-enforcer-database=sqlite3 \
				--with-enforcer-database-test-database=opendnssec-build-test \
				--with-sqlite3=/usr/pkg &&
			$MAKE &&
			$MAKE check &&
			sed_inplace 's% -ge 5 % -ge 30 %g' tools/ods-control &&
			$MAKE install &&
			cp "conf/addns.xml" "$INSTALL_ROOT/etc/opendnssec/addns.xml.build" &&
			cp "conf/conf.xml" "$INSTALL_ROOT/etc/opendnssec/conf.xml.build" &&
			cp "conf/kasp.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml.build" &&
			cp "conf/zonelist.xml" "$INSTALL_ROOT/etc/opendnssec/zonelist.xml.build"
		) &&
		build_ok=1
		;;
	freebsd )
		(
			sh autogen.sh &&
			mkdir -p build &&
			cd build &&
			../configure --prefix="$INSTALL_ROOT" \
				--with-enforcer-database=sqlite3 \
				--with-enforcer-database-test-database=opendnssec-build-test &&
			$MAKE &&
			$MAKE check &&
			sed_inplace 's% -ge 5 % -ge 30 %g' tools/ods-control &&
			$MAKE install &&
			cp "conf/addns.xml" "$INSTALL_ROOT/etc/opendnssec/addns.xml.build" &&
			cp "conf/conf.xml" "$INSTALL_ROOT/etc/opendnssec/conf.xml.build" &&
			cp "conf/kasp.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml.build" &&
			cp "conf/zonelist.xml" "$INSTALL_ROOT/etc/opendnssec/zonelist.xml.build"
		) &&
		build_ok=1
		;;
esac

finish

if [ "$build_ok" -eq 1 ]; then
	set_build_ok opendnssec || exit 1
	exit 0
fi

exit 1
