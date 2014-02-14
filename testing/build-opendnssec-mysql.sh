#!/usr/bin/env bash
source `dirname "$0"`/lib.sh && init || exit 1

require ldns
require softhsm

check_if_built opendnssec-mysql && exit 0
start_build opendnssec-mysql

build_ok=0
case "$DISTRIBUTION" in
	openbsd )
		export AUTOCONF_VERSION="2.68"
		export AUTOMAKE_VERSION="1.11"
		;;
	netbsd | \
	freebsd )
		append_cflags "-std=c99"
		;;
	opensuse )
		append_ldflags "-lncurses -lpthread"
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
	opensuse | \
	suse )
		(
			sh autogen.sh &&
			mkdir -p build &&
			cd build &&
			../configure --prefix="$INSTALL_ROOT" \
				--with-enforcer-database=mysql \
				--with-enforcer-database-test-database=build \
				--with-enforcer-database-test-host=localhost \
				--with-enforcer-database-test-username=build \
				--with-enforcer-database-test-password=build \
				--enable-timeshift &&
			$MAKE &&
			$MAKE check &&
			sed_inplace 's% -ge 5 % -ge 30 %g' tools/ods-control &&
			$MAKE install &&
			cp "conf/addns.xml" "$INSTALL_ROOT/etc/opendnssec/addns.xml.build" &&
			cp "conf/conf.xml" "$INSTALL_ROOT/etc/opendnssec/conf.xml.build" &&
			cp "conf/kasp.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml.build" &&
			cp "conf/zonelist.xml" "$INSTALL_ROOT/etc/opendnssec/zonelist.xml.build" &&
			sed 's%<Datastore><SQLite>.*</SQLite></Datastore>%<Datastore><MySQL><Host>localhost</Host><Database>test</Database><Username>test</Username><Password>test</Password></MySQL></Datastore>%g' "$INSTALL_ROOT/etc/opendnssec/conf.xml.build" > "$INSTALL_ROOT/etc/opendnssec/conf.xml.build.$$" &&
			mv "$INSTALL_ROOT/etc/opendnssec/conf.xml.build.$$" "$INSTALL_ROOT/etc/opendnssec/conf.xml.build"
		) &&
		build_ok=1
		;;
	sunos )
		(
			sh autogen.sh &&
			mkdir -p build &&
			cd build &&
			../configure --prefix="$INSTALL_ROOT" \
				--with-mysql=/usr/mysql/5.1 \
				--with-enforcer-database=mysql \
				--with-enforcer-database-test-database=build \
				--with-enforcer-database-test-host=localhost \
				--with-enforcer-database-test-username=build \
				--with-enforcer-database-test-password=build \
				--enable-timeshift &&
			$MAKE &&
			$MAKE check &&
			sed_inplace 's% -ge 5 % -ge 30 %g' tools/ods-control &&
			$MAKE install &&
			cp "conf/addns.xml" "$INSTALL_ROOT/etc/opendnssec/addns.xml.build" &&
			cp "conf/conf.xml" "$INSTALL_ROOT/etc/opendnssec/conf.xml.build" &&
			cp "conf/kasp.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml.build" &&
			cp "conf/zonelist.xml" "$INSTALL_ROOT/etc/opendnssec/zonelist.xml.build" &&
			sed 's%<Datastore><SQLite>.*</SQLite></Datastore>%<Datastore><MySQL><Host>localhost</Host><Database>test</Database><Username>test</Username><Password>test</Password></MySQL></Datastore>%g' "$INSTALL_ROOT/etc/opendnssec/conf.xml.build" > "$INSTALL_ROOT/etc/opendnssec/conf.xml.build.$$" &&
			mv "$INSTALL_ROOT/etc/opendnssec/conf.xml.build.$$" "$INSTALL_ROOT/etc/opendnssec/conf.xml.build"
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
				--with-enforcer-database=mysql \
				--with-enforcer-database-test-database=build \
				--with-enforcer-database-test-host=localhost \
				--with-enforcer-database-test-username=build \
				--with-enforcer-database-test-password=build \
				--enable-timeshift \
				--with-sqlite3=/usr/pkg &&
			$MAKE &&
			$MAKE check &&
			sed_inplace 's% -ge 5 % -ge 30 %g' tools/ods-control &&
			$MAKE install &&
			cp "conf/addns.xml" "$INSTALL_ROOT/etc/opendnssec/addns.xml.build" &&
			cp "conf/conf.xml" "$INSTALL_ROOT/etc/opendnssec/conf.xml.build" &&
			cp "conf/kasp.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml.build" &&
			cp "conf/zonelist.xml" "$INSTALL_ROOT/etc/opendnssec/zonelist.xml.build" &&
			sed 's%<Datastore><SQLite>.*</SQLite></Datastore>%<Datastore><MySQL><Host>localhost</Host><Database>test</Database><Username>test</Username><Password>test</Password></MySQL></Datastore>%g' "$INSTALL_ROOT/etc/opendnssec/conf.xml.build" > "$INSTALL_ROOT/etc/opendnssec/conf.xml.build.$$" &&
			mv "$INSTALL_ROOT/etc/opendnssec/conf.xml.build.$$" "$INSTALL_ROOT/etc/opendnssec/conf.xml.build"
		) &&
		build_ok=1
		;;
	freebsd )
		(
			sh autogen.sh &&
			mkdir -p build &&
			cd build &&
			../configure --prefix="$INSTALL_ROOT" \
				--with-enforcer-database=mysql \
				--with-enforcer-database-test-database=build \
				--with-enforcer-database-test-host=localhost \
				--with-enforcer-database-test-username=build \
				--with-enforcer-database-test-password=build \
				--enable-timeshift &&
			$MAKE &&
			#$MAKE check && # segfaults #0  0x00000008019363dc in _pthread_mutex_init_calloc_cb () from /lib/libc.so.7
			(cd enforcer-ng && $MAKE check) &&
			sed_inplace 's% -ge 5 % -ge 30 %g' tools/ods-control &&
			$MAKE install &&
			cp "conf/addns.xml" "$INSTALL_ROOT/etc/opendnssec/addns.xml.build" &&
			cp "conf/conf.xml" "$INSTALL_ROOT/etc/opendnssec/conf.xml.build" &&
			cp "conf/kasp.xml" "$INSTALL_ROOT/etc/opendnssec/kasp.xml.build" &&
			cp "conf/zonelist.xml" "$INSTALL_ROOT/etc/opendnssec/zonelist.xml.build" &&
			sed 's%<Datastore><SQLite>.*</SQLite></Datastore>%<Datastore><MySQL><Host>localhost</Host><Database>test</Database><Username>test</Username><Password>test</Password></MySQL></Datastore>%g' "$INSTALL_ROOT/etc/opendnssec/conf.xml.build" > "$INSTALL_ROOT/etc/opendnssec/conf.xml.build.$$" &&
			mv "$INSTALL_ROOT/etc/opendnssec/conf.xml.build.$$" "$INSTALL_ROOT/etc/opendnssec/conf.xml.build"
		) &&
		build_ok=1
		;;
esac

finish

if [ "$build_ok" -eq 1 ]; then
	set_build_ok opendnssec-mysql || exit 1
	exit 0
fi

exit 1
