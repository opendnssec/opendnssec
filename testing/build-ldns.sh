#!/usr/bin/env bash
source `dirname "$0"`/lib.sh && init || exit 1

LDNS="ldns-1.6.17"
LDNS_URL="http://nlnetlabs.nl/downloads/ldns/$LDNS.tar.gz"
LDNS_FILENAME="$LDNS.tar.gz"
LDNS_HASH_TYPE="sha1"
LDNS_HASH="4218897b3c002aadfc7280b3f40cda829e05c9a4"

check_if_built ldns && exit 0
start_build ldns

LDNS_SRC=`fetch_src "$LDNS_URL" "$LDNS_FILENAME" "$LDNS_HASH_TYPE" "$LDNS_HASH"`

build_ok=0
case "$DISTRIBUTION" in
	sunos )
		if uname -m 2>/dev/null | $GREP -q -i sun4v 2>/dev/null; then
			append_cflags  "-m64"
			append_ldflags "-m64"
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
	opensuse | \
	suse | \
	freebsd | \
	sunos | \
	openbsd | \
	netbsd )
		(
			gunzip -c "$LDNS_SRC" | tar xf - &&
			cd "$LDNS" &&
			./configure --prefix="$INSTALL_ROOT" \
				--enable-stderr-msgs \
				--disable-gost \
				--disable-ecdsa &&
			$MAKE &&
			$MAKE install
		) &&
		build_ok=1
		;;
esac

finish

if [ "$build_ok" -eq 1 ]; then
	set_build_ok ldns || exit 1
	exit 0
fi

exit 1
