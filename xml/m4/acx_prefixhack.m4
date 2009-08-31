# $Id$
#
# Special processing of paths depending on whether --prefix,
# --sysconfdir or --localstatedir arguments were given.

AC_DEFUN([ACX_PREFIXHACK],[
	case "$prefix" in
		NONE)
			case "$sysconfdir" in
				'${prefix}/etc')
					sysconfdir=/etc
					;;
			esac
			case "$localstatedir" in
				'${prefix}/var')
					localstatedir=/var
					;;
			esac
			;;
	esac
])
