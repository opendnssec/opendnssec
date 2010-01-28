# $Id$

m4_sinclude([../version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec-auditor], OPENDNSSEC_VERSION)

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

AM_PROG_RUBY
ACX_RUBY_LIBRARY([syslog openssl xsd/datatypes rexml/document])
ACX_DNSRUBY(1.42)

# check for xmllint
AC_PATH_PROG(XMLLINT, xmllint)
if test "x$XMLLINT" = "x"; then
    AC_MSG_ERROR([xmllint required, but not found.])
fi

full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_datadir=`eval eval eval eval eval echo "${datadir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

opendnsseclibdir=$full_libdir/opendnssec
opendnssecdatadir=$full_datadir/opendnssec

AC_SUBST([opendnsseclibdir])
AC_SUBST([opendnssecdatadir])

AC_SUBST(TIMESHIFT, false)

AC_ARG_ENABLE(timeshift,
        AC_HELP_STRING([--enable-timeshift],[Enable timeshift debug]),
        [AC_SUBST(TIMESHIFT, true)],[])

AC_CONFIG_FILES([
	Makefile
	ods-auditor
	ods-kaspcheck
])

AC_OUTPUT
