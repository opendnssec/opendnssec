# $Id$

m4_sinclude([version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec-auditor], OPENDNSSEC_VERSION)

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

OPENDNSSEC_COMMON

AM_PROG_RUBY
ACX_RUBY_LIBRARY([syslog openssl xsd/datatypes rexml/document])
ACX_DNSRUBY(1.46)

# check for xmllint
AC_PATH_PROG(XMLLINT, xmllint)
if test "x$XMLLINT" = "x"; then
    AC_MSG_ERROR([xmllint required, but not found.])
fi

# check for a decent grep
AC_PATH_PROGS(GREP, ggrep grep,[
    AC_MSG_ERROR([grep required, but not found.])
])
AC_SUBST([GREP])
#
AC_MSG_CHECKING([for grep compability])
if (echo "alpha\naardvark\n" | ${GREP} '^a\|^b' >/dev/null); then
    AC_MSG_RESULT([ok])
else
    AC_MSG_RESULT([failed])
    AC_MSG_ERROR([grep does not work as expected])
fi

# check for a decent sort
AC_PATH_PROGS(SORT, gsort sort,[
    AC_MSG_ERROR([sort required, but not found.])
])
AC_SUBST([SORT])
#
AC_MSG_CHECKING([for sort compability])
if ${SORT} -c $srcdir/sorttest.txt >/dev/null 2>&1; then
    AC_MSG_RESULT([ok])
else
    AC_MSG_RESULT([failed])
    AC_MSG_ERROR([sort does not work as expected])
fi

full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_datadir=`eval eval eval eval eval echo "${datadir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

AC_SUBST(TIMESHIFT, false)

AC_ARG_ENABLE(timeshift,
	AC_HELP_STRING([--enable-timeshift], [Enable timeshift debug]),
		[enable_timeshift="${enableval}"],
		[enable_timeshift="no"])
if test "x${enable_timeshift}" = "xyes"; then
	AC_SUBST(TIMESHIFT, true)
	AC_MSG_CHECKING(if we should do timeshift debugging)
	AC_MSG_RESULT(yes)
fi

AC_CONFIG_FILES([
	Makefile
	ods-auditor
	ods-auditor.1
	ods-kaspcheck
	ods-kaspcheck.1
        lib/kasp_auditor/commands.rb
])

AC_OUTPUT
