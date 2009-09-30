# $Id$

m4_sinclude([version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec], OPENDNSSEC_VERSION)

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

AC_CONFIG_SUBDIRS([ libhsm enforcer signer xml ])


# xml
AC_PATH_PROG(XMLLINT, xmllint)
AC_PATH_PROG(JAVA, java)

# libhsm
ACX_LIBXML2
ACX_LDNS
ACX_DLOPEN

# libksm
AC_PATH_PROG(PERL, perl)
if test -z "$PERL"; then
   AC_MSG_ERROR([perl not found])
fi
ACX_CUNIT
ACX_SQLITE3
AM_PATH_PYTHON
ACX_DBPARAMS

# auditor
AC_ARG_ENABLE(auditor,
	AC_HELP_STRING([--disable-auditor],
		[Disable auditor build (default enabled)]),
	[],[])
if test "${enable_auditor+set}" != set; then
	enable_auditor=yes
fi
if test "${enable_auditor}" = yes; then
	AM_PATH_RUBY([], [], [])
	AC_CONFIG_SUBDIRS([ auditor ])
fi

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
