# $Id$

m4_sinclude([version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec], OPENDNSSEC_VERSION)

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

OPENDNSSEC_COMMON

AC_CONFIG_SUBDIRS([ libhsm enforcer signer conf ])

# xml
AC_PATH_PROG(XMLLINT, xmllint)
AC_PATH_PROG(XSLTPROC, xsltproc)
AC_PATH_PROG(JAVA, java)

# libhsm
ACX_LIBXML2
ACX_LDNS(1,6,4)
ACX_DLOPEN

# libksm
AC_PATH_PROG(PERL, perl)
if test -z "$PERL"; then
   AC_MSG_ERROR([perl not found])
fi
ACX_CUNIT
AM_PATH_PYTHON
ACX_DBPARAMS
ACX_PKCS11_MODULES

# auditor
AC_ARG_ENABLE(auditor,
	AC_HELP_STRING([--disable-auditor],
		[Disable auditor build (default enabled)]),
		[enable_auditor="${enableval}"],
		[enable_auditor="yes"])
if test "x${enable_auditor}" = "xyes"; then
	AM_PROG_RUBY
	AC_CONFIG_SUBDIRS([ auditor ])
fi
AM_CONDITIONAL([ENABLE_AUDITOR], [test "${enable_auditor}" = "yes"])

# plugins/eppclient
AC_ARG_ENABLE(eppclient,
	AC_HELP_STRING([--enable-eppclient],
		[Enable eppclient build (default disabled)]),
		[enable_eppclient="${enableval}"],
		[enable_eppclient="no"])
if test "x${enable_eppclient}" = "xyes"; then
	LIBCURL_CHECK_CONFIG([yes], [7.18.2], [], [AC_MSG_ERROR(["libcurl not found"])])
	AC_CONFIG_SUBDIRS([ plugins/eppclient ])
fi
AM_CONDITIONAL([ENABLE_EPPCLIENT], [test "${enable_eppclient}" = "yes"])

AC_CONFIG_FILES([
	Makefile
	tools/Makefile
	tools/ods-control
	tools/solaris/Makefile
	tools/solaris/ods-enforcerd.init
	tools/solaris/ods-signerd.init
	tools/ods-timing.5
	tools/opendnssec.7
	tools/ods-control.8
	tools/ods-kasp2html
	contrib/Makefile
	test/conf/softhsm.conf
])

AC_OUTPUT
