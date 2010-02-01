# $Id$

m4_sinclude([version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec], OPENDNSSEC_VERSION)

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

AC_CONFIG_SUBDIRS([ libhsm enforcer signer conf ])


# xml
AC_PATH_PROG(XMLLINT, xmllint)
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
		[],[])
if test "${enable_auditor+set}" != set; then
	enable_auditor=yes
fi
if test "${enable_auditor}" = yes; then
	AM_PROG_RUBY
	AC_CONFIG_SUBDIRS([ auditor ])
fi
AM_CONDITIONAL([ENABLE_AUDITOR], [test "${enable_auditor}" = "yes"])

full_prefix=`eval eval eval eval eval echo "${prefix}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
AC_SUBST([full_prefix])

AC_CONFIG_FILES([
	Makefile
	tools/Makefile
	tools/ods-control
	tools/solaris/Makefile
	tools/solaris/ods-enforcerd.init
	tools/solaris/ods-signerd.init
	tools/ods-timing.5.in
	tools/opendnssec.1.in
	contrib/Makefile
])

AC_OUTPUT
