# $Id$

AC_PREREQ(2.61)
AC_INIT([opendnssec],[0.0.1],[])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

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
AM_PATH_RUBY([], [], [])

AC_CONFIG_SUBDIRS([libhsm libksm enforcer signer auditor xml])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
