# $Id$

AC_PREREQ(2.61)
AC_INIT([auditor], [0.0.1], [alex.dalitz@nominet.org.uk])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

AM_PATH_RUBY(,with_ruby=yes, with_ruby=no)

full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

opendnsseclibdir=$full_libdir/opendnssec
AC_SUBST([opendnsseclibdir])

AC_CONFIG_FILES([Makefile kasp_auditor])

AC_OUTPUT
