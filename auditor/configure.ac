# $Id$

AC_PREREQ(2.61)
AC_INIT([auditor], [0.0.1], [alex.dalitz@nominet.org.uk])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

AM_PATH_RUBY([], [], [])

AC_MSG_CHECKING([for ruby library rubygems])
have_ruby_rubygems=`$RUBY -e 'require "rubygems"; print "yes"'`
if test "x$have_ruby_rubygems" = "x"; then
    AC_MSG_ERROR([Missing ruby library rubygems])
fi
AC_MSG_RESULT([yes])

AC_MSG_CHECKING([for ruby library syslog])
have_ruby_syslog=`$RUBY -e 'require "syslog"; print "yes"'`
if test "x$have_ruby_syslog" = "x"; then
    AC_MSG_ERROR([Missing ruby library syslog])
fi
AC_MSG_RESULT([yes])

AC_MSG_CHECKING([for ruby library openssl])
have_ruby_openssl=`$RUBY -e 'require "openssl"; print "yes"'`
if test "x$have_ruby_openssl" = "x"; then
    AC_MSG_ERROR([Missing ruby library openssl])
fi
AC_MSG_RESULT([yes])

AC_MSG_CHECKING([for ruby library dnsruby])
have_ruby_dnsruby=`$RUBY -e 'require "rubygems"; require "dnsruby"; print "yes"'`
if test "x$have_ruby_dnsruby" = "x"; then
    AC_MSG_ERROR([Missing ruby library dnsruby])
fi
AC_MSG_RESULT([yes])

AC_MSG_CHECKING([for ruby library xsd/datatypes])
have_ruby_xsd_datatypes=`$RUBY -e 'require "xsd/datatypes"; print "yes"'`
if test "x$have_ruby_xsd_datatypes" = "x"; then
    AC_MSG_ERROR([Missing ruby library xsd/datatypes])
fi
AC_MSG_RESULT([yes])

AC_MSG_CHECKING([for ruby library rexml/document])
have_ruby_rexml_document=`$RUBY -e 'require "rexml/document"; print "yes"'`
if test "x$have_ruby_rexml_document" = "x"; then
    AC_MSG_ERROR([Missing ruby library rexml/document])
fi
AC_MSG_RESULT([yes])


full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

opendnsseclibdir=$full_libdir/opendnssec
AC_SUBST([opendnsseclibdir])

AC_CONFIG_FILES([Makefile kasp_auditor])

AC_OUTPUT
