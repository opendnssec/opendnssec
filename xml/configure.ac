# $Id$
#
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(opendnssec-xml, 0.0.1, jad@jadickinson.co.uk)
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

# Checks for programs.
AC_PATH_PROG(XMLLINT, xmllint)

AC_PATH_PROG(JAVA, java)

AC_ARG_WITH(trang,
	[AS_HELP_STRING([--with-trang],[Path to trang.jar (optional)])],
   	TRANGJAR="$withval"
	)
if test "x$TRANGJAR" != "x"
then
	if test -e $TRANGJAR
	then
		TRANG="$JAVA -jar $TRANGJAR"
		AC_MSG_NOTICE(trang will run like this $TRANG)
  	else
    		AC_MSG_ERROR(trang.jar is needed to continue. Say where it is with --with-trang=PATH)
	fi
else
	AC_MSG_NOTICE([trang.jar can be downloaded from http://code.google.com/p/jing-trang/])
	TRANG=
fi
AC_SUBST(TRANG)

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
