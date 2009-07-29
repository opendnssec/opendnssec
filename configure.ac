# $Id$

AC_PREREQ(2.61)
AC_INIT([opendnssec], [0.0.1], [])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

# softham
ACX_BOTAN

# xml
AC_PATH_PROG(XMLLINT, xmllint)
AC_PATH_PROG(JAVA, java)
ACX_TRANG

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

# auditor
AM_PATH_RUBY([], [], [])

AC_ARG_WITH(dbname,
[  --with-dbname=DB_NAME   Database name/schema for unit tests  ],
   DB_NAME="$withval"
)

AC_ARG_WITH(dbhost,
[  --with-dbhost=DB_HOST   Database host for unit tests  ],
   DB_HOST="$withval"
)

AC_ARG_WITH(dbpass,
[  --with-dbpass=DB_PASS   Database host for unit tests  ],
   DB_PASS="$withval"
)

AC_ARG_WITH(dbuser,
[  --with-dbuser=DB_USER   Database host for unit tests  ],
   DB_USER="$withval"
)


AC_CONFIG_SUBDIRS([softHSM libhsm libksm enforcer signer auditor xml])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
