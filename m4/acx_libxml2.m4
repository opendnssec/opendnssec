AC_DEFUN([ACX_LIBXML2],[
	PKG_CHECK_MODULES([XML2], [libxml-2.0])
	XML2_INCLUDES="$XML2_CFLAGS"
	AC_SUBST(XML2_INCLUDES)
	AC_SUBST(XML2_LIBS)
])
