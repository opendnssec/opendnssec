# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = src man

doxygen:
	rm -fr $(top_builddir)/enforcer-ng/doxygen-doc
	env $(DX_ENV) \
		PROJECT_NAME="OpenDNSSEC-enforcer" \
		SRCDIR=$(top_srcdir)/enforcer-ng \
		OUTPUTDIR=$(top_builddir)/enforcer-ng/doxygen-doc \
		$(DX_DOXYGEN) $(top_builddir)/$(DX_CONFIG)
