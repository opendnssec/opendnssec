# $Id: Makefile.am 615 2009-05-06 08:52:03Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = ksm common enforcerd utils 

if WITH_CUNIT
SUBDIRS += test
endif

doxygen:
	rm -fr $(top_builddir)/enforcer/doxygen-doc
	env $(DX_ENV) \
		PROJECT_NAME="OpenDNSSEC-enforcer" \
		SRCDIR=$(top_srcdir)/enforcer \
		OUTPUTDIR=$(top_builddir)/enforcer/doxygen-doc \
		$(DX_DOXYGEN) $(top_builddir)/$(DX_CONFIG)
