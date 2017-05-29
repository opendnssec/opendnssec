.PHONY: analyze

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = src src/test man

doxygen:
	rm -fr $(top_builddir)/signer/doxygen-doc
	env $(DX_ENV) \
		PROJECT_NAME="OpenDNSSEC-signer" \
		SRCDIR=$(top_srcdir)/signer \
		OUTPUTDIR=$(top_builddir)/signer/doxygen-doc \
		$(DX_DOXYGEN) $(top_builddir)/$(DX_CONFIG)

analyze:
	cd src && $(MAKE) $(AM_MAKEFLAGS) analyze
