# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

BUILT_SOURCES = dbsmsg.h kmemsg.h
DISTCLEANFILES = dbsmsg.h kmemsg.h

EXTRA_DIST = $(srcdir)/*.h $(srcdir)/*.pl dbsmsg.h kmemsg.h


dbsmsg.h: dbsdef.h
	@test -x ${PERL} || \
		(echo "perl is required for rebuilding message header files"; false)
	${PERL} $(srcdir)/status_messages.pl DBS $(srcdir)/dbsdef.h $@

kmemsg.h: kmedef.h
	@test -x ${PERL} || \
		(echo "perl is required for rebuilding message header files"; false)
	${PERL} $(srcdir)/status_messages.pl KME $(srcdir)/kmedef.h $@
