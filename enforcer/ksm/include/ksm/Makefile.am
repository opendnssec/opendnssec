# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

BUILT_SOURCES = dbsmsg.h kmemsg.h
CLEANFILES = dbsmsg.h kmemsg.h

EXTRA_DIST = $(srcdir)/*.h $(srcdir)/*.pl

dbsmsg.h: dbsdef.h
	@PERL@ $(srcdir)/status_messages.pl DBS $(srcdir)/dbsdef.h $@

kmemsg.h: kmedef.h
	@PERL@ $(srcdir)/status_messages.pl KME $(srcdir)/kmedef.h $@
