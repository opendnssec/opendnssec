# $Id$

BUILT_SOURCES = dbsmsg.h kmemsg.h
CLEANFILES = dbsmsg.h kmemsg.h

dbsmsg.h: dbsdef.h
	@PERL@ $(srcdir)/status_messages.pl DBS dbsdef.h $@

kmemsg.h: kmedef.h
	@PERL@ $(srcdir)/status_messages.pl KME kmedef.h $@

ksminclude_HEADERS = *.h $(srcdir)/*.h
