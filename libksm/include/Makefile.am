BUILT_SOURCES = dbsdef.inc kmedef.inc
CLEANFILES = dbsdef.inc kmedef.inc

dbsdef.inc: dbsdef.h
	@PERL@ $(srcdir)/status_messages.pl DBS dbsdef.h dbsdef.inc

kmedef.inc: kmedef.h
	@PERL@ $(srcdir)/status_messages.pl KME kmedef.h kmedef.inc

nobase_include_HEADERS = *.h *.inc

EXTRA_DIST = *.h
