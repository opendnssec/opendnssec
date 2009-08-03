# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

BUILT_SOURCES = dbsmsg.h kmemsg.h
CLEANFILES = dbsmsg.h kmemsg.h

dbsmsg.h: dbsdef.h
	@PERL@ $(srcdir)/status_messages.pl DBS $(srcdir)/dbsdef.h $@

kmemsg.h: kmedef.h
	@PERL@ $(srcdir)/status_messages.pl KME $(srcdir)/kmedef.h $@

ksminclude_HEADERS =    dbsmsg.h \
			kmemsg.h \
			$(srcdir)/database.h \
			$(srcdir)/database_statement.h \
			$(srcdir)/datetime.h \
			$(srcdir)/db_fields.h \
			$(srcdir)/dbsdef.h \
			$(srcdir)/debug.h \
			$(srcdir)/kmedef.h \
			$(srcdir)/ksm.h \
			$(srcdir)/ksm_internal.h \
			$(srcdir)/ksm_version.h \
			$(srcdir)/ksmdef.h \
			$(srcdir)/ksmutil.h \
			$(srcdir)/memory.h \
			$(srcdir)/message.h \
			$(srcdir)/parser.h \
			$(srcdir)/string_util2.h \
			$(srcdir)/string_util.h \
			$(srcdir)/system_includes.h

extra_DIST = $(srcdir)/*.h
