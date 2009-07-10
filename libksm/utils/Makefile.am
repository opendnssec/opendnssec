# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

# dist_bin_SCRIPTS = kaspimport

CLEANFILES = $(dist_bin_SCRIPTS)

dist_ksmdata_DATA = database_create.sqlite3

do_subst = sed -e "s,[@]PERL[@],$(PERL),g" -e "s,[@]opendnssecsysconf[@],$(opendnssecsysconf),g" -e"s,[@]mysql_path[@],$(MYSQL),g" -e"s,[@]DB_TYPE[@],$(DB_TYPE),g" -e "s,[@]ksmdatadir[@],$(ksmdatadir),g" -e"s,[@]sqlite3_path[@],$(SQLITE3),g"
              
kaspimport: kaspimport.in
	$(do_subst) $(srcdir)/kaspimport.in > $@
