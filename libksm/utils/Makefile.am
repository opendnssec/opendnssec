# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

dist_bin_SCRIPTS = kaspimport
dist_data_DATA =

CLEANFILES = $(dist_bin_SCRIPTS)

if MYSQL
	dist_ksmdata_DATA += database_create.mysql 
else
	dist_ksmdata_DATA += database_create.sqlite3
endif

do_subst = sed -e "s,[@]PERL[@],$(PERL),g" -e "s,[@]opendnssecsysconf[@],$(opendnssecsysconf),g" -e"s,[@]mysql_path[@],$(MYSQL),g" -e"s,[@]DB_TYPE[@],$(DB_TYPE),g" -e "s,[@]ksmdatadir[@],$(ksmdatadir),g" -e"s,[@]sqlite3_path[@],$(SQLITE3),g"
              
kaspimport: kaspimport.in
	$(do_subst) $(srcdir)/kaspimport.in > $@
