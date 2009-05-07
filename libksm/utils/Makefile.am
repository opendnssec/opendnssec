# $Id$

datadir= @datarootdir@/opendnssec

dist_bin_SCRIPTS = kaspimport
dist_data_DATA =

if MYSQL
	dist_data_DATA += database_create.mysql 
else
	dist_data_DATA += database_create.sqlite3
endif

do_subst = sed -e "s,[@]PERL[@],$(PERL),g" -e "s,[@]sysconfdir[@],$(sysconfdir),g" -e"s,[@]mysql_path[@],$(MYSQL),g" -e"s,[@]DB_TYPE[@],$(DB_TYPE),g" -e "s,[@]datadir[@],$(datadir),g" -e"s,[@]sqlite3_path[@],$(SQLITE3),g"
              
kaspimport: kaspimport.in
	$(do_subst) $(srcdir)/kaspimport.in > $@
