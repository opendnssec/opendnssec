# $Id$

if MYSQL
dist_bin_SCRIPTS = kaspimport.pl database_create.mysql 
else
dist_bin_SCRIPTS = kaspimport.pl database_create.sqlite3
endif

do_subst = sed -e "s,[@]PERL[@],$(PERL),g" -e "s,[@]sysconfdir[@],$(sysconfdir),g" -e"s,[@]mysql_path[@],$(MYSQL),g" -e"s,[@]DB_TYPE[@],$(DB_TYPE),g" -e "s,[@]bindir[@],$(bindir),g" -e"s,[@]sqlite3_path[@],$(SQLITE3),g"
              
kaspimport.pl: kaspimport.in Makefile
	$(do_subst) $(srcdir)/kaspimport.in > kaspimport.pl
	chmod +x kaspimport.pl


