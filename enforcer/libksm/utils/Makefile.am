dist_bin_SCRIPTS = kaspimport.pl

do_subst = sed -e "s,[@]PERL[@],$(PERL),g" -e "s,[@]sysconfdir[@],$(sysconfdir),g"
              
kaspimport.pl: kaspimport.in Makefile
	$(do_subst) $(srcdir)/kaspimport.in > kaspimport.pl
	chmod +x kaspimport.pl


