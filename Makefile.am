ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/common/config.h.in $(srcdir)/common/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub

SUBDIRS = common libhsm enforcer conf tools

if ENABLE_SIGNER
SUBDIRS += signer
endif

EXTRA_DIST =	$(srcdir)/LICENSE \
		$(srcdir)/KNOWN_ISSUES \
		$(srcdir)/MIGRATION \		
		$(srcdir)/plugins/simple-dnskey-mailer/simple-dnskey-mailer.sh


install-data-hook:
	$(INSTALL) -d $(DESTDIR)$(localstatedir)
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/tmp
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/signconf
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/unsigned
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/signed
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/run
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/run/opendnssec

docs:
	(cd libhsm; $(MAKE) doxygen)
	(cd enforcer; $(MAKE) doxygen)
	(cd signer; $(MAKE) doxygen)
