.PHONY: analyze

ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/common/config.h.in $(srcdir)/common/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub

SUBDIRS = common libhsm conf tools

if ENABLE_SIGNER
SUBDIRS += signer
endif

if ENABLE_ENFORCER
SUBDIRS += enforcer
endif

EXTRA_DIST =	$(srcdir)/LICENSE \
		$(srcdir)/README.md \
		$(srcdir)/contrib/ods-sequencer/ods-sequencer \
		$(srcdir)/contrib/ods-sequencer/ods-sequencer.md \
		$(srcdir)/contrib/ods-sequencer/ods-sequencer-submit.sh \
		$(srcdir)/contrib/simple-dnskey-mailer/simple-dnskey-mailer.sh


install-data-hook:
	$(INSTALL) -d $(DESTDIR)$(localstatedir)
	$(INSTALL) @INSTALLATIONUSERARG@ @INSTALLATIONGROUPARG@ -d $(DESTDIR)$(localstatedir)/opendnssec
	$(INSTALL) @INSTALLATIONUSERARG@ @INSTALLATIONGROUPARG@ -d $(DESTDIR)$(localstatedir)/opendnssec/signer
	$(INSTALL) @INSTALLATIONUSERARG@ @INSTALLATIONGROUPARG@ -d $(DESTDIR)$(localstatedir)/opendnssec/enforcer
	$(INSTALL) @INSTALLATIONUSERARG@ @INSTALLATIONGROUPARG@ -d $(DESTDIR)$(localstatedir)/opendnssec/signconf
	$(INSTALL) @INSTALLATIONUSERARG@ @INSTALLATIONGROUPARG@ -d $(DESTDIR)$(localstatedir)/opendnssec/unsigned
	$(INSTALL) @INSTALLATIONUSERARG@ @INSTALLATIONGROUPARG@ -d $(DESTDIR)$(localstatedir)/opendnssec/signed
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/run
	$(INSTALL) @INSTALLATIONUSERARG@ @INSTALLATIONGROUPARG@ -d $(DESTDIR)$(localstatedir)/run/opendnssec

docs:
	(cd libhsm; $(MAKE) doxygen)
if ENABLE_ENFORCER
	(cd enforcer; $(MAKE) doxygen)
endif
if ENABLE_SIGNER
	(cd signer; $(MAKE) doxygen)
endif

analyze:
	cd signer && $(MAKE) $(AM_MAKEFLAGS) analyze
