# $Id$

SVN_SCRIPTS=	/usr/local/libexec/subversion
DESTDIR=	/usr/local/sbin

SUDO=		sudo

all:

install:
	$(SUDO) install -m 555 svn-checkzone.pl $(SVN_SCRIPTS)/svn-checkzone
	$(SUDO) install -m 555 svn-installzone.pl $(SVN_SCRIPTS)/svn-installzone
	$(SUDO) install -m 544 zkt-batch.sh $(DESTDIR)/zkt-batch
	$(SUDO) install -m 544 dns-installzone.pl $(DESTDIR)/dns-installzone
