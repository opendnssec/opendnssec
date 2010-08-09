# $Id$

HUDSON_URL=	http://hudson-ci.org/latest/hudson.war
HUDSON_WAR=	hudson.war
JOB_NAME=	OpenDNSSEC

DESTDIR=	$(HOME)/.hudson/jobs/$(JOB_NAME)

JAVA=		java
INSTALL=	install


all::

fetch:: $(HUDSON_WAR)

install::
	$(INSTALL) -d $(DESTDIR)
	$(INSTALL) config.xml $(DESTDIR)/config.xml

run:: $(HUDSON_WAR)
	$(JAVA) -jar $(HUDSON_WAR)

$(HUDSON_WAR):
	wget $(HUDSON_URL)
