# $Id$

HUDSON_URL=	http://hudson-ci.org/latest/hudson.war
HUDSON_WAR=	hudson.war
HUDSON_CLI=	hudson-cli.jar
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

$(HUDSON_CLI):
	unzip $(HUDSON_WAR) WEB-INF/$(HUDSON_CLI)
	mv WEB-INF/$(HUDSON_CLI) $(HUDSON_CLI)
	rmdir WEB-INF
